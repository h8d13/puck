// archive_read_support_filter_program.c as the lrzip, lzop and grzip
// bidders use it (__archive_read_program; libarchive has no liblzo2 here,
// so lzop runs its program too). the program reads the upstream data on
// its stdin, its stdout is this filter's output in 64 KiB blocks; one
// thread feeds and reads non-blocking pipes like child_read. the program
// is run by name through PATH: when it cannot be run, libarchive's vfork
// child exits 254 (__archive_create_child), and the first read fails
// with that status. the vfork child shares the caller's memory, so
// execvp's errno (ENOENT, EACCES) is left in the caller's errno: the
// failure carries its kind. stderr is the caller's

use std::io::{self, BufRead, ErrorKind};
use std::os::unix::process::ExitStatusExt;
use std::process::{
	Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio,
};

use rustix::event::{PollFd, PollFlags, poll};
use rustix::fs::{OFlags, fcntl_setfl};
use rustix::io::Errno;

use super::{Decode, Filter};

const OUT_BUF_LEN: usize = 64 * 1024;

// execvp's failure in the vfork child: _exit(254)
const EXEC_FAILED: i32 = 254;

// SIGPIPE: the program died because the reader stopped early
const SIGPIPE: i32 = 13;

pub(super) struct Program {
	up: Box<Filter>,
	child: Option<Child>,
	stdin: Option<ChildStdin>,
	stdout: Option<ChildStdout>,
	// child_stdout != -1; true with no stdout when the program could
	// not run (its pipe only gives the end)
	open: bool,
	// child_stop's sticky result, the error text if any
	stopped: Option<Option<String>>,
	// the program could not run: what execvp left in errno
	exec_failed: Option<ErrorKind>,
}

impl Program {
	pub(super) fn spawn(
		up: Filter,
		cmd: &str,
		args: &[&str],
	) -> Box<dyn Decode> {
		let child = Command::new(cmd)
			.args(args)
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.spawn();
		let mut p = Program {
			up: Box::new(up),
			child: None,
			stdin: None,
			stdout: None,
			open: true,
			stopped: None,
			exec_failed: None,
		};
		let mut child = match child {
			Ok(c) => c,
			Err(e) => {
				p.exec_failed = Some(e.kind());
				return Box::new(p);
			}
		};
		p.stdin = child.stdin.take();
		p.stdout = child.stdout.take();
		p.child = Some(child);
		// O_NONBLOCK alone, like the C's F_SETFL
		if let Some(s) = &p.stdin {
			let _ = fcntl_setfl(s, OFlags::NONBLOCK);
		}
		if let Some(s) = &p.stdout {
			let _ = fcntl_setfl(s, OFlags::NONBLOCK);
		}
		Box::new(p)
	}

	// close(child_stdin), stdout blocking again
	fn close_stdin(&mut self) {
		self.stdin = None;
		if let Some(s) = &self.stdout {
			let _ = fcntl_setfl(s, OFlags::empty());
		}
	}

	// child_stop: pipes closed, the child reaped once; Ok if it exited
	// 0 or died of SIGPIPE
	fn child_stop(&mut self) -> io::Result<()> {
		self.stdin = None;
		self.stdout = None;
		self.open = false;
		if self.stopped.is_none() {
			let status = match self.child.take() {
				Some(mut c) => c.wait().ok(),
				None => Some(ExitStatus::from_raw(
					EXEC_FAILED << 8,
				)),
			};
			self.stopped = Some(exit_text(status));
		}
		let kind = self.exec_failed.unwrap_or(ErrorKind::Other);
		match self.stopped.as_ref().and_then(|s| s.as_deref()) {
			Some(t) => Err(io::Error::new(kind, t)),
			None => Ok(()),
		}
	}

	// waits until the child can take input or has output
	fn check_child(&self) {
		let mut fds = Vec::new();
		if let Some(s) = &self.stdin {
			fds.push(PollFd::new(s, PollFlags::OUT));
		}
		if let Some(s) = &self.stdout {
			fds.push(PollFd::new(s, PollFlags::IN));
		}
		let _ = poll(&mut fds, None);
	}

	// child_read: output of the child, 0 once it closed its output and
	// exited well; upstream data written to it meanwhile
	fn child_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		loop {
			let r = match &self.stdout {
				Some(s) => {
					retry(|| rustix::io::read(s, &mut *buf))
				}
				None => Ok(0),
			};
			match r {
				Ok(n) if n > 0 => return Ok(n),
				Ok(_) | Err(Errno::PIPE) => {
					return self.child_stop().map(|()| 0);
				}
				Err(Errno::AGAIN) => {}
				Err(e) => return Err(e.into()),
			}
			if self.stdin.is_none() {
				self.check_child();
				continue;
			}
			let data = match self.up.fill_buf() {
				Ok(d) if !d.is_empty() => d,
				r => {
					let r = r.map(|_| ());
					self.close_stdin();
					r?;
					continue;
				}
			};
			let stdin = self.stdin.as_ref().expect("checked above");
			match retry(|| rustix::io::write(stdin, data)) {
				Ok(n) if n > 0 => self.up.consume(n),
				Err(Errno::AGAIN) => self.check_child(),
				r => {
					self.close_stdin();
					// EPIPE or nothing written: the output is
					// still read
					if let Err(e) = r
						&& e != Errno::PIPE
					{
						return Err(e.into());
					}
				}
			}
		}
	}
}

// the call again while it is interrupted
fn retry<T>(
	mut f: impl FnMut() -> rustix::io::Result<T>,
) -> rustix::io::Result<T> {
	loop {
		match f() {
			Err(Errno::INTR) => {}
			r => return r,
		}
	}
}

// child_stop's verdict on a status: None when it is fine, else its text
fn exit_text(status: Option<ExitStatus>) -> Option<String> {
	let Some(status) = status else {
		return Some("Error closing child process".into());
	};
	if let Some(sig) = status.signal() {
		if sig == SIGPIPE {
			return None;
		}
		return Some(format!("Child process exited with signal {sig}"));
	}
	match status.code() {
		Some(0) => None,
		Some(n) => {
			Some(format!("Child process exited with status {n}"))
		}
		None => Some("Error closing child process".into()),
	}
}

impl Decode for Program {
	// program_filter_read: a whole block, or what came before the end
	fn block(&mut self, out: &mut Vec<u8>) -> io::Result<bool> {
		let start = out.len();
		out.resize(start + OUT_BUF_LEN, 0);
		let mut total = 0;
		while self.open && total < OUT_BUF_LEN {
			let n = self.child_read(&mut out[start + total..])?;
			if n == 0 {
				break;
			}
			total += n;
		}
		out.truncate(start + total);
		Ok(!self.open)
	}

	fn offset(&self) -> u64 {
		self.up.offset()
	}

	fn block_size(&self) -> usize {
		OUT_BUF_LEN
	}
}

// program_filter_close: the child stopped and reaped
impl Drop for Program {
	fn drop(&mut self) {
		let _ = self.child_stop();
	}
}
