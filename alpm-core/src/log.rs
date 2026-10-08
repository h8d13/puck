// port of lib/libalpm/log.c: alpm_logaction, the logfile and syslog
// lines. _alpm_log is Callbacks::log with the message formatted.
//
// the C stamps lines with localtime(time(NULL)): the offset comes from
// glibc's localtime_r through time's local-offset (METHODOLOGY.md), so
// TZ, /etc/localtime and the zone's rules at that second are the C's.
// glibc reads TZ at the first call of the process where the C's
// localtime rereads it every time; nothing here changes the environment.
// messages come formatted (the C takes fmt + va_list). vsyslog(3) is rebuilt on std's unix socket: glibc's default
// openlog (no ident, LOG_USER, no LOG_PID) to /dev/log, datagram first
// then stream, a failed send drops the line (no LOG_CONS).

use std::ffi::{OsStr, c_int};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::time::{SystemTime, UNIX_EPOCH};

use time::{OffsetDateTime, UtcOffset};

use crate::dload::MONTHS;
use crate::error::Errno;
use crate::util::until_nul;

// _PATH_LOG
const PATH_LOG: &str = "/dev/log";
// LOG_WARNING | LOG_USER, what vsyslog(LOG_WARNING, ...) sends without
// openlog
const SYSLOG_PRI: c_int = 4 | 1 << 3;
const ENOENT: i32 = 2;
const EACCES: i32 = 13;
const EPROTOTYPE: i32 = 91;

// a point in time as localtime(3) sees it: seconds since the epoch and
// the zone's offset east of UTC (tm_gmtoff)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogTime {
	pub secs: i64,
	pub utcoff: i32,
}

// time(NULL)
pub fn now_secs() -> i64 {
	match SystemTime::now().duration_since(UNIX_EPOCH) {
		Ok(d) => d.as_secs() as i64,
		Err(e) => -(e.duration().as_secs() as i64),
	}
}

// localtime(&secs)->tm_gmtoff. None outside the years time holds (-9999
// to 9999), where glibc still answers
pub fn local_offset(secs: i64) -> Option<i32> {
	let t = OffsetDateTime::from_unix_timestamp(secs).ok()?;
	let off = UtcOffset::local_offset_at(t).ok()?;
	Some(off.whole_seconds())
}

// localtime(time(NULL)); UTC in the years local_offset cannot take
pub fn local_now() -> LogTime {
	let secs = now_secs();
	let utcoff = local_offset(secs).unwrap_or(0);
	LogTime { secs, utcoff }
}

// the broken-down local time: year, month, day, hour, minute, second.
// a clock past time's years (-9999..9999) stamps the epoch
fn local(t: LogTime) -> (i32, u8, u8, u8, u8, u8) {
	let s = t.secs + i64::from(t.utcoff);
	let d = OffsetDateTime::from_unix_timestamp(s)
		.unwrap_or(OffsetDateTime::UNIX_EPOCH);
	(
		d.year(),
		d.month() as u8,
		d.day(),
		d.hour(),
		d.minute(),
		d.second(),
	)
}

// _alpm_log_leader: "[%FT%T%z] [prefix] ". glibc's %F is "%Y-%m-%d",
// the year unpadded
pub fn leader(t: LogTime, prefix: &[u8]) -> Vec<u8> {
	let (y, mo, d, h, mi, s) = local(t);
	let sign = if t.utcoff < 0 { '-' } else { '+' };
	let off = t.utcoff.unsigned_abs();
	let stamp = format!(
		"[{y}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}{sign}{:02}{:02}] [",
		off / 3600,
		off / 60 % 60
	);
	[stamp.as_bytes(), prefix, b"] "].concat()
}

// the packet vsyslog sends: "<pri>%h %e %T tag: msg", C locale
pub fn syslog_message(t: LogTime, tag: &[u8], msg: &[u8]) -> Vec<u8> {
	let (_, mo, d, h, mi, s) = local(t);
	let month = String::from_utf8_lossy(MONTHS[(mo - 1) as usize]);
	let head =
		format!("<{SYSLOG_PRI}>{month} {d:2} {h:02}:{mi:02}:{s:02} ");
	[head.as_bytes(), tag, b": ", msg].concat()
}

// __progname: argv[0] after its last '/'
fn progname() -> Vec<u8> {
	let arg0 = std::env::args_os().next().unwrap_or_default();
	let arg0 = arg0.as_bytes();
	let i = arg0.iter().rposition(|&c| c == b'/').map_or(0, |i| i + 1);
	arg0[i..].to_vec()
}

// the connection openlog_internal keeps open across calls
#[derive(Debug)]
enum Syslog {
	Datagram(UnixDatagram),
	Stream(UnixStream),
}

impl Syslog {
	// SOCK_DGRAM, SOCK_STREAM when the socket says EPROTOTYPE
	fn connect() -> io::Result<Syslog> {
		let dgram = UnixDatagram::unbound()?;
		match dgram.connect(PATH_LOG) {
			Ok(()) => Ok(Syslog::Datagram(dgram)),
			Err(e) if e.raw_os_error() == Some(EPROTOTYPE) => {
				UnixStream::connect(PATH_LOG)
					.map(Syslog::Stream)
			}
			Err(e) => Err(e),
		}
	}

	// a stream packet carries its nul
	fn send(&mut self, packet: &[u8]) -> io::Result<()> {
		match self {
			Syslog::Datagram(s) => s.send(packet).map(drop),
			Syslog::Stream(s) => {
				s.write_all(&[packet, b"\0"].concat())
			}
		}
	}
}

// handle->logfile, logstream and usesyslog
#[derive(Debug, Default)]
pub struct Logger {
	logfile: Option<Vec<u8>>,
	stream: Option<File>,
	usesyslog: c_int,
	syslog: Option<Syslog>,
}

impl Logger {
	// alpm_option_get_logfile
	pub fn logfile(&self) -> Option<&[u8]> {
		self.logfile.as_deref()
	}

	// alpm_option_set_logfile: the stream closes, the next logaction
	// opens the new file
	pub fn set_logfile(&mut self, logfile: &[u8]) {
		self.logfile = Some(until_nul(logfile).to_vec());
		self.stream = None;
	}

	pub fn usesyslog(&self) -> c_int {
		self.usesyslog
	}

	// alpm_option_set_usesyslog. turning it off keeps the connection,
	// the C's closelog runs at handle release only
	pub fn set_usesyslog(&mut self, usesyslog: c_int) {
		self.usesyslog = usesyslog;
	}

	// open(logfile, O_WRONLY|O_APPEND|O_CREAT|O_CLOEXEC, 0644)
	fn open(&mut self) -> Result<(), Errno> {
		let Some(path) = &self.logfile else {
			return Ok(());
		};
		let f = OpenOptions::new()
			.append(true)
			.create(true)
			.mode(0o644)
			.open(OsStr::from_bytes(path));
		match f {
			Ok(f) => {
				self.stream = Some(f);
				Ok(())
			}
			Err(e) => Err(match e.raw_os_error() {
				Some(EACCES) => Errno::Badperms,
				Some(ENOENT) => Errno::NotADir,
				_ => Errno::System,
			}),
		}
	}

	// vsyslog: connects on first use, one reconnect when a send fails
	fn syslog(&mut self, msg: &[u8]) {
		let packet = syslog_message(local_now(), &progname(), msg);
		for _ in 0..2 {
			if self.syslog.is_none() {
				self.syslog = Syslog::connect().ok();
			}
			let Some(s) = &mut self.syslog else {
				return;
			};
			if s.send(&packet).is_ok() {
				return;
			}
			self.syslog = None;
		}
	}

	// alpm_logaction: an empty prefix is "UNKNOWN". a logfile that does
	// not open sets the errno, syslog still gets the line. the C's stdio
	// buffer (st_blksize) hides a failed write unless the line overflows
	// it, fflush's error is not checked
	pub fn logaction(
		&mut self,
		prefix: &[u8],
		msg: &[u8],
	) -> Result<(), Errno> {
		let mut ret = Ok(());
		if self.stream.is_none() {
			ret = self.open();
		}
		if self.usesyslog != 0 {
			self.syslog(msg);
		}
		let Some(f) = &mut self.stream else {
			return ret;
		};
		let prefix = match until_nul(prefix) {
			b"" => &b"UNKNOWN"[..],
			p => p,
		};
		let line = [&leader(local_now(), prefix)[..], msg].concat();
		let blksize = f.metadata().map_or(4096, |m| m.blksize());
		if f.write_all(&line).is_err() && line.len() as u64 > blksize {
			ret = Err(Errno::System);
		}
		ret
	}
}
