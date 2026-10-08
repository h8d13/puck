// port of src/pacman/sighandler.c: the soft interrupt handler on SIGINT
// and SIGHUP, installed by main and removed by cleanup.
//
// a handler in safe Rust can only set a flag or write to a pipe
// (signal-hook, METHODOLOGY.md), which is all the C's handler may do
// async-signal-safely besides write(2) and _exit. signal-hook's handler
// writes the signal number to its self-pipe; a thread reads it and does
// what the C's handler does, in its order: the cursor to the line after
// the download bars, the message, the cursor shown, then
// alpm_trans_interrupt on the handle's Interrupt, or alpm_unlock and
// _exit(128 + signum). the C decides at delivery, here the thread
// decides a moment after it: a signal at the very edge of the commit
// (a hook ending, the state becoming COMMITTING) can fall on the other
// side. the main thread's Output is flushed by every callback, so the
// C's fflush(stdout) has nothing left to write here.
//
// remove_soft_interrupt_handler is a flag read in signal context, the
// default action then runs there (C: SIG_DFL).
//
// not ported: segv_handler, signal-hook refuses SIGSEGV and safe Rust
// only faults on a stack overflow, which std's own SIGSEGV handler
// reports before it aborts. winch_handler: util::getcols reads the
// width on every call, there is no cache for it to reset.
use std::ffi::c_int;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use alpm_core::handle::Interrupt;
use signal_hook::consts::{SIGHUP, SIGINT};
use signal_hook::flag;
use signal_hook::iterator::Signals;
use signal_hook::low_level;

use crate::util::{
	console_cursor_move_down, console_cursor_move_up, console_cursor_show,
};

// config->handle as the handler sees it, None until setup_libalpm
static HANDLE: Mutex<Option<Arc<Interrupt>>> = Mutex::new(None);
// set by remove_soft_interrupt_handler, None until installed
static REMOVED: OnceLock<Arc<AtomicBool>> = OnceLock::new();
// multibar_ui.active_downloads_num - cursor_lineno: the lines
// console_cursor_move_end goes down (up when negative)
static BARS_BELOW: AtomicI32 = AtomicI32::new(0);

// config->handle set by setup_libalpm. kept past cleanup like the C's
// until alpm_release: its Interrupt then holds no lock
pub fn set_handle(handle: Arc<Interrupt>) {
	*HANDLE.lock().unwrap_or_else(PoisonError::into_inner) = Some(handle);
}

// the multibar cursor as the callbacks left it
pub fn set_bars_below(active: usize, cursor_lineno: c_int) {
	let active = c_int::try_from(active).unwrap_or(c_int::MAX);
	let below = active.wrapping_sub(cursor_lineno);
	BARS_BELOW.store(below, Ordering::SeqCst);
}

fn write_out(s: &[u8]) {
	// xwrite's result is not checked
	let mut out = io::stdout();
	let _ = out.write_all(s);
	let _ = out.flush();
}

// soft_interrupt_handler, on the signal thread
fn soft_interrupt_handler(signum: c_int) {
	let mut s = Vec::new();
	let below = BARS_BELOW.load(Ordering::SeqCst);
	if below > 0 {
		console_cursor_move_down(&mut s, below.unsigned_abs());
	} else if below < 0 {
		console_cursor_move_up(&mut s, below.unsigned_abs());
	}
	write_out(&s);
	let msg: &[u8] = match signum {
		SIGINT => b"\nInterrupt signal received\n",
		_ => b"\nHangup signal received\n",
	};
	let _ = io::stderr().write_all(msg);
	// shown whether stdout is a terminal or not, like the C
	let mut show = Vec::new();
	console_cursor_show(&mut show, true);
	write_out(&show);
	let handle = HANDLE.lock().unwrap_or_else(PoisonError::into_inner);
	let handle = handle.clone();
	if let Some(h) = &handle {
		if h.trans_interrupt().is_ok() {
			// a transaction is being interrupted, don't exit yet
			return;
		}
		let _ = h.unlock();
	}
	// a newline to be sure any line we may be on is cleared
	write_out(b"\n");
	low_level::exit(128 + signum);
}

// install_soft_interrupt_handler, once per process. Err when a
// registration or the thread failed (the C ignores sigaction's result)
pub fn install_soft_interrupt_handler() -> io::Result<()> {
	let removed = Arc::new(AtomicBool::new(false));
	if REMOVED.set(Arc::clone(&removed)).is_err() {
		return Ok(());
	}
	// registered first, so once removed the default action runs before
	// the signal reaches the pipe
	for sig in [SIGINT, SIGHUP] {
		flag::register_conditional_default(sig, Arc::clone(&removed))?;
	}
	let mut signals = Signals::new([SIGINT, SIGHUP])?;
	std::thread::Builder::new()
		.name("sighandler".into())
		.spawn(move || {
			for sig in signals.forever() {
				soft_interrupt_handler(sig);
			}
		})?;
	Ok(())
}

// remove_soft_interrupt_handler: SIGINT and SIGHUP back to their default
// action. nothing when not installed (the in-process tests)
pub fn remove_soft_interrupt_handler() {
	if let Some(removed) = REMOVED.get() {
		removed.store(true, Ordering::SeqCst);
	}
}
