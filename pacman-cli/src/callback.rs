// port of src/pacman/callback.c: the libalpm callbacks of the frontend
// (cb_event, cb_question, cb_progress, cb_download, cb_log) as one
// alpm_core::callbacks::Callbacks impl
//
// the C statics (on_progress, the delayed output list, the total bar,
// prevpercent/prevcurrent, the timediff clock, the multibar UI) are the
// fields of a Frontend, one per handle. the global config is the
// Frontend's own copy, taken when it is installed. stdout and stderr
// collect in an Output flushed to its sink where the C fflushes and at
// the end of every callback; stdin, getcols and the clocks come from a
// util::Term. what the C asks config->handle (the local db cache and
// the transaction for optdepends) comes from a Lookup, () until trans.c
// is ported.
//
// wide character handling follows util.rs: glibc's UTF-8 decoder, a
// string that does not decode keeps its valid prefix (swprintf fails
// there in the C), wcwidth from unicode-width. messages are the msgids.
// where the C asserts a download bar exists, an unknown file is ignored.
use std::ffi::c_int;
use std::io::BufRead;
use std::sync::atomic::Ordering;

use alpm_core::callbacks::{
	Callbacks, DownloadEvent, Event, HookWhen, LogLevel, PackageOperation,
	Progress, Question,
};
use alpm_core::conflict::Conflict;
use alpm_core::deps::{Depend, dep_compute_string};
use alpm_core::package::Package;
use alpm_core::util::until_nul;

use crate::conf::{ColStr, Config, LOG_WARNING};
use crate::pacman::PM_OP_FILES;
use crate::sighandler::set_bars_below;
use crate::util::{
	Output, Term, colon_printf, console_cursor_move_down,
	console_cursor_move_up, console_erase_line, display_new_optdepends,
	display_optdepends, humanize_size, list_display, mbstowcs, noyes,
	pm_vasprintf, pm_vfprintf, select_display, select_question, wcwidth,
	yesno,
};

// update speed for the fill_progress based functions
const UPDATE_SPEED_MS: i64 = 200;

// what the callbacks need from the handle besides the callback data
pub trait Lookup {
	// make_optstring's lists: the local db cache and the transaction's
	// add list
	fn installed(&mut self) -> (Vec<Package>, Vec<Package>) {
		(Vec::new(), Vec::new())
	}
}

impl Lookup for () {}

// struct pacman_progress_bar. the C's uint64_t times are i64 here, the
// subtractions wrap the same
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Bar {
	pub filename: Vec<u8>,
	pub xfered: i64,
	pub total_size: i64,
	pub downloaded: usize,
	pub howmany: usize,
	pub init_time: i64,
	pub sync_time: i64,
	pub sync_xfered: i64,
	pub rate: f64,
	pub eta: u32,
	pub completed: bool,
}

// struct pacman_multibar_ui. active_downloads_num is active.len()
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Multibar {
	pub active: Vec<Bar>,
	pub cursor_lineno: c_int,
}

// the frontend callbacks, printing into out
pub struct Frontend<R: BufRead, L: Lookup = ()> {
	pub config: Config,
	pub term: Term<R>,
	// stdout and stderr since the last flush, its sink set by the owner
	pub out: Output,
	pub lookup: L,
	on_progress: bool,
	// the delayed stderr lines, printed when the bar is done
	output: Vec<Vec<u8>>,
	total_enabled: bool,
	list_total: i64,
	list_total_pkgs: usize,
	// the C frees totalbar and keeps the pointer, unused until re-init
	totalbar: Option<Bar>,
	prevpercent: c_int,
	prevcurrent: usize,
	// get_update_timediff's last_time
	last_time: i64,
	multibar: Multibar,
}

// (double -> unsigned/off_t) as x86_64 converts: cvttsd2si into 64 bits,
// 1 << 63 for NaN and out of range. the C conversion is undefined out of
// range; this keeps the reference platform's output
fn cvtt(x: f64) -> i64 {
	// 2^63, exact as an f64
	let limit = (1u64 << 63) as f64;
	if x.is_nan() || x >= limit || x < -limit {
		return i64::MIN;
	}
	x as i64
}

// number_length: decimal digits of n
fn number_length(n: usize) -> usize {
	n.to_string().len()
}

// clean_filename: cut at the first ".pkg", else ".db", else ".files"
fn clean_filename(filename: &[u8]) -> Vec<u8> {
	let f = until_nul(filename);
	let find = |pat: &[u8]| f.windows(pat.len()).position(|w| w == pat);
	let cut = find(b".pkg")
		.or_else(|| find(b".db"))
		.or_else(|| find(b".files"));
	f[..cut.unwrap_or(f.len())].to_vec()
}

// wcswidth of decoded characters, -1 if any is not printable
fn wcswidth(w: &[u32]) -> i32 {
	let mut n: i32 = 0;
	for &c in w {
		let x = wcwidth(c);
		if x < 0 {
			return -1;
		}
		n = n.wrapping_add(x);
	}
	n
}

// the characters back as UTF-8 (%ls), up to the first L'\0'
fn encode(w: &[u32]) -> Vec<u8> {
	let mut out = Vec::new();
	for &c in w.iter().take_while(|&&c| c != 0) {
		let ch = char::from_u32(c)
			.unwrap_or(char::REPLACEMENT_CHARACTER);
		let mut buf = [0; 4];
		out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
	}
	out
}

// the text fitted into width columns: padding when shorter, cut with
// "..." at the first character reaching `width - 3` when longer.
// (characters, padding)
fn fit(w: Vec<u32>, width: i32) -> (Vec<u32>, i32) {
	// a width of -1 (not printable) pads one more and is never cut
	let pad = width - wcswidth(&w);
	if pad >= 0 {
		return (w, pad);
	}
	let mut i = width - 3;
	let mut p = 0;
	while i > wcwidth(w.get(p).copied().unwrap_or(0)) {
		i -= wcwidth(w[p]);
		p += 1;
	}
	let mut cut = w[..p].to_vec();
	cut.extend(b"...".iter().map(|&c| u32::from(c)));
	(cut, i)
}

// "%-*s" of "": width spaces, nothing when negative
fn spaces(n: i32) -> Vec<u8> {
	vec![b' '; usize::try_from(n).unwrap_or(0)]
}

impl<R: BufRead> Frontend<R, ()> {
	pub fn new(config: Config, term: Term<R>) -> Self {
		Frontend::with_lookup(config, term, ())
	}
}

impl<R: BufRead, L: Lookup> Frontend<R, L> {
	pub fn with_lookup(config: Config, term: Term<R>, lookup: L) -> Self {
		Frontend {
			config,
			term,
			out: Output::default(),
			lookup,
			on_progress: false,
			output: Vec::new(),
			total_enabled: false,
			list_total: 0,
			list_total_pkgs: 0,
			totalbar: None,
			prevpercent: 0,
			prevcurrent: 0,
			last_time: 0,
			multibar: Multibar::default(),
		}
	}

	// the download bars the multibar UI still redraws
	pub fn multibar(&self) -> &Multibar {
		&self.multibar
	}

	// multibar_move_completed_up: the flag is the Term's, shared
	pub fn multibar_move_completed_up(&mut self, value: bool) {
		self.term.move_completed_up.store(value, Ordering::Relaxed);
	}

	fn print(&mut self, s: &[u8]) {
		self.out.stdout.extend_from_slice(s);
	}

	fn colon(&mut self, msg: &[u8]) {
		colon_printf(&mut self.out.stdout, &self.config.colstr, msg);
		self.out.flush();
	}

	// pm_printf, stamped by the Term's clock
	fn warn(&mut self, msg: &[u8]) {
		let now = (self.term.now_secs)();
		let line = pm_vfprintf(&self.config, LOG_WARNING, msg, now);
		self.out.stderr.extend(line.unwrap_or_default());
	}

	// pm_sprintf into the delayed output while a bar runs, else pm_printf
	fn warn_delayed(&mut self, msg: &[u8]) {
		if !self.on_progress {
			self.warn(msg);
			return;
		}
		if let Some(s) = pm_vasprintf(&self.config, LOG_WARNING, msg) {
			self.output.push(s);
		}
	}

	// get_update_timediff
	fn update_timediff(&mut self, first_call: bool) -> i64 {
		let now = (self.term.now_ms)();
		if first_call {
			self.last_time = now;
			return 0;
		}
		let diff = now.wrapping_sub(self.last_time);
		// do not update last_time if the interval was too short
		if !(0..UPDATE_SPEED_MS).contains(&diff) {
			self.last_time = now;
		}
		diff
	}

	// fill_progress: the bar in proglen columns and the percentage
	fn fill_progress(&mut self, percent: c_int, proglen: i32) {
		// 8 = 1 space + 1 [ + 1 ] + 5 for percent
		let hashlen = if proglen > 8 { proglen - 8 } else { 0 };
		let hash = percent.wrapping_mul(hashlen) / 100;
		let mut s = Vec::new();
		if hashlen > 0 {
			s.extend_from_slice(b" [");
			for i in (1..=hashlen).rev() {
				s.extend_from_slice(
					self.bar_cell(
						i, hashlen, hash, percent,
					),
				);
			}
			s.push(b']');
		}
		// 5 = 1 space + 3 digits + 1 %
		if proglen >= 5 {
			s.extend_from_slice(
				format!(" {percent:3}%").as_bytes(),
			);
		}
		s.push(b'\r');
		self.print(&s);
		self.out.flush();
	}

	// one column of the bar, the ILoveCandy one with chomp
	fn bar_cell(
		&self,
		i: i32,
		hashlen: i32,
		hash: i32,
		percent: c_int,
	) -> &'static [u8] {
		let done = hashlen - hash;
		if self.config.chomp == 0 {
			return if i > done { b"#" } else { b"-" };
		}
		if i > done {
			b"-"
		} else if i == done {
			if percent % 2 == 0 {
				b"\x1b[1;33mC\x1b[m"
			} else {
				b"\x1b[1;33mc\x1b[m"
			}
		} else if i % 3 == 0 {
			b"\x1b[0;37mo\x1b[m"
		} else {
			b"\x1b[0;37m \x1b[m"
		}
	}

	// flush_output_list
	fn flush_output_list(&mut self) {
		self.out.flush();
		for s in std::mem::take(&mut self.output) {
			self.out.stderr.extend_from_slice(&s);
		}
		self.out.flush();
	}

	fn progressbar_enabled(&mut self) -> bool {
		self.config.noprogressbar == 0 && (self.term.cols)() != 0
	}

	// console_cursor_goto_bar
	fn goto_bar(&mut self, num: c_int) {
		let mut s = Vec::new();
		let cur = self.multibar.cursor_lineno;
		if num > cur {
			console_cursor_move_down(
				&mut s,
				num.wrapping_sub(cur) as u32,
			);
		} else if num < cur {
			console_cursor_move_up(
				&mut s,
				cur.wrapping_sub(num) as u32,
			);
		}
		self.print(&s);
		self.multibar.cursor_lineno = num;
	}

	// the end of every callback: what it printed goes out, the bar
	// cursor is published for the soft interrupt handler
	fn end_callback(&mut self) {
		self.out.flush();
		let m = &self.multibar;
		set_bars_below(m.active.len(), m.cursor_lineno);
	}

	// console_cursor_move_end: the line after the last active bar
	pub fn console_cursor_move_end(&mut self) {
		self.goto_bar(self.multibar.active.len() as c_int);
	}

	// init_total_progressbar
	fn init_total_progressbar(&mut self) {
		self.totalbar = Some(Bar {
			filename: b"Total".to_vec(),
			init_time: (self.term.now_ms)(),
			total_size: self.list_total,
			howmany: self.list_total_pkgs,
			..Bar::default()
		});
	}

	// draw_pacman_progress_bar
	fn draw(&mut self, bar: &Bar) {
		let cols = (self.term.cols)();
		let file_percent = match bar.total_size {
			0 => 100,
			t => bar.sync_xfered.wrapping_mul(100).wrapping_div(t)
				as c_int,
		};
		let eta_h = bar.eta / 3600;
		let eta_m = bar.eta % 3600 / 60;
		let eta_s = bar.eta % 60;
		let mut fname = clean_filename(&bar.filename);
		if bar.howmany > 0 {
			let d = number_length(bar.howmany);
			// snprintf into strlen + 2 * digits + 5: a downloaded
			// count wider than howmany is cut
			let room = fname.len() + 2 * d + 4;
			let n = format!(
				" ({:d$}/{:d$})",
				bar.downloaded, bar.howmany
			);
			fname.extend_from_slice(n.as_bytes());
			fname.truncate(room);
		}
		let infolen = (i32::from(cols) * 6 / 10).max(50);
		// 1 space + filenamelen + 1 space + 6 for size + 1 space + 3
		// for label + 2 spaces + 4 for rate + 1 space + 3 for label + 2
		// for /s + 1 space + 5 for eta
		let filenamelen = infolen - 30;
		let (w, padwid) = fit(mbstowcs(&fname).0, filenamelen);
		let (rate, rate_label) = humanize_size(cvtt(bar.rate), 0, -1);
		let (xfered, xfered_label) =
			humanize_size(bar.sync_xfered, 0, -1);
		let mut s = [&b" "[..], &encode(&w), &spaces(padwid), b" "]
			.concat();
		// 1.62 MiB/s, 11.6 MiB/s, but 116 KiB/s and 1116 KiB/s
		let prec = match rate {
			r if r < 9.995 => 2,
			r if r < 99.95 => 1,
			_ => 0,
		};
		let (xl, rl) = (xfered_label, rate_label);
		let line = format!(
			"{xfered:6.1} {xl:>3}  {rate:4.prec$} {rl:>3}/s "
		);
		s.extend_from_slice(line.as_bytes());
		let eta = match (eta_h, eta_m) {
			(0, m) => format!("{m:02}:{eta_s:02}"),
			(1, m) if m < 40 => format!("{:02}:{eta_s:02}", m + 60),
			_ => "--:--".to_string(),
		};
		s.extend_from_slice(eta.as_bytes());
		self.print(&s);
		self.fill_progress(file_percent, i32::from(cols) - infolen);
	}

	// draws the total bar where the cursor is
	fn draw_total(&mut self) {
		if let Some(t) = self.totalbar.take() {
			self.draw(&t);
			self.totalbar = Some(t);
		}
	}

	fn find_bar(&self, filename: &[u8]) -> Option<usize> {
		let f = until_nul(filename);
		self.multibar.active.iter().position(|b| b.filename == f)
	}

	// dload_init_event
	fn dload_init(&mut self, filename: &[u8]) {
		let cleaned = clean_filename(filename);
		if !self.progressbar_enabled() {
			self.print(&[b" ", &cleaned[..], b" downloading...\n"]
				.concat());
			return;
		}
		let bar = Bar {
			filename: until_nul(filename).to_vec(),
			init_time: (self.term.now_ms)(),
			..Bar::default()
		};
		self.multibar.active.push(bar);
		// the cursor goes to the old end, under the bars before it
		let end = self.multibar.active.len() as c_int - 1;
		self.goto_bar(end);
		self.print(&[b" ", &cleaned[..], b"\n"].concat());
		self.multibar.cursor_lineno += 1;
		if self.total_enabled {
			self.draw_total();
			self.print(b"\n");
			self.multibar.cursor_lineno += 1;
		}
	}

	// update_bar_stats: false when the last update is too recent
	fn update_bar_stats(now: i64, bar: &mut Bar) -> bool {
		let timediff = now.wrapping_sub(bar.sync_time);
		if timediff < UPDATE_SPEED_MS {
			return false;
		}
		let last_chunk_amount =
			bar.xfered.wrapping_sub(bar.sync_xfered);
		bar.sync_xfered = bar.xfered;
		bar.sync_time = now;
		let last_chunk_rate =
			last_chunk_amount as f64 * 1000.0 / timediff as f64;
		// average rate to reduce jumpiness
		bar.rate = (last_chunk_rate + 2.0 * bar.rate) / 3.0;
		bar.eta = if bar.rate > 0.0 {
			let left = bar.total_size.wrapping_sub(bar.sync_xfered);
			cvtt(left as f64 / bar.rate) as u32
		} else {
			u32::MAX
		};
		true
	}

	// update_bar_finalstats
	fn update_bar_finalstats(now: i64, bar: &mut Bar) {
		bar.xfered = bar.total_size;
		bar.sync_xfered = bar.total_size;
		// a transfer under 1 ms counts as 1 ms for the rate
		let timediff = now.wrapping_sub(bar.init_time).max(1);
		bar.rate = bar.total_size as f64 * 1000.0 / timediff as f64;
		// elapsed time rounded to the nearest second
		bar.eta = (timediff.wrapping_add(500) as u32) / 1000;
	}

	// dload_progress_event
	fn dload_progress(
		&mut self,
		filename: &[u8],
		downloaded: i64,
		total: i64,
	) {
		if !self.progressbar_enabled() {
			return;
		}
		let Some(index) = self.find_bar(filename) else {
			return;
		};
		let now = (self.term.now_ms)();
		let bar = &mut self.multibar.active[index];
		// the total size comes after the download starts
		let last_chunk_amount = downloaded.wrapping_sub(bar.xfered);
		bar.xfered = downloaded;
		bar.total_size = total;
		if Self::update_bar_stats(now, bar) {
			let bar = bar.clone();
			self.goto_bar(index as c_int);
			self.draw(&bar);
		}
		if self.total_enabled {
			let now = (self.term.now_ms)();
			let redraw = self.totalbar.as_mut().is_some_and(|t| {
				t.xfered = t
					.xfered
					.wrapping_add(last_chunk_amount);
				Self::update_bar_stats(now, t)
			});
			if redraw {
				self.console_cursor_move_end();
				self.draw_total();
			}
		}
		self.out.flush();
	}

	// dload_retry_event
	fn dload_retry(&mut self, filename: &[u8], resume: bool) {
		if !self.progressbar_enabled() {
			return;
		}
		let Some(index) = self.find_bar(filename) else {
			return;
		};
		let now = (self.term.now_ms)();
		let bar = &mut self.multibar.active[index];
		// the total does not count partial downloads that restart
		let total =
			self.totalbar.as_mut().filter(|_| self.total_enabled);
		if !resume && let Some(t) = total {
			t.xfered = t.xfered.wrapping_sub(bar.xfered);
		}
		bar.xfered = 0;
		bar.total_size = 0;
		bar.init_time = now;
		bar.sync_time = 0;
		bar.sync_xfered = 0;
		bar.rate = 0.0;
		bar.eta = 0;
	}

	// dload_complete_event
	fn dload_complete(
		&mut self,
		filename: &[u8],
		total: i64,
		result: c_int,
	) {
		if !self.progressbar_enabled() {
			return;
		}
		if self.total_enabled
			&& let Some(t) = &mut self.totalbar
		{
			t.downloaded = t.downloaded.wrapping_add(1);
		}
		let Some(mut index) = self.find_bar(filename) else {
			return;
		};
		let bar = &mut self.multibar.active[index];
		bar.completed = true;
		// not set yet if no progress event came before the end
		bar.total_size = total;
		match result {
			1 => {
				self.goto_bar(index as c_int);
				let cleaned = clean_filename(filename);
				self.print(&[
					b" ",
					&cleaned[..],
					b" is up to date",
				]
				.concat());
				self.erase_line();
			}
			0 => {
				let now = (self.term.now_ms)();
				Self::update_bar_finalstats(now, bar);
				let up = &self.term.move_completed_up;
				if up.load(Ordering::Relaxed) && index != 0 {
					// the completed bar moves to the top
					self.multibar.active.swap(0, index);
					let former_top = self.multibar.active
						[index]
						.clone();
					self.goto_bar(index as c_int);
					self.draw(&former_top);
					index = 0;
				}
				let bar = self.multibar.active[index].clone();
				self.goto_bar(index as c_int);
				self.draw(&bar);
			}
			_ => {
				self.goto_bar(index as c_int);
				let name = until_nul(filename);
				self.print(&[
					b" ",
					name,
					b" failed to download",
				]
				.concat());
				self.erase_line();
			}
		}
		self.out.flush();
		// completed bars at the top are never redrawn
		while self.multibar.active.first().is_some_and(|b| b.completed)
		{
			self.multibar.active.remove(0);
			self.multibar.cursor_lineno -= 1;
		}
	}

	fn erase_line(&mut self) {
		let mut s = Vec::new();
		console_erase_line(&mut s);
		self.print(&s);
	}

	// display_optdepends of a new package, display_new_optdepends of an
	// upgrade (old Some)
	fn show_optdepends(&mut self, old: Option<&Package>, new: &Package) {
		let (local, pending) = self.lookup.installed();
		let local: Vec<&Package> = local.iter().collect();
		let pending: Vec<&Package> = pending.iter().collect();
		let lists = (&local[..], &pending[..]);
		let cols = (self.term.cols)();
		let (out, c) = (&mut self.out.stdout, &self.config.colstr);
		match old {
			None => display_optdepends(out, c, new, lists, cols),
			Some(old) => display_new_optdepends(
				out,
				c,
				(old, new),
				lists,
				cols,
			),
		}
	}

	// cb_event
	fn cb_event(&mut self, event: &Event<'_>) {
		if self.config.print != 0 {
			self.console_cursor_move_end();
			return;
		}
		let bar = self.config.noprogressbar == 0;
		match *event {
			Event::HookStart { when } => match when {
				HookWhen::PreTransaction => self.colon(
					b"Running pre-transaction hooks...\n",
				),
				HookWhen::PostTransaction => self.colon(
					b"Running post-transaction hooks...\n",
				),
			},
			Event::HookRunStart(e) => {
				let d = number_length(e.total);
				let name = until_nul(e.desc.unwrap_or(e.name));
				let head = format!(
					"({:d$}/{:d$}) ",
					e.position, e.total
				);
				self.print(&[head.as_bytes(), name, b"\n"]
					.concat());
			}
			Event::CheckdepsStart => {
				self.print(b"checking dependencies...\n")
			}
			Event::FileconflictsStart if !bar => {
				self.print(b"checking for file conflicts...\n")
			}
			Event::ResolvedepsStart => {
				self.print(b"resolving dependencies...\n")
			}
			Event::InterconflictsStart => {
				self
					.print(b"looking for conflicting packages...\n")
			}
			Event::TransactionStart => {
				self.colon(b"Processing package changes...\n")
			}
			Event::PackageOperationStart(e) if !bar => {
				let name = |p: Option<&Package>| {
					p.map(|p| p.name_bytes().to_vec())
						.unwrap_or_default()
				};
				let (verb, pkg): (&[u8], _) = match e.operation
				{
					PackageOperation::Install => {
						(b"installing ", e.newpkg)
					}
					PackageOperation::Upgrade => {
						(b"upgrading ", e.newpkg)
					}
					PackageOperation::Reinstall => {
						(b"reinstalling ", e.newpkg)
					}
					PackageOperation::Downgrade => {
						(b"downgrading ", e.newpkg)
					}
					PackageOperation::Remove => {
						(b"removing ", e.oldpkg)
					}
				};
				let line =
					[verb, &name(pkg), b"...\n"].concat();
				self.print(&line);
			}
			Event::PackageOperationDone(e) => {
				match (e.operation, e.oldpkg, e.newpkg) {
					(
						PackageOperation::Install,
						_,
						Some(new),
					) => self.show_optdepends(None, new),
					(
						PackageOperation::Upgrade
						| PackageOperation::Downgrade,
						Some(old),
						Some(new),
					) => self.show_optdepends(
						Some(old),
						new,
					),
					_ => {}
				}
			}
			Event::IntegrityStart if !bar => {
				self.print(b"checking package integrity...\n")
			}
			Event::KeyringStart if !bar => {
				self.print(b"checking keyring...\n")
			}
			Event::KeyDownloadStart => {
				self.print(b"downloading required keys...\n")
			}
			Event::LoadStart if !bar => {
				self.print(b"loading package files...\n")
			}
			Event::ScriptletInfo { line } => {
				self.print(until_nul(line))
			}
			Event::DbRetrieveStart => self.on_progress = true,
			Event::PkgRetrieveStart { num, total_size } => {
				self.colon(b"Retrieving packages...\n");
				self.on_progress = true;
				self.list_total_pkgs = num;
				self.list_total = total_size;
				self.total_enabled = total_size != 0
					&& num > 1 && self
					.progressbar_enabled();
				if self.total_enabled {
					self.init_total_progressbar();
				}
			}
			Event::DiskspaceStart if !bar => self
				.print(b"checking available disk space...\n"),
			Event::OptdepRemoval { pkg, optdep } => {
				let dep = dep_compute_string(optdep);
				let msg = [
					pkg.name_bytes(),
					b" optionally requires ",
					&dep,
					b"\n",
				];
				self.colon(&msg.concat());
			}
			Event::DatabaseMissing { dbname }
				if self.config.op_s_sync == 0 =>
			{
				let opt: &[u8] = match self.config.op {
					PM_OP_FILES => b"-Fy",
					_ => b"-Sy",
				};
				let msg = [
					b"database file for '",
					until_nul(dbname),
					b"' does not exist (use '",
					opt,
					b"' to download)\n",
				];
				self.warn(&msg.concat());
			}
			Event::PacnewCreated { file, .. } => {
				let f = until_nul(file);
				self.warn_delayed(
					&[
						f,
						b" installed as ",
						f,
						b".pacnew\n",
					]
					.concat(),
				);
			}
			Event::PacsaveCreated { file, .. } => {
				let f = until_nul(file);
				self.warn_delayed(
					&[f, b" saved as ", f, b".pacsave\n"]
						.concat(),
				);
			}
			Event::DbRetrieveDone
			| Event::DbRetrieveFailed
			| Event::PkgRetrieveDone { .. }
			| Event::PkgRetrieveFailed { .. } => {
				self.console_cursor_move_end();
				if self.total_enabled {
					if let Some(mut t) =
						self.totalbar.take()
					{
						let now = (self.term.now_ms)();
						Self::update_bar_finalstats(
							now, &mut t,
						);
						self.draw(&t);
					}
					self.print(b"\n");
				}
				self.total_enabled = false;
				self.flush_output_list();
				self.on_progress = false;
			}
			// done events, starts the progress bar stands for
			_ => {}
		}
		self.out.flush();
	}

	// cb_question
	fn cb_question(&mut self, question: &mut Question<'_>) {
		if self.config.print != 0 {
			let yes = matches!(
				question,
				Question::InstallIgnorepkg { .. }
					| Question::ReplacePkg { .. }
			);
			question.set_answer(c_int::from(yes));
			return;
		}
		let answer = self.ask(question);
		question.set_answer(answer);
		// --ask inverts the default answer of the types it names
		let ask = self.config.ask as c_int;
		if self.config.noask != 0 && ask & question.kind() != 0 {
			question.set_answer(c_int::from(
				question.answer() == 0,
			));
		}
	}

	fn ask(&mut self, question: &Question<'_>) -> c_int {
		let (out, term) = (&mut self.out, &mut self.term);
		let config = &self.config;
		let yes = |b: bool| c_int::from(b);
		match *question {
			Question::InstallIgnorepkg { pkg, .. } => {
				if config.op_s_downloadonly != 0 {
					return 1;
				}
				let msg = [pkg.name_bytes(), IGNORED].concat();
				yes(yesno(out, config, term, &msg))
			}
			Question::ReplacePkg {
				oldpkg,
				newpkg,
				newdb,
				..
			} => {
				let msg = [
					b"Replace ",
					oldpkg.name_bytes(),
					b" with ",
					until_nul(newdb.name()),
					b"/",
					newpkg.name_bytes(),
					b"?",
				];
				yes(yesno(out, config, term, &msg.concat()))
			}
			Question::ConflictPkg { conflict, .. } => {
				let msg =
					conflict_msg(conflict, &config.colstr);
				yes(noyes(out, config, term, &msg))
			}
			Question::RemovePkgs { packages, .. } => {
				ask_remove_pkgs(out, config, term, packages)
			}
			Question::SelectProvider {
				providers,
				dbs,
				depend,
				..
			} => {
				let p: (&[&Package], &[&[u8]]) =
					(providers, dbs);
				ask_provider(out, config, term, p, depend)
			}
			Question::CorruptedPkg {
				filepath, reason, ..
			} => {
				let msg = [
					b"File ",
					until_nul(filepath),
					b" is corrupted (",
					reason.strerror().as_bytes(),
					b").\nDo you want to delete it?",
				];
				yes(yesno(out, config, term, &msg.concat()))
			}
			Question::ImportKey {
				uid, fingerprint, ..
			} => {
				// the uid is unknown with db signatures
				let fpr = until_nul(fingerprint);
				let msg = match uid {
					None => [
						&b"Import PGP key "[..],
						fpr,
						b"?",
					]
					.concat(),
					Some(uid) => {
						let uid = until_nul(uid);
						let parts: [&[u8]; 5] = [
							b"Import PGP key ",
							fpr,
							b", \"",
							uid,
							b"\"?",
						];
						parts.concat()
					}
				};
				yes(yesno(out, config, term, &msg))
			}
		}
	}

	// cb_progress
	fn cb_progress(
		&mut self,
		event: Progress,
		pkgname: &[u8],
		percent: c_int,
		howmany: usize,
		current: usize,
	) {
		let pkgname = until_nul(pkgname);
		let has_pkgname = !pkgname.is_empty();
		let cols = (self.term.cols)();
		if self.config.noprogressbar != 0 || cols == 0 {
			return;
		}
		if percent == 0 {
			self.update_timediff(true);
		} else if percent == 100 {
			// once per bar, the timediff is not checked
			if self.prevpercent == 100 {
				return;
			}
		} else if current == self.prevcurrent
			&& (!has_pkgname
				|| percent == self.prevpercent
				|| self.update_timediff(false)
					< UPDATE_SPEED_MS)
		{
			// a bar with a package name moves when the percentage
			// changed and enough time passed
			return;
		}
		self.prevpercent = percent;
		self.prevcurrent = current;
		let opr: &[u8] = match event {
			Progress::AddStart => b"installing",
			Progress::UpgradeStart => b"upgrading",
			Progress::DowngradeStart => b"downgrading",
			Progress::ReinstallStart => b"reinstalling",
			Progress::RemoveStart => b"removing",
			Progress::ConflictsStart => {
				b"checking for file conflicts"
			}
			Progress::DiskspaceStart => {
				b"checking available disk space"
			}
			Progress::IntegrityStart => {
				b"checking package integrity"
			}
			Progress::KeyringStart => b"checking keys in keyring",
			Progress::LoadStart => b"loading package files",
		};
		let infolen = (i32::from(cols) * 6 / 10).max(50);
		// the package counts scale with their digits
		let digits = number_length(howmany);
		// room left for the text after "(n/m) "
		let textlen = infolen - 3 - 2 * digits as i32 - 1;
		let text = match has_pkgname {
			true => [opr, b" ", pkgname].concat(),
			false => opr.to_vec(),
		};
		let (w, padwid) = fit(mbstowcs(&text).0, textlen);
		let head = format!("({current:digits$}/{howmany:digits$}) ");
		self.print(&[head.as_bytes(), &encode(&w), &spaces(padwid)]
			.concat());
		self.fill_progress(percent, i32::from(cols) - infolen);
		if percent == 100 {
			self.print(b"\n");
			self.flush_output_list();
			self.on_progress = false;
		} else {
			self.on_progress = true;
		}
	}

	// cb_download: .sig files get no bar
	fn cb_download(&mut self, filename: &[u8], event: DownloadEvent) {
		if until_nul(filename).ends_with(b".sig") {
			return;
		}
		match event {
			DownloadEvent::Init { .. } => self.dload_init(filename),
			DownloadEvent::Progress { downloaded, total } => {
				self.dload_progress(filename, downloaded, total)
			}
			DownloadEvent::Retry { resume } => {
				self.dload_retry(filename, resume)
			}
			DownloadEvent::Completed { total, result } => {
				self.dload_complete(filename, total, result)
			}
		}
	}

	// cb_log: delayed while a bar runs. the C skips an empty format,
	// here an empty message
	fn cb_log(&mut self, level: LogLevel, msg: &[u8]) {
		if msg.is_empty() {
			return;
		}
		let level = level as u16;
		if self.on_progress {
			if let Some(s) = pm_vasprintf(&self.config, level, msg)
			{
				self.output.push(s);
			}
			return;
		}
		let now = (self.term.now_secs)();
		if let Some(s) = pm_vfprintf(&self.config, level, msg, now) {
			self.out.stderr.extend_from_slice(&s);
		}
	}
}

const IGNORED: &[u8] = b" is in IgnorePkg/IgnoreGroup. Install anyway?";

// the conflict question, with the reason only when it says something
// new
fn conflict_msg(conflict: &Conflict, c: &ColStr) -> Vec<u8> {
	let (p1, p2) = (&conflict.package1, &conflict.package2);
	let reason = until_nul(&conflict.reason.name);
	let ver = |p: &Package| {
		until_nul(p.version.as_deref().unwrap_or_default()).to_vec()
	};
	let mut msg = [
		p1.name_bytes(),
		b"-",
		c.faint,
		&ver(p1),
		c.nocolor,
		b" and ",
		p2.name_bytes(),
		b"-",
		c.faint,
		&ver(p2),
		c.nocolor,
		b" are in conflict",
	]
	.concat();
	if p1.name_bytes() != reason && p2.name_bytes() != reason {
		msg.extend_from_slice(&[b" (", reason, b")"].concat());
	}
	msg.extend_from_slice(&[b". Remove ", p2.name_bytes(), b"?"].concat());
	msg
}

// ALPM_QUESTION_REMOVE_PKGS: the names listed, then skip them?
fn ask_remove_pkgs<R: BufRead>(
	out: &mut Output,
	config: &Config,
	term: &mut Term<R>,
	packages: &[&Package],
) -> c_int {
	let names: Vec<&[u8]> =
		packages.iter().map(|p| p.name_bytes()).collect();
	// _n(): singular for one package
	let what: &[u8] = match names.len() {
		1 => b"package cannot",
		_ => b"packages cannot",
	};
	let head = [
		&b"The following "[..],
		what,
		b" be upgraded due to unresolvable dependencies:\n",
	];
	let c = &config.colstr;
	colon_printf(&mut out.stdout, c, &head.concat());
	let title = Some(&b"     "[..]);
	list_display(&mut out.stdout, title, &names, (term.cols)(), c);
	out.stdout.push(b'\n');
	let what: &[u8] = match names.len() {
		1 => b"package",
		_ => b"packages",
	};
	let ask = [
		&b"Do you want to skip the above "[..],
		what,
		b" for this upgrade?",
	];
	c_int::from(noyes(out, config, term, &ask.concat()))
}

// ALPM_QUESTION_SELECT_PROVIDER: the providers by db, then the index.
// only the plural line ends in ':'
fn ask_provider<R: BufRead>(
	out: &mut Output,
	config: &Config,
	term: &mut Term<R>,
	(providers, dbs): (&[&Package], &[&[u8]]),
	depend: &Depend,
) -> c_int {
	let count = providers.len();
	let dep = dep_compute_string(depend);
	let head = match count {
		1 => format!("There is {count} provider available for "),
		_ => format!("There are {count} providers available for "),
	};
	let tail: &[u8] = if count == 1 { b"\n" } else { b":\n" };
	let c = &config.colstr;
	let line = [head.as_bytes(), &dep, tail].concat();
	colon_printf(&mut out.stdout, c, &line);
	let list: Vec<(Option<&[u8]>, &Package)> = dbs
		.iter()
		.zip(providers)
		.map(|(&d, &p)| (Some(d), p))
		.collect();
	select_display(&mut out.stdout, c, &list, (term.cols)());
	select_question(out, config, term, count as c_int)
}

impl<R: BufRead, L: Lookup> Callbacks for Frontend<R, L> {
	fn log(&mut self, level: LogLevel, msg: &[u8]) {
		self.cb_log(level, msg);
		self.end_callback();
	}

	fn event(&mut self, event: &Event<'_>) {
		self.cb_event(event);
		self.end_callback();
	}

	fn question(&mut self, question: &mut Question<'_>) {
		self.cb_question(question);
		self.end_callback();
	}

	fn progress(
		&mut self,
		progress: Progress,
		pkg: &[u8],
		percent: c_int,
		howmany: usize,
		current: usize,
	) {
		self.cb_progress(progress, pkg, percent, howmany, current);
		self.end_callback();
	}

	fn download(&mut self, filename: &[u8], event: DownloadEvent) {
		self.cb_download(filename, event);
		self.end_callback();
	}
}
