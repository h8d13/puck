// C side of lib/libalpm/dload.c (_alpm_download, alpm_fetch_pkgurl,
// _alpm_dload_payload_reset) and the util.c download helpers
// (_alpm_download_dir_setup, _alpm_remove_temporary_download_dir,
// _alpm_filecache_find/setup), plus the scripted HTTP server both
// sides download from.
//
// a CDload is one alpm_initialize'd handle holding the ALPM lock, with
// log/download/event/fetch callbacks recording into a Record like the
// Rust side's Recorder. only error and warning logs are kept (debug logs
// carry __FILE__/__LINE__). payloads are alpm_core Payloads copied into
// calloc'd struct dload_payload mirrors, released through
// _alpm_dload_payload_reset.
use std::collections::HashMap;
use std::ffi::{CStr, c_char, c_int, c_long, c_void};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use alpm_core::callbacks::{Callbacks, DownloadEvent, Event, Fetch, LogLevel};
use alpm_core::dload::Payload;

use crate::handle::*;
use crate::{CFile, CList, TempRoot, alpm_list_add, alpm_list_free, c_free};
use crate::{cstr, strdup, take, vsnprintf};

// CURL_ERROR_SIZE
const CURL_ERROR_SIZE: usize = 256;

// struct dload_payload, dload.h, HAVE_LIBCURL layout
#[repr(C)]
struct CPayload {
	handle: *mut c_void,
	tempfile_openmode: *const c_char,
	remote_name: *mut c_char,
	tempfile_name: *mut c_char,
	destfile_name: *mut c_char,
	fileurl: *mut c_char,
	filepath: *mut c_char,
	cache_servers: *mut CList,
	servers: *mut CList,
	respcode: c_long,
	mtime_existing_file: c_long,
	initial_size: i64,
	max_size: i64,
	prevprogress: i64,
	force: c_int,
	allow_resume: c_int,
	errors_ok: c_int,
	unlink_on_fail: c_int,
	download_signature: c_int,
	signature_optional: c_int,
	curl: *mut c_void,
	error_buffer: [c_char; CURL_ERROR_SIZE],
	signature: c_int,
	request_errors_ok: c_int,
	localf: *mut CFile,
}

unsafe extern "C" {
	fn _alpm_download(
		handle: *mut c_void,
		payloads: *mut CList,
		localpath: *const c_char,
		temporary_localpath: *const c_char,
	) -> c_int;
	fn _alpm_dload_payload_reset(payload: *mut CPayload);
	fn alpm_fetch_pkgurl(
		handle: *mut c_void,
		urls: *const CList,
		fetched: *mut *mut CList,
	) -> c_int;
	fn _alpm_download_dir_setup(
		handle: *mut c_void,
		dir: *const c_char,
	) -> *mut c_char;
	fn _alpm_remove_temporary_download_dir(dir: *const c_char);
	fn _alpm_filecache_find(
		handle: *mut c_void,
		filename: *const c_char,
	) -> *mut c_char;
	fn _alpm_filecache_setup(handle: *mut c_void) -> *const c_char;
}

// what the callbacks saw, in order
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Record {
	pub downloads: Vec<(Vec<u8>, DownloadEvent)>,
	// error and warning logs
	pub logs: Vec<(LogLevel, Vec<u8>)>,
	pub events: Vec<Event<'static>>,
}

// the Rust side's callbacks, recording like the C ones
#[derive(Default)]
pub struct Recorder(pub Record);

impl Callbacks for Recorder {
	fn log(&mut self, level: LogLevel, msg: &[u8]) {
		if matches!(level, LogLevel::Error | LogLevel::Warning) {
			self.0.logs.push((level, msg.to_vec()));
		}
	}

	fn download(&mut self, filename: &[u8], event: DownloadEvent) {
		self.0.downloads.push((filename.to_vec(), event));
	}

	fn event(&mut self, event: &Event<'_>) {
		self.0.events.push(pkg_retrieve(event));
	}
}

// an event dload sends (pkg_retrieve only, they borrow nothing), owned
pub fn pkg_retrieve(e: &Event<'_>) -> Event<'static> {
	match *e {
		Event::PkgRetrieveStart { num, total_size } => {
			Event::PkgRetrieveStart { num, total_size }
		}
		Event::PkgRetrieveDone { num, total_size } => {
			Event::PkgRetrieveDone { num, total_size }
		}
		Event::PkgRetrieveFailed { num, total_size } => {
			Event::PkgRetrieveFailed { num, total_size }
		}
		e => panic!("dload sent {e:?}"),
	}
}

pub type FetchFn = Box<dyn FnMut(&[u8], &[u8], bool) -> c_int + Send>;

// a fetchcb/XferCommand stand-in: a script over (url, localpath, force),
// every call recorded
pub struct Fetcher {
	pub script: FetchFn,
	pub calls: Vec<(Vec<u8>, Vec<u8>, bool)>,
}

impl Fetcher {
	pub fn new(script: FetchFn) -> Self {
		Fetcher {
			script,
			calls: Vec::new(),
		}
	}
}

impl Fetch for Fetcher {
	fn fetch(
		&mut self,
		url: &[u8],
		localpath: &[u8],
		force: bool,
	) -> c_int {
		self.calls.push((url.to_vec(), localpath.to_vec(), force));
		(self.script)(url, localpath, force)
	}
}

struct Ctx {
	rec: Record,
	fetch: Option<Fetcher>,
}

fn bytes(p: *const c_char) -> Vec<u8> {
	if p.is_null() {
		return Vec::new();
	}
	// SAFETY: libalpm passes nul-terminated strings
	unsafe { CStr::from_ptr(p) }.to_bytes().to_vec()
}

#[repr(C)]
struct CCompleted {
	total: i64,
	result: c_int,
}

#[repr(C)]
struct CPkgRetrieve {
	kind: c_int,
	num: usize,
	total_size: i64,
}

unsafe extern "C" fn dl_cb(
	ctx: *mut c_void,
	filename: *const c_char,
	event: c_int,
	data: *mut c_void,
) {
	// SAFETY: ctx is the CDload's boxed Ctx, data the
	// alpm_download_event_*_t of that event type
	let (ctx, ev) = unsafe {
		let ctx = &mut *ctx.cast::<Ctx>();
		let ev = match event {
			0 => DownloadEvent::Init {
				optional: *data.cast::<c_int>() != 0,
			},
			1 => {
				let p = data.cast::<[i64; 2]>();
				DownloadEvent::Progress {
					downloaded: (*p)[0],
					total: (*p)[1],
				}
			}
			2 => DownloadEvent::Retry {
				resume: *data.cast::<c_int>() != 0,
			},
			_ => {
				let c = &*data.cast::<CCompleted>();
				DownloadEvent::Completed {
					total: c.total,
					result: c.result,
				}
			}
		};
		(ctx, ev)
	};
	ctx.rec.downloads.push((bytes(filename), ev));
}

unsafe extern "C" fn log_cb(
	ctx: *mut c_void,
	level: c_int,
	fmt: *const c_char,
	args: *mut c_void,
) {
	let level = match level {
		1 => LogLevel::Error,
		2 => LogLevel::Warning,
		_ => return,
	};
	let mut buf = vec![0 as c_char; 8192];
	// SAFETY: fmt and args are the printf pair _alpm_log got, used once;
	// buf is writable for its length. ctx is the boxed Ctx
	let ctx = unsafe {
		vsnprintf(buf.as_mut_ptr(), buf.len(), fmt, args);
		&mut *ctx.cast::<Ctx>()
	};
	ctx.rec.logs.push((level, bytes(buf.as_ptr())));
}

unsafe extern "C" fn event_cb(ctx: *mut c_void, event: *mut c_void) {
	// SAFETY: event starts with its type; the pkg_retrieve types carry
	// alpm_event_pkg_retrieve_t. ctx is the boxed Ctx
	let (ctx, e) = unsafe {
		let e = &*event.cast::<CPkgRetrieve>();
		(&mut *ctx.cast::<Ctx>(), e)
	};
	let (num, total_size) = (e.num, e.total_size);
	let ev = match e.kind {
		21 => Event::PkgRetrieveStart { num, total_size },
		22 => Event::PkgRetrieveDone { num, total_size },
		23 => Event::PkgRetrieveFailed { num, total_size },
		_ => return,
	};
	ctx.rec.events.push(ev);
}

unsafe extern "C" fn fetch_cb(
	ctx: *mut c_void,
	url: *const c_char,
	localpath: *const c_char,
	force: c_int,
) -> c_int {
	// SAFETY: ctx is the boxed Ctx, fetch is set while this cb is
	let ctx = unsafe { &mut *ctx.cast::<Ctx>() };
	let f = ctx.fetch.as_mut().expect("fetchcb without a script");
	f.fetch(&bytes(url), &bytes(localpath), force != 0)
}

pub struct CDload {
	h: *mut c_void,
	ctx: Box<Ctx>,
	_guard: MutexGuard<'static, ()>,
}

impl Drop for CDload {
	fn drop(&mut self) {
		// SAFETY: h came from alpm_initialize, nothing uses it after; the
		// callbacks' ctx outlives it
		unsafe { alpm_release(self.h) };
	}
}

// strdup'd strings in a C list, freed with free_strs
fn str_list(strs: &[Vec<u8>]) -> *mut CList {
	strs.iter().fold(ptr::null_mut(), |list, s| {
		let s = cstr(s);
		// SAFETY: list is NULL or built here, the copy is owned by it
		unsafe { alpm_list_add(list, strdup(s.as_ptr()).cast()) }
	})
}

fn free_strs(list: *mut CList) {
	let mut i = list;
	while !i.is_null() {
		// SAFETY: nodes from str_list, each data strdup'd
		unsafe {
			c_free((*i).data);
			i = (*i).next;
		}
	}
	// SAFETY: nodes from alpm_list_add
	unsafe { alpm_list_free(list) };
}

fn dup(s: &[u8]) -> *mut c_char {
	let s = cstr(s);
	// SAFETY: valid C string, the copy goes to the payload
	unsafe { strdup(s.as_ptr()) }
}

fn dup_opt(s: &Option<Vec<u8>>) -> *mut c_char {
	s.as_deref().map_or(ptr::null_mut(), dup)
}

// a payload mirror and the server list heads the C advances past
struct Mirror {
	p: Box<CPayload>,
	cache_servers: *mut CList,
	servers: *mut CList,
}

impl Mirror {
	fn new(h: *mut c_void, p: &Payload) -> Mirror {
		let cache_servers = str_list(&p.cache_servers);
		let servers = str_list(&p.servers);
		let c = CPayload {
			handle: h,
			tempfile_openmode: ptr::null(),
			remote_name: dup(&p.remote_name),
			tempfile_name: dup(&p.tempfile_name),
			destfile_name: dup_opt(&p.destfile_name),
			fileurl: dup_opt(&p.fileurl),
			filepath: dup_opt(&p.filepath),
			cache_servers,
			servers,
			respcode: 0,
			mtime_existing_file: p.mtime_existing_file as c_long,
			initial_size: 0,
			max_size: p.max_size,
			prevprogress: 0,
			force: p.force.into(),
			allow_resume: p.allow_resume.into(),
			errors_ok: p.errors_ok.into(),
			unlink_on_fail: p.unlink_on_fail.into(),
			download_signature: p.download_signature.into(),
			signature_optional: p.signature_optional.into(),
			curl: ptr::null_mut(),
			error_buffer: [0; CURL_ERROR_SIZE],
			signature: 0,
			request_errors_ok: 0,
			localf: ptr::null_mut(),
		};
		Mirror {
			p: Box::new(c),
			cache_servers,
			servers,
		}
	}
}

impl Drop for Mirror {
	fn drop(&mut self) {
		// SAFETY: the strings are strdup'd, localf NULL or the C's FILE;
		// reset frees and zeroes them, the server lists stay ours
		unsafe { _alpm_dload_payload_reset(&mut *self.p) };
		free_strs(self.cache_servers);
		free_strs(self.servers);
	}
}

impl CDload {
	// a handle on fx's root and dbpath with the recording callbacks
	pub fn new(fx: &TempRoot) -> CDload {
		let guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
		let (root, dbpath) = (cstr(&fx.root()), cstr(&fx.dbpath()));
		let mut err = 0;
		// SAFETY: valid C strings, err is writable
		let h = unsafe {
			alpm_initialize(
				root.as_ptr(),
				dbpath.as_ptr(),
				&mut err,
			)
		};
		assert!(!h.is_null(), "alpm_initialize: {err}");
		let mut ctx = Box::new(Ctx {
			rec: Record::default(),
			fetch: None,
		});
		let c: *mut Ctx = &mut *ctx;
		// SAFETY: h is live; ctx is boxed and dropped after the handle
		unsafe {
			alpm_option_set_dlcb(h, Some(dl_cb), c.cast());
			alpm_option_set_logcb(h, Some(log_cb), c.cast());
			alpm_option_set_eventcb(h, Some(event_cb), c.cast());
		}
		CDload {
			h,
			ctx,
			_guard: guard,
		}
	}

	// alpm_option_set_parallel_downloads
	pub fn set_parallel(&self, n: u32) {
		// SAFETY: h is live
		unsafe { alpm_option_set_parallel_downloads(self.h, n) };
	}

	pub fn set_disable_dl_timeout(&self, off: bool) {
		// SAFETY: h is live
		unsafe {
			alpm_option_set_disable_dl_timeout(self.h, off.into())
		};
	}

	pub fn set_dbext(&self, dbext: &[u8]) {
		let d = cstr(dbext);
		// SAFETY: h is live, the C copies d
		unsafe { alpm_option_set_dbext(self.h, d.as_ptr()) };
	}

	pub fn set_remote_file_siglevel(&self, level: c_int) {
		// SAFETY: h is live
		unsafe { alpm_option_set_remote_file_siglevel(self.h, level) };
	}

	pub fn add_cachedir(&self, dir: &[u8]) {
		let d = cstr(dir);
		// SAFETY: h is live, the C copies d
		unsafe { alpm_option_add_cachedir(self.h, d.as_ptr()) };
	}

	// alpm_option_get_cachedirs
	pub fn cachedirs(&self) -> Vec<Vec<u8>> {
		// SAFETY: h is live, the list stays owned by it
		let mut i = unsafe { alpm_option_get_cachedirs(self.h) };
		let mut out = Vec::new();
		while !i.is_null() {
			// SAFETY: a live list node holding a C string
			unsafe {
				out.push(bytes((*i).data.cast()));
				i = (*i).next;
			}
		}
		out
	}

	// the fetchcb, None for the built-in downloader. calls of the
	// previous script come back
	pub fn set_fetch(&mut self, f: Option<Fetcher>) -> Option<Fetcher> {
		let c: *mut Ctx = &mut *self.ctx;
		let cb = f.as_ref().map(|_| fetch_cb as FetchCb);
		let old = std::mem::replace(&mut self.ctx.fetch, f);
		// SAFETY: h is live, ctx boxed
		unsafe { alpm_option_set_fetchcb(self.h, cb, c.cast()) };
		old
	}

	pub fn fetch_calls(&self) -> Vec<(Vec<u8>, Vec<u8>, bool)> {
		self.ctx.fetch
			.as_ref()
			.map(|f| f.calls.clone())
			.unwrap_or_default()
	}

	fn take_record(&mut self) -> Record {
		std::mem::take(&mut self.ctx.rec)
	}

	// pm_errno to ALPM_ERR_OK through a getter's CHECK_HANDLE
	fn reset_errno(&self) {
		// SAFETY: h is live
		unsafe { alpm_option_get_dbext(self.h) };
	}

	// _alpm_download: return value, pm_errno, what the callbacks saw
	pub fn download(
		&mut self,
		payloads: &[Payload],
		localpath: &[u8],
		temporary_localpath: &[u8],
	) -> (c_int, c_int, Record) {
		let mut mirrors: Vec<Mirror> = payloads
			.iter()
			.map(|p| Mirror::new(self.h, p))
			.collect();
		let list = mirrors.iter_mut().fold(ptr::null_mut(), |l, m| {
			let p: *mut CPayload = &mut *m.p;
			// SAFETY: l is NULL or built here; the mirrors outlive it
			unsafe { alpm_list_add(l, p.cast()) }
		});
		let (lp, tp) = (cstr(localpath), cstr(temporary_localpath));
		self.reset_errno();
		// SAFETY: h live, list of live payload mirrors, valid paths
		let ret = unsafe {
			_alpm_download(self.h, list, lp.as_ptr(), tp.as_ptr())
		};
		// SAFETY: h is live
		let errno = unsafe { alpm_errno(self.h) };
		// SAFETY: nodes from alpm_list_add, data owned by mirrors
		unsafe { alpm_list_free(list) };
		drop(mirrors);
		(ret, errno, self.take_record())
	}

	// alpm_fetch_pkgurl: return value, pm_errno, the fetched paths
	pub fn fetch_pkgurl(
		&mut self,
		urls: &[Vec<u8>],
	) -> (c_int, c_int, Vec<Vec<u8>>, Record) {
		let list = str_list(urls);
		let mut fetched: *mut CList = ptr::null_mut();
		// SAFETY: h is live, list of C strings, fetched starts NULL
		let ret = unsafe {
			alpm_fetch_pkgurl(self.h, list, &mut fetched)
		};
		// SAFETY: h is live
		let errno = unsafe { alpm_errno(self.h) };
		let mut out = Vec::new();
		let mut i = fetched;
		while !i.is_null() {
			// SAFETY: list built by the C, each data malloc'd
			unsafe {
				out.extend(take((*i).data.cast()));
				i = (*i).next;
			}
		}
		// SAFETY: nodes of the C's list, data freed above
		unsafe { alpm_list_free(fetched) };
		free_strs(list);
		(ret, errno, out, self.take_record())
	}

	// _alpm_download_dir_setup, None for NULL
	pub fn download_dir_setup(&mut self, dir: &[u8]) -> Option<Vec<u8>> {
		let d = cstr(dir);
		// SAFETY: h is live, the result is malloc'd
		take(unsafe { _alpm_download_dir_setup(self.h, d.as_ptr()) })
	}

	pub fn remove_temporary_download_dir(&self, dir: &[u8]) {
		let d = cstr(dir);
		// SAFETY: valid C string
		unsafe { _alpm_remove_temporary_download_dir(d.as_ptr()) };
	}

	// _alpm_filecache_find and the logs it made
	pub fn filecache_find(
		&mut self,
		name: &[u8],
	) -> (Option<Vec<u8>>, Record) {
		let n = cstr(name);
		// SAFETY: h is live, the result is malloc'd
		let r = take(unsafe {
			_alpm_filecache_find(self.h, n.as_ptr())
		});
		(r, self.take_record())
	}

	// _alpm_filecache_setup and the logs it made
	pub fn filecache_setup(&mut self) -> (Vec<u8>, Record) {
		// SAFETY: h is live, the string stays owned by the handle
		let r = bytes(unsafe { _alpm_filecache_setup(self.h) });
		(r, self.take_record())
	}
}

// _alpm_dload_payload_reset zeroes sizeof(struct dload_payload): every
// mirror byte zeroed and the canary after it intact means the sizes match
pub fn payload_layout_ok() -> bool {
	#[repr(C)]
	struct Guarded {
		p: CPayload,
		canary: [u8; 64],
	}
	let mut g = Box::new(Guarded {
		p: CPayload {
			handle: ptr::null_mut(),
			tempfile_openmode: ptr::null(),
			remote_name: ptr::null_mut(),
			tempfile_name: ptr::null_mut(),
			destfile_name: ptr::null_mut(),
			fileurl: ptr::null_mut(),
			filepath: ptr::null_mut(),
			cache_servers: ptr::null_mut(),
			servers: ptr::null_mut(),
			respcode: 7,
			mtime_existing_file: 7,
			initial_size: 7,
			max_size: 7,
			prevprogress: 7,
			force: 7,
			allow_resume: 7,
			errors_ok: 7,
			unlink_on_fail: 7,
			download_signature: 7,
			signature_optional: 7,
			curl: ptr::null_mut(),
			error_buffer: [7; CURL_ERROR_SIZE],
			signature: 7,
			request_errors_ok: 7,
			localf: ptr::null_mut(),
		},
		canary: [0xa5; 64],
	});
	// SAFETY: every pointer is NULL, reset frees nothing and writes
	// sizeof(struct dload_payload) zero bytes into g
	unsafe { _alpm_dload_payload_reset(&mut g.p) };
	let p = &g.p;
	let zero = p.respcode == 0
		&& p.prevprogress == 0
		&& p.signature_optional == 0
		&& p.error_buffer.iter().all(|&c| c == 0)
		&& p.signature == 0
		&& p.request_errors_ok == 0;
	zero && g.canary.iter().all(|&c| c == 0xa5)
}

// HTTP dates for Last-Modified, independent of the port's
pub fn http_date(t: i64) -> String {
	const WD: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
	const MON: [&str; 12] = [
		"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
		"Oct", "Nov", "Dec",
	];
	let days = t.div_euclid(86400);
	let secs = t.rem_euclid(86400);
	// civil_from_days, H. Hinnant
	let z = days + 719468;
	let era = z.div_euclid(146097);
	let doe = z - era * 146097;
	let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
	let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	let mp = (5 * doy + 2) / 153;
	let d = doy - (153 * mp + 2) / 5 + 1;
	let m = if mp < 10 { mp + 3 } else { mp - 9 };
	let y = yoe + era * 400 + i64::from(m <= 2);
	format!(
		"{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
		WD[days.rem_euclid(7) as usize],
		d,
		MON[(m - 1) as usize],
		y,
		secs / 3600,
		secs / 60 % 60,
		secs % 60
	)
}

// what the server answers on one request
#[derive(Clone, Debug)]
pub enum Reply {
	// 200 with Content-Length. ranges: "Range: bytes=N-" gets 206 (416
	// with "bytes */len" past the end). mtime: Last-Modified, and 304 for
	// an If-Modified-Since equal to it
	File {
		body: Vec<u8>,
		ranges: bool,
		mtime: Option<i64>,
	},
	// that status, an html body
	Status(u16, Vec<u8>),
	// Content-Length of body, `sent` bytes of it, then close
	Truncated {
		body: Vec<u8>,
		sent: usize,
	},
	// chunked transfer, cut: closed before the last chunk
	Chunked {
		body: Vec<u8>,
		cut: bool,
	},
	// Content-Length, `at` bytes, a pause, then the rest or a close
	Stall {
		body: Vec<u8>,
		at: usize,
		pause: Duration,
		finish: bool,
	},
	// that status with a Location
	Redirect(u16, String),
	// 200 with these header lines and a Content-Length
	Headers(Vec<String>, Vec<u8>),
	// 200 without Content-Length: the body ends with the connection
	Unsized(Vec<u8>),
	// these bytes as the whole response
	Raw(Vec<u8>),
	// close without a response
	Close,
	// no response for that long, then close
	Hang(Duration),
}

// one request as the server saw it
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Req {
	pub path: String,
	pub range: Option<String>,
	pub ims: Option<String>,
	pub agent: Option<String>,
	pub auth: Option<String>,
}

#[derive(Default)]
struct ServerState {
	// per path, the nth request gets the nth reply (the last repeats)
	routes: HashMap<String, Vec<Reply>>,
	hits: HashMap<String, usize>,
	log: Vec<Req>,
}

// how a Server frames its connections
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
	// HTTP/1.1 with "Connection: close", one response per connection
	Close,
	// HTTP/1.1 without "Connection: close", closed after one response
	// anyway: pactest's pmserve, keep-alive promised and not kept
	Drop,
	// HTTP/1.1 keep-alive: requests served on one connection until the
	// client closes it, a response that cannot be framed, or 1 s idle
	KeepAlive,
	// HTTP/1.0 without keep-alive, one response per connection
	Http10,
}

// 127.0.0.1:<random port>, a thread per connection, framed by its Style
// (one response per connection unless KeepAlive). unknown paths get 404
pub struct Server {
	port: u16,
	state: Arc<Mutex<ServerState>>,
	active: Arc<AtomicUsize>,
	peak: Arc<AtomicUsize>,
	stop: Arc<AtomicBool>,
	accept: Option<JoinHandle<()>>,
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
	buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn read_request(s: &mut TcpStream, wait: Duration) -> Option<Req> {
	s.set_read_timeout(Some(wait)).ok()?;
	let mut buf = Vec::new();
	let mut chunk = [0u8; 4096];
	while find_head_end(&buf).is_none() && buf.len() < 65536 {
		let n = s.read(&mut chunk).ok()?;
		if n == 0 {
			return None;
		}
		buf.extend_from_slice(&chunk[..n]);
	}
	let head = String::from_utf8_lossy(&buf[..find_head_end(&buf)?]);
	let mut lines = head.split("\r\n");
	let path = lines.next()?.split(' ').nth(1)?.to_string();
	let mut req = Req {
		path,
		range: None,
		ims: None,
		agent: None,
		auth: None,
	};
	for l in lines {
		let Some((k, v)) = l.split_once(':') else {
			continue;
		};
		let v = Some(v.trim().to_string());
		match k.to_ascii_lowercase().as_str() {
			"range" => req.range = v,
			"if-modified-since" => req.ims = v,
			"user-agent" => req.agent = v,
			"authorization" => req.auth = v,
			_ => {}
		}
	}
	Some(req)
}

fn head(style: Style, status: &str, extra: &[String]) -> Vec<u8> {
	let ver = match style {
		Style::Http10 => "HTTP/1.0",
		_ => "HTTP/1.1",
	};
	let mut h = format!("{ver} {status}\r\n");
	if style == Style::Close {
		h.push_str("Connection: close\r\n");
	}
	for e in extra {
		h.push_str(e);
		h.push_str("\r\n");
	}
	h.push_str("\r\n");
	h.into_bytes()
}

fn status_text(code: u16) -> &'static str {
	match code {
		200 => "OK",
		206 => "Partial Content",
		301 => "Moved Permanently",
		302 => "Found",
		303 => "See Other",
		304 => "Not Modified",
		307 => "Temporary Redirect",
		308 => "Permanent Redirect",
		403 => "Forbidden",
		404 => "Not Found",
		416 => "Range Not Satisfiable",
		500 => "Internal Server Error",
		503 => "Service Unavailable",
		_ => "Whatever",
	}
}

// true when the response was framed whole and the connection can serve
// another request
fn respond(
	s: &mut TcpStream,
	style: Style,
	req: &Req,
	reply: Reply,
	stalls: &AtomicUsize,
	peak: &AtomicUsize,
) -> bool {
	let head = |status: &str, extra: &[String]| head(style, status, extra);
	let r = match reply {
		Reply::File {
			body,
			ranges,
			mtime,
		} => {
			let mut extra = Vec::new();
			if let Some(t) = mtime {
				extra.push(format!(
					"Last-Modified: {}",
					http_date(t)
				));
				if req.ims.as_deref() == Some(&http_date(t)) {
					let h = head(
						"304 Not Modified",
						&extra,
					);
					return s.write_all(&h).is_ok();
				}
			}
			let from = req
				.range
				.as_deref()
				.and_then(|r| r.strip_prefix("bytes="))
				.and_then(|r| r.strip_suffix('-'))
				.and_then(|r| r.parse::<usize>().ok())
				.filter(|_| ranges);
			match from {
				Some(n) if n >= body.len() => {
					let page = b"<html>416</html>\n";
					extra.push(format!(
						"Content-Range: bytes */{}",
						body.len()
					));
					extra.push(format!(
						"Content-Length: {}",
						page.len()
					));
					let h = head(
						"416 Range Not Satisfiable",
						&extra,
					);
					[h, page.to_vec()].concat()
				}
				Some(n) => {
					let len = body.len();
					extra.push(format!(
						"Content-Range: bytes {}-{}/{}",
						n,
						len - 1,
						len
					));
					extra.push(format!(
						"Content-Length: {}",
						len - n
					));
					let h = head(
						"206 Partial Content",
						&extra,
					);
					[h, body[n..].to_vec()].concat()
				}
				None => {
					extra.push(format!(
						"Content-Length: {}",
						body.len()
					));
					[head("200 OK", &extra), body].concat()
				}
			}
		}
		Reply::Status(code, body) => {
			let extra = [format!("Content-Length: {}", body.len())];
			let st = format!("{code} {}", status_text(code));
			[head(&st, &extra), body].concat()
		}
		Reply::Truncated { body, sent } => {
			let extra = [format!("Content-Length: {}", body.len())];
			let r = [head("200 OK", &extra), body[..sent].to_vec()];
			let _ = s.write_all(&r.concat());
			return false;
		}
		Reply::Chunked { body, cut } => {
			let extra = ["Transfer-Encoding: chunked".to_string()];
			let mut out = head("200 OK", &extra);
			for c in body.chunks(7) {
				out.extend(format!("{:x}\r\n", c.len()).bytes());
				out.extend_from_slice(c);
				out.extend(b"\r\n");
			}
			if cut {
				let _ = s.write_all(&out);
				return false;
			}
			out.extend(b"0\r\n\r\n");
			out
		}
		Reply::Stall {
			body,
			at,
			pause,
			finish,
		} => {
			let extra = [format!("Content-Length: {}", body.len())];
			let first =
				[head("200 OK", &extra), body[..at].to_vec()]
					.concat();
			if s.write_all(&first).is_err() {
				return false;
			}
			let _ = s.flush();
			let now = stalls.fetch_add(1, Ordering::SeqCst) + 1;
			peak.fetch_max(now, Ordering::SeqCst);
			thread::sleep(pause);
			stalls.fetch_sub(1, Ordering::SeqCst);
			return finish && s.write_all(&body[at..]).is_ok();
		}
		Reply::Redirect(code, to) => {
			let extra = [
				format!("Location: {to}"),
				"Content-Length: 0".to_string(),
			];
			head(&format!("{code} {}", status_text(code)), &extra)
		}
		Reply::Headers(mut extra, body) => {
			extra.push(format!("Content-Length: {}", body.len()));
			[head("200 OK", &extra), body].concat()
		}
		Reply::Unsized(body) => {
			let _ = s.write_all(
				&[head("200 OK", &[]), body].concat(),
			);
			return false;
		}
		// framing unknown
		Reply::Raw(b) => {
			let _ = s.write_all(&b);
			return false;
		}
		Reply::Hang(d) => {
			thread::sleep(d);
			return false;
		}
		Reply::Close => return false,
	};
	s.write_all(&r).is_ok()
}

// the reply for a request, logged and counted
fn route(st: &Mutex<ServerState>, req: &Req) -> Reply {
	let mut g = st.lock().unwrap();
	g.log.push(req.clone());
	let n = g.hits.entry(req.path.clone()).or_default();
	let i = *n;
	*n += 1;
	match g.routes.get(&req.path) {
		Some(r) => r[i.min(r.len() - 1)].clone(),
		None => Reply::Status(404, b"<html>404</html>\n".to_vec()),
	}
}

// one connection: 5 s for the first request, 1 s for a kept-alive one
fn serve(
	mut s: TcpStream,
	style: Style,
	st: &Mutex<ServerState>,
	stalls: &AtomicUsize,
	peak: &AtomicUsize,
) {
	let mut wait = Duration::from_secs(5);
	while let Some(req) = read_request(&mut s, wait) {
		let reply = route(st, &req);
		let more = respond(&mut s, style, &req, reply, stalls, peak);
		if !more || style != Style::KeepAlive {
			break;
		}
		wait = Duration::from_secs(1);
	}
	let _ = s.flush();
	let _ = s.shutdown(Shutdown::Both);
}

impl Server {
	pub fn start() -> Server {
		Server::start_styled(Style::Close)
	}

	pub fn start_styled(style: Style) -> Server {
		let l = TcpListener::bind("127.0.0.1:0").unwrap();
		let port = l.local_addr().unwrap().port();
		let state = Arc::new(Mutex::new(ServerState::default()));
		let active = Arc::new(AtomicUsize::new(0));
		let stalls = Arc::new(AtomicUsize::new(0));
		let peak = Arc::new(AtomicUsize::new(0));
		let stop = Arc::new(AtomicBool::new(false));
		let (st, act, pk, sp) = (
			state.clone(),
			active.clone(),
			peak.clone(),
			stop.clone(),
		);
		let stl = stalls.clone();
		let accept = thread::spawn(move || {
			for conn in l.incoming() {
				if sp.load(Ordering::SeqCst) {
					break;
				}
				let Ok(s) = conn else {
					continue;
				};
				let (st, act, pk) =
					(st.clone(), act.clone(), pk.clone());
				let stl = stl.clone();
				thread::spawn(move || {
					act.fetch_add(1, Ordering::SeqCst);
					serve(s, style, &st, &stl, &pk);
					act.fetch_sub(1, Ordering::SeqCst);
				});
			}
		});
		Server {
			port,
			state,
			active,
			peak,
			stop,
			accept: Some(accept),
		}
	}

	pub fn port(&self) -> u16 {
		self.port
	}

	// "http://127.0.0.1:<port>"
	pub fn base(&self) -> String {
		format!("http://127.0.0.1:{}", self.port)
	}

	pub fn url(&self, path: &str) -> Vec<u8> {
		format!("{}{path}", self.base()).into_bytes()
	}

	// replies for a path, in request order
	pub fn route(&self, path: &str, replies: Vec<Reply>) {
		let mut g = self.state.lock().unwrap();
		g.routes.insert(path.to_string(), replies);
	}

	// requests seen since the last reset
	pub fn requests(&self) -> Vec<Req> {
		self.state.lock().unwrap().log.clone()
	}

	// most stalled responses at once since the last reset
	pub fn peak(&self) -> usize {
		self.peak.load(Ordering::SeqCst)
	}

	// waits for open connections to finish (up to 30 s), then forgets
	// the requests and hit counts
	pub fn reset(&self) {
		for _ in 0..3000 {
			if self.active.load(Ordering::SeqCst) == 0 {
				break;
			}
			thread::sleep(Duration::from_millis(10));
		}
		let mut g = self.state.lock().unwrap();
		g.log.clear();
		g.hits.clear();
		self.peak.store(0, Ordering::SeqCst);
	}
}

impl Drop for Server {
	fn drop(&mut self) {
		self.stop.store(true, Ordering::SeqCst);
		// wakes the accept loop
		let _ = TcpStream::connect(("127.0.0.1", self.port));
		if let Some(t) = self.accept.take() {
			let _ = t.join();
		}
	}
}

// a port nothing listens on (bound, then released)
pub fn closed_port() -> u16 {
	let l = TcpListener::bind("127.0.0.1:0").unwrap();
	l.local_addr().unwrap().port()
}

type FetchCb = unsafe extern "C" fn(
	*mut c_void,
	*const c_char,
	*const c_char,
	c_int,
) -> c_int;
