// port of lib/libalpm/dload.c, plus the util.c helpers only its callers
// need (_alpm_download_dir_setup, _alpm_remove_temporary_download_dir).
//
// libcurl is replaced by reqwest (blocking, rustls), one thread per
// transfer, the curl behaviour libalpm relies on rebuilt around it: the
// response code kept by the header callback, Range resume and curl's
// Content-Range check, If-Modified-Since and the time condition, the max
// file size, file:// urls, 10 redirects, the low-speed abort, the
// truncation check. error texts copy curl's where libalpm prints them.
// reqwest only times single waits: the low-speed abort is no byte for
// 10 s (curl: under 1 B/s on a 5 s average, for 10 s).
//
// handle state is DownloadState (handle->server_errors and the
// dload_interrupted static, both kept across calls), handle options are
// Settings. _alpm_log, dlcb and eventcb go through Callbacks (error and
// warning logs only), fetchcb through Fetch, the forked sandbox child
// through Sandbox. pm_errno comes back in Err, as the C leaves it: it can
// be Errno::Ok where the C fails without setting it.

use std::ffi::{OsStr, c_int};
use std::fs::{self, File, OpenOptions};
use std::hash::{BuildHasher, RandomState};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::ToSocketAddrs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::fs::{PermissionsExt, chown};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use reqwest::Url;
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::header;
use reqwest::redirect::Policy;
use rustix::fs::{AtFlags, CWD, Timespec, Timestamps};

use crate::callbacks::{Callbacks, DownloadEvent, Event, Fetch, LogLevel};
use crate::error::Errno;
use crate::util::{
	PATH_MAX, filecache_exists, filecache_find, filecache_setup,
	get_fullpath, strerror, until_nul,
};

// ALPM_SIG_PACKAGE, ALPM_SIG_PACKAGE_OPTIONAL
pub const SIG_PACKAGE: c_int = 1;
pub const SIG_PACKAGE_OPTIONAL: c_int = 1 << 1;
// hard upper limit of a .sig download
pub const SIG_MAX_SIZE: i64 = 16 * 1024;

// soft errors that block a server, 0 would disable blocking
const SERVER_ERROR_LIMIT: i32 = 3;
// RFC1123 hostname buffer of curl_gethost, nul included
const HOSTNAME_SIZE: usize = 256;
// CURLOPT_CONNECTTIMEOUT, CURLOPT_LOW_SPEED_TIME, CURLOPT_MAXREDIRS
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const LOW_SPEED_TIME: Duration = Duration::from_secs(10);
const MAX_REDIRS: usize = 10;
const KEEPALIVE: Duration = Duration::from_secs(60);

// the sandbox side of the handle, set when _alpm_use_sandbox holds (root,
// a sandbox user, one of the restrictions enabled)
pub trait Sandbox {
	// handle->sandboxuser
	fn user(&self) -> &[u8];
	// getpwnam(sandboxuser): uid and gid. Err(None) when there is no such
	// user, Err(Some(e)) when the lookup failed
	fn lookup(&self) -> Result<(u32, u32), Option<io::Error>>;
	// curl_download_internal_sandboxed: download_internal as the sandbox
	// user inside temporary_localpath, callbacks forwarded. the forked C
	// child keeps its own copies of state and payloads. returns the
	// result and the child's terminating signal (0 for none)
	fn download(
		&mut self,
		settings: &Settings,
		state: &DownloadState,
		cb: &mut dyn Callbacks,
		payloads: &mut [Payload],
		temporary_localpath: &[u8],
	) -> (Result<bool, Errno>, c_int);
	// kill(getpid(), sig), after the downloads are moved into place
	fn raise(&mut self, sig: c_int);
}

// the handle options the downloader reads
#[derive(Clone, Debug)]
pub struct Settings {
	// handle->parallel_downloads, 1 by default; 0 counts as 1
	// (alpm_option_set_parallel_downloads refuses it)
	pub parallel_downloads: u32,
	pub disable_dl_timeout: bool,
	// handle->dbext, picks the url .sig files are fetched from
	pub dbext: Vec<u8>,
}

impl Default for Settings {
	fn default() -> Self {
		Settings {
			parallel_downloads: 1,
			disable_dl_timeout: false,
			dbext: b".db".to_vec(),
		}
	}
}

// handle->server_errors (per host, -1 once blocked for good) and the
// dload_interrupted static: once a download went over its max size,
// every later transfer aborts
#[derive(Clone, Debug, Default)]
pub struct DownloadState {
	server_errors: Vec<(Vec<u8>, i32)>,
	interrupted: bool,
}

impl DownloadState {
	// whether a download went over its max size
	pub fn is_interrupted(&self) -> bool {
		self.interrupted
	}

	// the error count of a host, None before its first lookup
	pub fn server_errors(&self, host: &[u8]) -> Option<i32> {
		let h = self.server_errors.iter().find(|(h, _)| h == host);
		h.map(|(_, e)| *e)
	}

	// every host's error count in lookup order, and a state rebuilt from
	// them: the sandbox helper gets a copy like the C's forked child
	pub fn hosts(&self) -> &[(Vec<u8>, i32)] {
		&self.server_errors
	}

	pub fn from_hosts(
		hosts: Vec<(Vec<u8>, i32)>,
		interrupted: bool,
	) -> Self {
		DownloadState {
			server_errors: hosts,
			interrupted,
		}
	}

	// find_server_errors: the entry of the url's host, created on first
	// use; None when the url has no host
	fn find(&mut self, url: &[u8]) -> Option<(&[u8], &mut i32)> {
		let host = gethost(url)?;
		let i = match self
			.server_errors
			.iter()
			.position(|(h, _)| *h == host)
		{
			Some(i) => i,
			None => {
				self.server_errors.push((host, 0));
				self.server_errors.len() - 1
			}
		};
		let (h, e) = &mut self.server_errors[i];
		Some((h, e))
	}

	// should_skip_server: hard errors or too many soft ones
	fn should_skip(&mut self, url: &[u8]) -> bool {
		self.find(url).is_some_and(|(_, e)| {
			*e < 0 || *e >= SERVER_ERROR_LIMIT
		})
	}

	// should_skip_cache_server: hard errors only
	fn should_skip_cache(&mut self, url: &[u8]) -> bool {
		self.find(url).is_some_and(|(_, e)| *e < 0)
	}

	// server_soft_error
	fn soft_error(&mut self, url: &[u8], cb: &mut dyn Callbacks) {
		if self.should_skip(url) {
			return;
		}
		let Some((host, e)) = self.find(url) else {
			return;
		};
		*e += 1;
		if *e >= SERVER_ERROR_LIMIT {
			let m = cat(&[
				b"too many errors from ",
				host,
				b", skipping for the remainder of this transaction\n",
			]);
			cb.log(LogLevel::Warning, &m);
		}
	}

	// server_hard_error: blocks cache servers too
	fn hard_error(&mut self, url: &[u8], cb: &mut dyn Callbacks) {
		let Some((host, e)) = self.find(url) else {
			return;
		};
		if *e != -1 {
			*e = -1;
			let m = cat(&[
				b"fatal error from ",
				host,
				b", skipping for the remainder of this transaction\n",
			]);
			cb.log(LogLevel::Warning, &m);
		}
	}
}

// struct dload_payload. a payload names either fileurl, or filepath
// fetched from cache_servers then servers ("$server/$filepath").
// tempfile_name is where the transfer writes, renamed to destfile_name
// when set
#[derive(Debug, Default)]
pub struct Payload {
	pub remote_name: Vec<u8>,
	pub tempfile_name: Vec<u8>,
	pub destfile_name: Option<Vec<u8>>,
	pub fileurl: Option<Vec<u8>>,
	pub filepath: Option<Vec<u8>>,
	pub cache_servers: Vec<Vec<u8>>,
	pub servers: Vec<Vec<u8>>,
	// mtime of the existing destination, set by the download itself
	pub mtime_existing_file: i64,
	// 0 for no limit
	pub max_size: i64,
	pub force: bool,
	pub allow_resume: bool,
	pub errors_ok: bool,
	pub unlink_on_fail: bool,
	// also fetch "<url>.sig" into "<destfile or tempfile>.sig"
	pub download_signature: bool,
	pub signature_optional: bool,

	// payload->fileurl of the running transfer
	url: Option<Vec<u8>>,
	// response code of the last header seen, kept across retries
	respcode: i64,
	initial_size: i64,
	prevprogress: i64,
	// how far payload->cache_servers/servers have advanced
	next_cache: usize,
	next_server: usize,
	request_errors_ok: bool,
	// a .sig payload made by the download
	signature: bool,
	// tempfile_openmode "ab" instead of "wb"
	append: bool,
	// curl easy handle options that outlive a retry
	resume_from: i64,
	time_cond: bool,
	localf: Option<File>,
}

impl Payload {
	// the size the .part had when the transfer resumed from it
	pub fn initial_size(&self) -> i64 {
		self.initial_size
	}
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
	parts.concat()
}

fn path(p: &[u8]) -> &Path {
	Path::new(OsStr::from_bytes(until_nul(p)))
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
	if needle.is_empty() {
		return Some(0);
	}
	hay.windows(needle.len()).position(|w| w == needle)
}

// get_filename/mbasename: after the last '/', the whole string without one
fn basename(s: &[u8]) -> &[u8] {
	match s.iter().rposition(|&c| c == b'/') {
		Some(i) => &s[i + 1..],
		None => s,
	}
}

// curl_gethost: what sits between the first "//" and the next '/', a
// user:pass@ prefix dropped; file:// urls are "disk". None without "//"
// or for 256+ byte hosts
pub fn gethost(url: &[u8]) -> Option<Vec<u8>> {
	let url = until_nul(url);
	if url.starts_with(b"file://") {
		return Some(b"disk".to_vec());
	}
	let p = &url[find_sub(url, b"//")? + 2..];
	let mut host =
		&p[..p.iter().position(|&c| c == b'/').unwrap_or(p.len())];
	// the C scans back to the second byte only
	if let Some(q) = host.iter().rposition(|&c| c == b'@')
		&& q > 0
	{
		host = &host[q + 1..];
	}
	if host.len() > HOSTNAME_SIZE - 1 {
		return None;
	}
	Some(host.to_vec())
}

// payload_next_server: cache servers first (skipped on hard errors, their
// errors never count), then servers (skipped on hard or 3 soft errors)
fn next_server(state: &mut DownloadState, p: &mut Payload) -> Option<Vec<u8>> {
	while let Some(s) = p.cache_servers.get(p.next_cache) {
		p.next_cache += 1;
		if !state.should_skip_cache(s) {
			p.request_errors_ok = true;
			return Some(s.clone());
		}
	}
	while let Some(s) = p.servers.get(p.next_server) {
		p.next_server += 1;
		if !state.should_skip(s) {
			p.request_errors_ok = p.errors_ok;
			return Some(s.clone());
		}
	}
	None
}

// random suffix for mkstemp/mkdtemp's XXXXXX
fn random_suffix() -> Vec<u8> {
	const CHARS: &[u8] =
		b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	let mut x = RandomState::new().hash_one(Instant::now());
	(0..6).map(|_| {
		let c = CHARS[(x % CHARS.len() as u64) as usize];
		x /= CHARS.len() as u64;
		c
	})
	.collect()
}

// mkdtemp("<prefix>XXXXXX"), mode 0700: the name (the last one tried on
// failure) and the result
fn mkdtemp(prefix: &[u8]) -> (Vec<u8>, io::Result<()>) {
	let mut name = Vec::new();
	for _ in 0..100 {
		name = cat(&[prefix, &random_suffix()]);
		match fs::DirBuilder::new().mode(0o700).create(path(&name)) {
			Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
			r => return (name, r),
		}
	}
	(name, Err(io::ErrorKind::AlreadyExists.into()))
}

// umask without setting it (the C's umask(0)/umask(mask) pair): the Umask
// line of /proc/self/status (linux 4.7+), 022 when missing
fn current_umask() -> u32 {
	let status = fs::read("/proc/self/status").unwrap_or_default();
	let line = status
		.split(|&c| c == b'\n')
		.find_map(|l| l.strip_prefix(b"Umask:"));
	line.and_then(|v| std::str::from_utf8(v).ok())
		.and_then(|v| u32::from_str_radix(v.trim(), 8).ok())
		.unwrap_or(0o022)
}

// create_tempfile: "<localpath>alpmtmp.XXXXXX" made with O_EXCL, mode
// 0666 under the umask (the C's fchmod); becomes the payload's tempfile
// and remote name. false after logging when it cannot be made
fn create_tempfile(
	p: &mut Payload,
	localpath: &[u8],
	cb: &mut dyn Callbacks,
) -> bool {
	for _ in 0..100 {
		let name = cat(&[localpath, b"alpmtmp.", &random_suffix()]);
		let f = OpenOptions::new()
			.read(true)
			.write(true)
			.create_new(true)
			.mode(0o666)
			.open(path(&name));
		match f {
			Ok(f) => {
				p.remote_name = basename(&name).to_vec();
				p.tempfile_name = name;
				p.localf = Some(f);
				return true;
			}
			Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
			Err(_) => break,
		}
	}
	let m = b"failed to create temporary file for download\n";
	cb.log(LogLevel::Error, m);
	false
}

// utimes_long: atime and mtime to seconds, -1 leaves the file alone
fn utimes_long(p: &[u8], seconds: i64) {
	if seconds == -1 {
		return;
	}
	let t = Timespec {
		tv_sec: seconds,
		tv_nsec: 0,
	};
	let times = Timestamps {
		last_access: t,
		last_modification: t,
	};
	let _ = rustix::fs::utimensat(CWD, path(p), &times, AtFlags::empty());
}

// days since 1970-01-01 of a proleptic gregorian date
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
	let y = if m <= 2 { y - 1 } else { y };
	let era = y.div_euclid(400);
	let yoe = y - era * 400;
	let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
	let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	era * 146097 + doe - 719468
}

pub(crate) fn civil_from_days(z: i64) -> (i64, i64, i64) {
	let z = z + 719468;
	let era = z.div_euclid(146097);
	let doe = z - era * 146097;
	let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
	let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	let mp = (5 * doy + 2) / 153;
	let d = doy - (153 * mp + 2) / 5 + 1;
	let m = if mp < 10 { mp + 3 } else { mp - 9 };
	(yoe + era * 400 + i64::from(m <= 2), m, d)
}

pub(crate) const MONTHS: [&[u8]; 12] = [
	b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep",
	b"Oct", b"Nov", b"Dec",
];
const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];

// the If-Modified-Since date curl sends: "Sun, 06 Nov 1994 08:49:37 GMT"
pub fn http_date(t: i64) -> String {
	let (days, secs) = (t.div_euclid(86400), t.rem_euclid(86400));
	let (y, m, d) = civil_from_days(days);
	format!(
		"{}, {:02} {} {:4} {:02}:{:02}:{:02} GMT",
		WEEKDAYS[days.rem_euclid(7) as usize],
		d,
		String::from_utf8_lossy(MONTHS[(m - 1) as usize]),
		y,
		secs / 3600,
		secs / 60 % 60,
		secs % 60
	)
}

// Last-Modified as curl's getdate reads the usual forms (RFC 1123, RFC
// 850, asctime): a month name, hh:mm:ss, a day, a year, GMT/UTC or a
// numeric zone; weekday names are skipped. None when a part is missing
pub fn parse_http_date(s: &[u8]) -> Option<i64> {
	let (mut mon, mut day, mut year, mut time) = (None, None, None, None);
	let mut zone = 0i64;
	let tokens = s.split(|c| matches!(c, b' ' | b',' | b'-' | b'\t'));
	for tok in tokens.filter(|t| !t.is_empty()) {
		if tok.iter().all(u8::is_ascii_alphabetic) {
			let short =
				tok.get(..3).map(<[u8]>::to_ascii_lowercase);
			let i = MONTHS.iter().position(|m| {
				short.as_deref()
					== Some(&m.to_ascii_lowercase()[..])
			});
			if let Some(i) = i {
				mon = Some(i as i64 + 1);
			}
		} else if tok.contains(&b':') {
			let v: Vec<i64> = tok
				.split(|&c| c == b':')
				.map(|n| {
					std::str::from_utf8(n)
						.ok()?
						.parse()
						.ok()
				})
				.collect::<Option<_>>()?;
			match v[..] {
				[h, m, s] => time = Some(h * 3600 + m * 60 + s),
				[h, m] => time = Some(h * 3600 + m * 60),
				_ => return None,
			}
		} else if let [b'+' | b'-', rest @ ..] = tok {
			let n: i64 =
				std::str::from_utf8(rest).ok()?.parse().ok()?;
			let off = (n / 100) * 3600 + (n % 100) * 60;
			zone = if tok[0] == b'+' { off } else { -off };
		} else if tok.iter().all(u8::is_ascii_digit) {
			let n: i64 =
				std::str::from_utf8(tok).ok()?.parse().ok()?;
			if tok.len() <= 2
				&& day.is_none() && (1..=31).contains(&n)
			{
				day = Some(n);
			} else if year.is_none() {
				year = Some(match n {
					0..=69 if tok.len() <= 2 => n + 2000,
					70..=99 if tok.len() <= 2 => n + 1900,
					_ => n,
				});
			} else {
				return None;
			}
		}
	}
	let days = days_from_civil(year?, mon?, day?);
	Some(days * 86400 + time? - zone)
}

// one download stream's result, what curl reports through
// curl_easy_getinfo and the CURLMsg
#[derive(Debug)]
enum Code {
	Ok,
	// CURLE_ABORTED_BY_CALLBACK
	Aborted,
	// CURLE_COULDNT_RESOLVE_HOST
	Resolve,
	// every other CURLcode
	Failed,
}

#[derive(Debug)]
struct Transfer {
	code: Code,
	// CURLOPT_ERRORBUFFER
	error: Vec<u8>,
	respcode: i64,
	// CURLINFO_FILETIME, -1 unknown
	filetime: i64,
	// CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, -1 unknown
	remote_size: i64,
	// CURLINFO_SIZE_DOWNLOAD_T
	bytes_dl: i64,
	// CURLINFO_CONDITION_UNMET
	timecond: bool,
	effective_url: Vec<u8>,
	// size of the file when this attempt started
	start_len: i64,
}

type Fail = (Code, Vec<u8>);

fn failed(msg: impl Into<Vec<u8>>) -> Fail {
	(Code::Failed, msg.into())
}

enum Msg {
	Progress {
		slot: usize,
		dlnow: i64,
		dltotal: i64,
	},
	Done {
		slot: usize,
		file: File,
		xfer: Transfer,
	},
}

// what a transfer thread gets: the easy handle's options
struct Job {
	slot: usize,
	url: Vec<u8>,
	resume_from: i64,
	// CURLOPT_TIMECONDITION IFMODSINCE with this time
	time_cond: Option<i64>,
	respcode: i64,
	initial_size: i64,
	max_size: i64,
	user_agent: Option<Vec<u8>>,
	file: File,
}

// shared by the transfer threads of one download
#[derive(Clone)]
struct Worker {
	client: Client,
	tx: Sender<Msg>,
	interrupted: Arc<AtomicBool>,
}

// Curl_meets_timecondition for IFMODSINCE: an unknown (0) document time
// always meets it
fn meets_timecondition(timeofdoc: i64, timevalue: i64) -> bool {
	timeofdoc == 0 || timevalue == 0 || timeofdoc > timevalue
}

fn header_bytes(r: &Response, name: header::HeaderName) -> Option<&[u8]> {
	r.headers().get(name).map(|v| v.as_bytes())
}

// curl's Content-Range read: the first number (after any "bytes" or
// "bytes:" prefix), None when a '*' or nothing comes first
fn content_range_offset(v: &[u8]) -> Option<Option<i64>> {
	let i = v.iter().position(|c| c.is_ascii_digit() || *c == b'*');
	let d = &v[i?..];
	if d[0] == b'*' {
		return None;
	}
	let n = d.iter().take_while(|c| c.is_ascii_digit()).count();
	Some(std::str::from_utf8(&d[..n])
		.ok()
		.and_then(|s| s.parse().ok()))
}

fn is_timeout(e: &io::Error) -> bool {
	e.kind() == io::ErrorKind::TimedOut
		|| e.get_ref()
			.and_then(|i| i.downcast_ref::<reqwest::Error>())
			.is_some_and(reqwest::Error::is_timeout)
}

const TOO_SLOW: &str = "Operation too slow. \
	Less than 1 bytes/sec transferred the last 10 seconds";

// the curl error for a failed request (no response)
fn send_error(e: &reqwest::Error, url: &Url, start: Instant) -> Fail {
	if e.is_redirect() {
		return failed(format!(
			"Maximum ({MAX_REDIRS}) redirects followed"
		));
	}
	let ms = start.elapsed().as_millis();
	if e.is_connect() && e.is_timeout() {
		return failed(format!(
			"Connection timed out after {ms} milliseconds"
		));
	}
	if e.is_timeout() {
		return failed(TOO_SLOW);
	}
	if e.is_connect() {
		let host = url.host_str().unwrap_or_default();
		let port = url.port_or_known_default().unwrap_or_default();
		return failed(format!(
			"Failed to connect to {host}:{port} after {ms} ms: \
			 Could not connect to server"
		));
	}
	// hyper's IncompleteMessage
	let mut src: Option<&dyn std::error::Error> = Some(e);
	while let Some(s) = src {
		let text = s.to_string();
		if text.contains("connection closed before message completed") {
			return failed("Empty reply from server");
		}
		src = s.source();
	}
	failed(format!("Recv failure: {e}"))
}

// file:// url to a path (url's rules: localhost or no host, %XX
// decoded, query and fragment dropped)
fn file_url_path(url: &[u8]) -> Option<Vec<u8>> {
	let u = Url::parse(std::str::from_utf8(url).ok()?).ok()?;
	Some(u.to_file_path().ok()?.into_os_string().into_vec())
}

impl Worker {
	fn spawn(&self, job: Job) {
		let w = self.clone();
		thread::spawn(move || w.run(job));
	}

	fn run(self, mut job: Job) {
		let mut xfer = Transfer {
			code: Code::Ok,
			error: Vec::new(),
			respcode: job.respcode,
			filetime: -1,
			remote_size: -1,
			bytes_dl: 0,
			timecond: false,
			effective_url: job.url.clone(),
			start_len: job
				.file
				.metadata()
				.map_or(0, |m| m.len() as i64),
		};
		let file_url = job.url.len() >= 7
			&& job.url[..7].eq_ignore_ascii_case(b"file://");
		let r = match file_url {
			true => self.file(&mut job, &mut xfer),
			false => self.http(&mut job, &mut xfer),
		};
		if let Err((code, error)) = r {
			xfer.code = code;
			xfer.error = error;
		}
		let done = Msg::Done {
			slot: job.slot,
			file: job.file,
			xfer,
		};
		// the receiver lives until every transfer reported back
		let _ = self.tx.send(done);
	}

	// dload_progress_cb: Err aborts the transfer. nothing is checked
	// while the last response code is a redirect or an error
	fn progress(
		&self,
		job: &Job,
		respcode: i64,
		dlnow: i64,
		dltotal: i64,
	) -> Result<(), Fail> {
		if respcode >= 300 {
			return Ok(());
		}
		if self.interrupted.load(Ordering::SeqCst) {
			return Err((
				Code::Aborted,
				b"Callback aborted".to_vec(),
			));
		}
		if dlnow < 0 || dltotal <= 0 || dlnow > dltotal {
			return Ok(());
		}
		if job.max_size != 0 && job.initial_size + dlnow > job.max_size
		{
			self.interrupted.store(true, Ordering::SeqCst);
			return Err((
				Code::Aborted,
				b"Callback aborted".to_vec(),
			));
		}
		let msg = Msg::Progress {
			slot: job.slot,
			dlnow,
			dltotal,
		};
		let _ = self.tx.send(msg);
		Ok(())
	}

	// curl's body write: CURLOPT_MAXFILESIZE stops a body that gets past
	// it (sizes unknown up front: chunked, file://)
	fn write_body(
		&self,
		job: &mut Job,
		xfer: &mut Transfer,
		chunk: &[u8],
		dltotal: i64,
	) -> Result<(), Fail> {
		let mut take = chunk.len();
		let over = job.max_size > 0
			&& xfer.bytes_dl + chunk.len() as i64 > job.max_size;
		if over {
			take = (job.max_size - xfer.bytes_dl) as usize;
		}
		if job.file.write_all(&chunk[..take]).is_err() {
			return Err(failed(
				"Failure writing output to destination",
			));
		}
		xfer.bytes_dl += take as i64;
		if over {
			return Err(failed(format!(
				"Exceeded the maximum allowed file size ({}) with {} bytes",
				job.max_size, xfer.bytes_dl
			)));
		}
		self.progress(job, xfer.respcode, xfer.bytes_dl, dltotal)
	}

	// the request curl_set_handle_opts describes
	fn request(&self, job: &Job, url: &Url) -> RequestBuilder {
		let mut req = self.client.get(url.clone());
		if job.resume_from > 0 {
			let range = format!("bytes={}-", job.resume_from);
			req = req.header(header::RANGE, range);
		}
		if let Some(t) = job.time_cond {
			req = req.header(
				header::IF_MODIFIED_SINCE,
				http_date(t),
			);
		}
		if let Some(ua) = &job.user_agent
			&& let Ok(v) = header::HeaderValue::from_bytes(ua)
		{
			req = req.header(header::USER_AGENT, v);
		}
		req
	}

	fn http(&self, job: &mut Job, xfer: &mut Transfer) -> Result<(), Fail> {
		self.progress(job, xfer.respcode, 0, 0)?;
		let bad = "URL rejected: Malformed input to a URL function";
		let s = std::str::from_utf8(&job.url)
			.map_err(|_| failed(bad))?;
		let url = Url::parse(s).map_err(|_| failed(bad))?;
		if !matches!(url.scheme(), "http" | "https") {
			let m = format!(
				"Protocol \"{}\" not supported",
				url.scheme()
			);
			return Err(failed(m));
		}
		// resolved first: reqwest's errors do not tell dns from connect
		let host = url.host_str().unwrap_or_default().to_string();
		let port = url.port_or_known_default().unwrap_or(80);
		if (host.as_str(), port).to_socket_addrs().is_err() {
			let m = format!("Could not resolve host: {host}");
			return Err((Code::Resolve, m.into_bytes()));
		}
		let start = Instant::now();
		let resp = self.request(job, &url).send();
		let resp = resp.map_err(|e| send_error(&e, &url, start))?;
		let status = i64::from(resp.status().as_u16());
		xfer.respcode = status;
		if resp.url() != &url {
			xfer.effective_url =
				resp.url().as_str().as_bytes().to_vec();
		}
		// Last-Modified is only read from 2xx responses
		let mut timeofdoc = 0;
		if (200..300).contains(&status)
			&& let Some(v) =
				header_bytes(&resp, header::LAST_MODIFIED)
		{
			timeofdoc = parse_http_date(v).unwrap_or(-1);
			xfer.filetime = timeofdoc;
		}
		if status == 304 {
			xfer.timecond = job.time_cond.is_some();
			return Ok(());
		}
		let chunked = header_bytes(&resp, header::TRANSFER_ENCODING)
			.is_some_and(|v| find_sub(v, b"chunked").is_some());
		let length = header_bytes(&resp, header::CONTENT_LENGTH)
			.and_then(|v| {
				std::str::from_utf8(v).ok()?.trim().parse().ok()
			});
		let size: i64 = if chunked { -1 } else { length.unwrap_or(-1) };
		if job.max_size > 0 && size > job.max_size {
			return Err(failed("Maximum file size exceeded"));
		}
		xfer.remote_size = size;
		// a resumed GET needs its offset back in Content-Range; "*/size"
		// (or no number) on a 2xx gets everything instead
		let mut resume_from = job.resume_from;
		let mut range_ok = false;
		if let Some(v) = header_bytes(&resp, header::CONTENT_RANGE) {
			match content_range_offset(v) {
				Some(off) => {
					range_ok = off == Some(resume_from)
				}
				None if status < 300 => resume_from = 0,
				None => {}
			}
		}
		// 416 on a resumed GET is no error to curl, its body is ignored
		if status == 416 && resume_from > 0 {
			return Ok(());
		}
		// curl_http_firstwrite
		if resume_from > 0 && !range_ok {
			if size == resume_from {
				// already downloaded, curl's final progress update
				return self.progress(job, status, 0, size);
			}
			return Err(failed(
				"HTTP server does not seem to support byte ranges. \
				 Cannot resume.",
			));
		}
		if let Some(t) = job.time_cond
			&& resume_from == 0 && !meets_timecondition(timeofdoc, t)
		{
			xfer.timecond = true;
			return Ok(());
		}
		self.http_body(job, xfer, resp, size)
	}

	// the body, size -1 when unknown
	fn http_body(
		&self,
		job: &mut Job,
		xfer: &mut Transfer,
		mut resp: Response,
		size: i64,
	) -> Result<(), Fail> {
		let dltotal = size.max(0);
		let mut buf = vec![0; 64 * 1024];
		loop {
			let n = match resp.read(&mut buf) {
				Ok(0) => break,
				Ok(n) => n,
				Err(e) if is_timeout(&e) => {
					return Err(failed(TOO_SLOW));
				}
				Err(_) if size < 0 => {
					return Err(failed(
						"transfer closed with outstanding read data \
						 remaining",
					));
				}
				Err(_) => break,
			};
			self.write_body(job, xfer, &buf[..n], dltotal)?;
		}
		if size >= 0 && xfer.bytes_dl < size {
			let left = size - xfer.bytes_dl;
			return Err(failed(format!(
				"end of response with {left} bytes missing"
			)));
		}
		Ok(())
	}

	// curl's file.c: the size reported is the whole file until a resume
	// leaves something to read, the progress callback runs once more at
	// the end (failures included), the response code becomes 0
	fn file(&self, job: &mut Job, xfer: &mut Transfer) -> Result<(), Fail> {
		self.progress(job, xfer.respcode, 0, 0)?;
		let Some(p) = file_url_path(&job.url) else {
			return Err(failed(
				"URL using bad/illegal format or missing URL",
			));
		};
		let open = File::open(path(&p));
		let Ok(mut src) = open else {
			return Err(failed(cat(&[
				b"Could not open file ",
				&p,
			])));
		};
		let Ok(md) = src.metadata() else {
			return Err(failed(cat(&[
				b"Could not open file ",
				&p,
			])));
		};
		xfer.filetime = md.mtime();
		let mut dltotal = 0;
		let r = self.file_body(
			job,
			xfer,
			&mut src,
			md.len(),
			&mut dltotal,
		);
		let last = self.progress(
			job,
			xfer.respcode,
			xfer.bytes_dl,
			dltotal,
		);
		r.and(last)
	}

	fn file_body(
		&self,
		job: &mut Job,
		xfer: &mut Transfer,
		src: &mut File,
		size: u64,
		dltotal: &mut i64,
	) -> Result<(), Fail> {
		// a resume offset is a range: no time condition then
		if let Some(t) = job.time_cond
			&& job.resume_from == 0
			&& !meets_timecondition(xfer.filetime, t)
		{
			xfer.timecond = true;
			return Ok(());
		}
		xfer.respcode = 0;
		let size = size as i64;
		*dltotal = size;
		xfer.remote_size = size;
		if job.resume_from > size {
			return Err(failed(
				"failed to resume file:// transfer",
			));
		}
		let expected = size - job.resume_from.max(0);
		if expected > 0 {
			*dltotal = expected;
			xfer.remote_size = expected;
		}
		// the .part is open at its end: appending, emptied or new
		let skip = job.resume_from.max(0) as u64;
		let bad = "Could not seek stream";
		src.seek(SeekFrom::Start(skip)).map_err(|_| failed(bad))?;
		let mut buf = vec![0; 64 * 1024];
		loop {
			let n = match src.read(&mut buf) {
				Ok(0) => break,
				Ok(n) => n,
				Err(_) => {
					return Err(failed(
						"Failed to read the file",
					));
				}
			};
			self.write_body(job, xfer, &buf[..n], *dltotal)?;
		}
		Ok(())
	}
}

fn build_client(settings: &Settings) -> reqwest::Result<Client> {
	let timeout = (!settings.disable_dl_timeout).then_some(LOW_SPEED_TIME);
	Client::builder()
		.timeout(timeout)
		.connect_timeout(CONNECT_TIMEOUT)
		.redirect(Policy::limited(MAX_REDIRS))
		.referer(false)
		.tcp_keepalive(KEEPALIVE)
		.tcp_keepalive_interval(KEEPALIVE)
		.build()
}

// curl_download_internal and its callbacks: up to parallel_downloads
// streams, payloads started largest max_size first
struct Engine<'a> {
	state: &'a mut DownloadState,
	cb: &'a mut dyn Callbacks,
	dbext: &'a [u8],
	errno: Errno,
	// .sig payloads made along the way, slots after the caller's
	sigs: Vec<Payload>,
	worker: Worker,
	rx: Receiver<Msg>,
}

fn slot_mut<'p>(
	payloads: &'p mut [Payload],
	sigs: &'p mut [Payload],
	slot: usize,
) -> &'p mut Payload {
	match slot.checked_sub(payloads.len()) {
		None => &mut payloads[slot],
		Some(i) => &mut sigs[i],
	}
}

// what fstat shows of a FILE that was written bytes_dl bytes since
// start_len: glibc buffers min(st_blksize, BUFSIZ) bytes and flushes
// whole buffers
fn fstat_size(file: &File, xfer: &Transfer) -> i64 {
	let blk = file.metadata().map_or(0, |m| m.blksize() as i64);
	let blk = if (1..8192).contains(&blk) { blk } else { 8192 };
	xfer.start_len + xfer.bytes_dl / blk * blk
}

fn open_tempfile(p: &Payload) -> io::Result<File> {
	OpenOptions::new()
		.write(true)
		.create(true)
		.truncate(!p.append)
		.append(p.append)
		.open(path(&p.tempfile_name))
}

// "failed retrieving file" with the curl error or libalpm's reason
fn log_failed(cb: &mut dyn Callbacks, name: &[u8], host: &[u8], why: &[u8]) {
	let m = cat(&[
		b"failed retrieving file '",
		name,
		b"' from ",
		host,
		b" : ",
		why,
		b"\n",
	]);
	cb.log(LogLevel::Error, &m);
}

impl Engine<'_> {
	fn job(p: &mut Payload, slot: usize, file: File) -> Job {
		Job {
			slot,
			url: p.url.clone().unwrap_or_default(),
			resume_from: p.resume_from,
			time_cond: p.time_cond.then_some(p.mtime_existing_file),
			respcode: p.respcode,
			initial_size: p.initial_size,
			max_size: p.max_size,
			user_agent: std::env::var_os("HTTP_USER_AGENT")
				.map(|v| v.as_bytes().to_vec()),
			file,
		}
	}

	// curl_add_payload: Ok(true) started, Ok(false) the .part is already
	// complete (not started, not renamed), Err(()) failed to set up
	fn add_payload(
		&mut self,
		payloads: &mut [Payload],
		slot: usize,
	) -> Result<bool, ()> {
		let p = slot_mut(payloads, &mut self.sigs, slot);
		let url = match &p.fileurl {
			Some(u) => {
				if !p.servers.is_empty() || p.filepath.is_some()
				{
					self.errno = Errno::WrongArgs;
					return Err(());
				}
				p.request_errors_ok = p.errors_ok;
				u.clone()
			}
			None => {
				let Some(server) = next_server(self.state, p)
				else {
					self.errno = Errno::ServerNone;
					return Err(());
				};
				let Some(fp) = &p.filepath else {
					self.errno = Errno::WrongArgs;
					return Err(());
				};
				cat(&[&server, b"/", fp])
			}
		};
		p.url = Some(url.clone());
		p.append = false;
		if gethost(&url).is_none() {
			let m = cat(&[b"url '", &url, b"' is invalid\n"]);
			self.cb.log(LogLevel::Error, &m);
			self.errno = Errno::ServerBadUrl;
			return Err(());
		}
		// curl_set_handle_opts after curl_easy_reset
		p.resume_from = 0;
		p.time_cond = false;
		let part = fs::metadata(path(&p.tempfile_name));
		if !p.force && p.mtime_existing_file != 0 {
			p.time_cond = true;
		} else if let Ok(md) = part
			&& p.allow_resume
		{
			p.append = true;
			p.resume_from = md.len() as i64;
			p.initial_size = md.len() as i64;
		}
		if p.max_size == p.initial_size && p.max_size != 0 {
			return Ok(false);
		}
		let file = match p.localf.take() {
			Some(f) => f,
			None => match open_tempfile(p) {
				Ok(f) => f,
				Err(e) => {
					let m = cat(&[
						b"could not open file ",
						&p.tempfile_name,
						b": ",
						&strerror(&e),
						b"\n",
					]);
					self.cb.log(LogLevel::Error, &m);
					self.errno = Errno::Retrieve;
					return Err(());
				}
			},
		};
		self.worker.spawn(Self::job(p, slot, file));
		let init = DownloadEvent::Init {
			optional: p.errors_ok,
		};
		self.cb.download(&p.remote_name, init);
		Ok(true)
	}

	// the dlcb half of dload_progress_cb
	fn progress(
		&mut self,
		payloads: &mut [Payload],
		slot: usize,
		dlnow: i64,
		dltotal: i64,
	) {
		let p = slot_mut(payloads, &mut self.sigs, slot);
		if p.prevprogress == p.initial_size + dltotal {
			return;
		}
		let ev = DownloadEvent::Progress {
			downloaded: dlnow,
			total: dltotal,
		};
		self.cb.download(&p.remote_name, ev);
		p.prevprogress = p.initial_size + dlnow;
	}

	// curl_retry_next_server: Ok(true) restarted on the next server,
	// Ok(false) none left, Err(()) the .part could not be emptied
	fn retry_next_server(
		&mut self,
		payloads: &mut [Payload],
		slot: usize,
		mut file: File,
	) -> Result<bool, ()> {
		let p = slot_mut(payloads, &mut self.sigs, slot);
		let Some(server) = next_server(self.state, p) else {
			p.localf = Some(file);
			return Ok(false);
		};
		let fp = p.filepath.clone().unwrap_or_default();
		p.url = Some(cat(&[&server, b"/", &fp]));
		let part = fs::metadata(path(&p.tempfile_name));
		if let Ok(md) = part
			&& p.allow_resume
		{
			p.append = true;
			p.resume_from = md.len() as i64;
			p.initial_size = md.len() as i64;
		} else {
			// the file stays for the retry, its data goes
			if file.set_len(0).is_err() {
				p.localf = Some(file);
				self.errno = Errno::System;
				return Err(());
			}
			let _ = file.seek(SeekFrom::Start(0));
		}
		let ev = DownloadEvent::Retry {
			resume: p.allow_resume,
		};
		self.cb.download(&p.remote_name, ev);
		self.worker.spawn(Self::job(p, slot, file));
		Ok(true)
	}

	// the .sig payload of a finished download, started right away
	fn add_signature(
		&mut self,
		payloads: &mut [Payload],
		slot: usize,
		effective_url: &[u8],
	) -> usize {
		let p = slot_mut(payloads, &mut self.sigs, slot);
		// alpm_option_get_dbext's CHECK_HANDLE resets pm_errno
		self.errno = Errno::Ok;
		let eff = basename(effective_url);
		let eff = match eff.iter().rposition(|&c| c == b'?') {
			Some(q) => &eff[..q],
			None => eff,
		};
		let fileurl = p.url.clone().unwrap_or_default();
		let use_effective = find_sub(eff, self.dbext).is_some()
			|| find_sub(eff, b".pkg").is_some();
		let url = if use_effective {
			effective_url
		} else {
			&fileurl
		};
		let realname =
			p.destfile_name.as_ref().unwrap_or(&p.tempfile_name);
		let sig = Payload {
			fileurl: Some(cat(&[url, b".sig"])),
			remote_name: cat(&[&p.remote_name, b".sig"]),
			destfile_name: Some(cat(&[realname, b".sig"])),
			tempfile_name: cat(&[realname, b".sig.part"]),
			signature: true,
			force: p.force,
			unlink_on_fail: p.unlink_on_fail,
			errors_ok: p.signature_optional,
			max_size: SIG_MAX_SIZE,
			..Payload::default()
		};
		self.sigs.push(sig);
		let s = payloads.len() + self.sigs.len() - 1;
		// a .sig that fails to start is dropped, the result stays
		usize::from(self.add_payload(payloads, s) == Ok(true))
	}

	// a failed transfer moves to the next server: None when it did,
	// else the file back for cleanup
	fn retry_or_keep(
		&mut self,
		payloads: &mut [Payload],
		slot: usize,
		file: File,
	) -> Option<File> {
		match self.retry_next_server(payloads, slot, file) {
			Ok(true) => None,
			_ => slot_mut(payloads, &mut self.sigs, slot)
				.localf
				.take(),
		}
	}

	// the rest of a transfer curl reports as done (CURLE_OK, code < 400):
	// the .sig payload, the time condition, the truncation check. the
	// result and the streams it started
	fn finish_ok(
		&mut self,
		payloads: &mut [Payload],
		slot: usize,
		xfer: &Transfer,
	) -> (c_int, usize) {
		let mut started = 0;
		let p = slot_mut(payloads, &mut self.sigs, slot);
		if !p.signature && p.download_signature {
			started = self.add_signature(
				payloads,
				slot,
				&xfer.effective_url,
			);
		}
		let p = slot_mut(payloads, &mut self.sigs, slot);
		if xfer.timecond && xfer.bytes_dl == 0 {
			// nothing came: the empty .part goes
			let _ = fs::remove_file(path(&p.tempfile_name));
			return (1, started);
		}
		if xfer.remote_size != -1 && xfer.bytes_dl != xfer.remote_size {
			let m = format!(
				" appears to be truncated: {}/{} bytes\n",
				xfer.bytes_dl, xfer.remote_size
			);
			let m = cat(&[&p.remote_name, m.as_bytes()]);
			self.cb.log(LogLevel::Error, &m);
			self.errno = Errno::Retrieve;
			return (-1, started);
		}
		(0, started)
	}

	// the cleanup label of curl_check_finished_download
	fn cleanup(
		&mut self,
		payloads: &mut [Payload],
		slot: usize,
		file: File,
		mut ret: c_int,
		xfer: Option<&Transfer>,
	) -> c_int {
		let p = slot_mut(payloads, &mut self.sigs, slot);
		drop(file);
		// CURLINFO_FILETIME and SIZE_DOWNLOAD are only read on success
		utimes_long(&p.tempfile_name, xfer.map_or(-1, |x| x.filetime));
		if ret == 0
			&& let Some(dest) = &p.destfile_name
			&& let Err(e) =
				fs::rename(path(&p.tempfile_name), path(dest))
		{
			let m = cat(&[
				b"could not rename ",
				&p.tempfile_name,
				b" to ",
				dest,
				b" (",
				&strerror(&e),
				b")\n",
			]);
			self.cb.log(LogLevel::Error, &m);
			ret = -1;
		}
		let interrupted =
			self.worker.interrupted.load(Ordering::SeqCst);
		if (ret == -1 || interrupted) && p.unlink_on_fail {
			let _ = fs::remove_file(path(&p.tempfile_name));
		}
		let done = DownloadEvent::Completed {
			total: xfer.map_or(0, |x| x.bytes_dl),
			result: ret,
		};
		self.cb.download(&p.remote_name, done);
		p.url = None;
		if ret == -1 && p.errors_ok {
			ret = -2;
		}
		ret
	}

	// curl_check_finished_download: 2 retried, 1 up to date, 0 done, -1
	// failed, -2 failed but optional; plus the streams it started
	fn check_finished(
		&mut self,
		payloads: &mut [Payload],
		slot: usize,
		mut file: File,
		xfer: Transfer,
	) -> (c_int, usize) {
		let p = slot_mut(payloads, &mut self.sigs, slot);
		p.respcode = xfer.respcode;
		let url = p.url.clone().unwrap_or_default();
		// empty for a url without a host
		let host = gethost(&url).unwrap_or_default();
		let name = p.remote_name.clone();
		let report = !p.request_errors_ok;
		match xfer.code {
			Code::Ok if p.respcode >= 400 => {
				if report {
					self.errno = Errno::Retrieve;
					let why = format!(
						"The requested URL returned error: {}",
						p.respcode
					);
					log_failed(
						self.cb,
						&name,
						&host,
						why.as_bytes(),
					);
					self.state.soft_error(&url, self.cb);
				}
				// an html error page was written to the file
				let initial = p.initial_size as u64;
				let size = file
					.metadata()
					.map_or(initial, |m| m.len());
				if size != initial
					&& file.set_len(initial).is_err()
				{
					let p = slot_mut(
						payloads,
						&mut self.sigs,
						slot,
					);
					p.localf = Some(file);
					self.errno = Errno::System;
					return (-1, 0);
				}
				let _ = file.seek(SeekFrom::Start(initial));
				let Some(file) = self
					.retry_or_keep(payloads, slot, file)
				else {
					return (2, 1);
				};
				slot_mut(payloads, &mut self.sigs, slot)
					.unlink_on_fail = true;
				(
					self.cleanup(
						payloads, slot, file, -1, None,
					),
					0,
				)
			}
			Code::Ok => {
				let (ret, started) =
					self.finish_ok(payloads, slot, &xfer);
				(
					self.cleanup(
						payloads,
						slot,
						file,
						ret,
						Some(&xfer),
					),
					started,
				)
			}
			Code::Aborted => {
				if self.worker
					.interrupted
					.load(Ordering::SeqCst)
				{
					p.unlink_on_fail = true;
					self.errno = Errno::Libcurl;
					let why = b"expected download size exceeded";
					log_failed(self.cb, &name, &host, why);
					self.state.soft_error(&url, self.cb);
				}
				(
					self.cleanup(
						payloads, slot, file, -1, None,
					),
					0,
				)
			}
			Code::Resolve => {
				self.errno = Errno::ServerBadUrl;
				log_failed(self.cb, &name, &host, &xfer.error);
				self.state.hard_error(&url, self.cb);
				let Some(file) = self
					.retry_or_keep(payloads, slot, file)
				else {
					return (2, 1);
				};
				(
					self.cleanup(
						payloads, slot, file, -1, None,
					),
					0,
				)
			}
			Code::Failed => {
				if report {
					self.errno = Errno::Libcurl;
					log_failed(
						self.cb,
						&name,
						&host,
						&xfer.error,
					);
					self.state.soft_error(&url, self.cb);
				}
				let Some(f) = self
					.retry_or_keep(payloads, slot, file)
				else {
					return (2, 1);
				};
				file = f;
				// delete zero length downloads. the C fstats its FILE
				// before fclose: what this attempt left in the stdio
				// buffer does not count
				if fstat_size(&file, &xfer) == 0 {
					let p = slot_mut(
						payloads,
						&mut self.sigs,
						slot,
					);
					p.unlink_on_fail = true;
				}
				(
					self.cleanup(
						payloads, slot, file, -1, None,
					),
					0,
				)
			}
		}
	}

	fn run(
		&mut self,
		payloads: &mut [Payload],
		max_streams: u32,
	) -> Result<bool, Errno> {
		let n = payloads.len();
		let mut order: Vec<usize> = (0..n).collect();
		// compare_dload_payload_sizes under a stable msort
		order.sort_by(|&a, &b| {
			payloads[b].max_size.cmp(&payloads[a].max_size)
		});
		let max = max_streams.max(1) as usize;
		let (mut next, mut active) = (0, 0);
		let (mut err, mut updated) = (false, false);
		while active > 0 || next < n {
			while active < max && next < n {
				let slot = order[next];
				match self.add_payload(payloads, slot) {
					Ok(started) => {
						next += 1;
						active += usize::from(started);
					}
					Err(()) => {
						// no new downloads, wait for the running ones
						let m = cat(&[
							b"failed to setup a download payload for ",
							&payloads[slot].remote_name,
							b"\n",
						]);
						self.cb.log(
							LogLevel::Error,
							&m,
						);
						next = n;
						err = true;
					}
				}
			}
			if active == 0 {
				continue;
			}
			let msg =
				self.rx.recv()
					.expect("a running transfer reports");
			match msg {
				Msg::Progress {
					slot,
					dlnow,
					dltotal,
				} => self.progress(
					payloads, slot, dlnow, dltotal,
				),
				Msg::Done { slot, file, xfer } => {
					active -= 1;
					let (ret, more) = self.check_finished(
						payloads, slot, file, xfer,
					);
					active += more;
					match ret {
						-1 => {
							next = n;
							err = true;
						}
						0 => updated = true,
						_ => {}
					}
				}
			}
		}
		if err { Err(self.errno) } else { Ok(updated) }
	}
}

// curl_download_internal: Ok(true) something was downloaded, Ok(false)
// nothing was and every error was optional, Err a required file failed
pub fn download_internal(
	settings: &Settings,
	state: &mut DownloadState,
	cb: &mut dyn Callbacks,
	payloads: &mut [Payload],
) -> Result<bool, Errno> {
	let Ok(client) = build_client(settings) else {
		return Err(Errno::Libcurl);
	};
	let (tx, rx) = mpsc::channel();
	let interrupted = Arc::new(AtomicBool::new(state.interrupted));
	let worker = Worker {
		client,
		tx,
		interrupted: interrupted.clone(),
	};
	let mut engine = Engine {
		state,
		cb,
		dbext: &settings.dbext,
		errno: Errno::Ok,
		sigs: Vec::new(),
		worker,
		rx,
	};
	let r = engine.run(payloads, settings.parallel_downloads);
	engine.state.interrupted = interrupted.load(Ordering::SeqCst);
	r
}

// finalize_download_file: an empty file is removed (1), others go to
// root:root (the sandbox only runs as root) with mode 0666 under the umask
fn finalize_download_file(file: &[u8]) -> io::Result<c_int> {
	let md = fs::metadata(path(file))?;
	if md.len() == 0 {
		let _ = fs::remove_file(path(file));
		return Ok(1);
	}
	chown(path(file), Some(0), Some(0))?;
	let mode = !current_umask() & 0o666;
	fs::set_permissions(path(file), fs::Permissions::from_mode(mode))?;
	Ok(0)
}

// move_file: finalized, then renamed into directory
fn move_file(file: &[u8], directory: &[u8]) -> io::Result<c_int> {
	let ret = finalize_download_file(file)?;
	if ret != 0 {
		return Ok(ret);
	}
	let dest = get_fullpath(directory, basename(file), b"");
	fs::rename(path(file), path(&dest))?;
	Ok(0)
}

// finalize_download_locations: sandboxed downloads (and .sig or .sig.part
// files) moved from the temporary dir into localpath. -1 when a file
// that did not exist before could not be moved
fn finalize_download_locations(
	payloads: &[Payload],
	localpath: &[u8],
	cb: &mut dyn Callbacks,
) -> c_int {
	let mut ret = 0;
	for p in payloads {
		let exists = |f: &[u8]| fs::metadata(path(f)).is_ok();
		let file = match &p.destfile_name {
			Some(d) if exists(d) => Some(d),
			_ if exists(&p.tempfile_name) => Some(&p.tempfile_name),
			_ => None,
		};
		if let Some(f) = file
			&& let Err(e) = move_file(f, localpath)
			&& p.mtime_existing_file == 0
		{
			let m = cat(&[
				b"could not move ",
				f,
				b" into ",
				localpath,
				b" (",
				&strerror(&e),
				b")\n",
			]);
			cb.log(LogLevel::Error, &m);
			ret = -1;
		}
		if p.download_signature {
			let f = p
				.destfile_name
				.as_ref()
				.unwrap_or(&p.tempfile_name);
			let sig = get_fullpath(b"", f, b".sig");
			if move_file(&sig, localpath).is_err() {
				let part = get_fullpath(b"", f, b".sig.part");
				let _ = move_file(&part, localpath);
			}
		}
	}
	ret
}

// one Downloader per libalpm call: the handle's download state, options
// and callbacks
pub struct Downloader<'a> {
	pub settings: &'a Settings,
	pub state: &'a mut DownloadState,
	pub cb: &'a mut dyn Callbacks,
	pub fetch: Option<&'a mut dyn Fetch>,
	pub sandbox: Option<&'a mut dyn Sandbox>,
}

impl Downloader<'_> {
	// prepare_resumable_downloads: the destination's mtime for the time
	// condition; with the sandbox, .part files move from localpath into
	// the temporary dir and go to the sandbox user
	fn prepare_resumable_downloads(
		&mut self,
		payloads: &mut [Payload],
		localpath: &[u8],
	) {
		let mut ids = None;
		if let Some(sb) = &self.sandbox {
			match sb.lookup() {
				Ok(id) => ids = Some(id),
				Err(_) => return,
			}
		}
		for p in payloads.iter_mut() {
			if let Some(d) = &p.destfile_name {
				let dest = get_fullpath(
					localpath,
					basename(d),
					b"",
				);
				if let Ok(md) = fs::metadata(path(&dest))
					&& md.len() != 0
				{
					p.mtime_existing_file = md.mtime();
				}
			}
			let Some((uid, gid)) = ids else {
				continue;
			};
			let src = get_fullpath(
				localpath,
				basename(&p.tempfile_name),
				b"",
			);
			if !fs::metadata(path(&src)).is_ok_and(|m| m.len() != 0)
			{
				continue;
			}
			if fs::rename(path(&src), path(&p.tempfile_name))
				.is_err()
			{
				continue;
			}
			// returns after the first chowned .part, like the C
			if chown(path(&p.tempfile_name), Some(uid), Some(gid))
				.is_ok()
			{
				return;
			}
		}
	}

	// the fetchcb path of _alpm_download: each payload in order, cache
	// servers then servers until one gives 0 or 1, then its .sig
	fn download_fetchcb(
		fetch: &mut dyn Fetch,
		payloads: &[Payload],
		tmp: &[u8],
	) -> Result<bool, Errno> {
		let mut updated = false;
		for p in payloads {
			let mut ret = -1;
			if let Some(url) = &p.fileurl {
				ret = fetch.fetch(url, tmp, p.force);
				if ret != -1 && p.download_signature {
					let sig = cat(&[url, b".sig"]);
					let retsig =
						fetch.fetch(&sig, tmp, p.force);
					if !p.signature_optional {
						ret = retsig;
					}
				}
			} else {
				let fp = p.filepath.clone().unwrap_or_default();
				let mut used = None;
				for s in
					p.cache_servers.iter().chain(&p.servers)
				{
					ret = fetch.fetch(
						&cat(&[s, b"/", &fp]),
						tmp,
						p.force,
					);
					if ret != -1 {
						used = Some(s);
						break;
					}
				}
				if let Some(s) = used
					&& p.download_signature
				{
					let sig = cat(&[s, b"/", &fp, b".sig"]);
					let retsig =
						fetch.fetch(&sig, tmp, p.force);
					if !p.signature_optional {
						ret = retsig;
					}
				}
			}
			if ret == -1 && !p.errors_ok {
				return Err(Errno::ExternalDownload);
			} else if ret == 0 {
				updated = true;
			}
		}
		Ok(updated)
	}

	// _alpm_download: Ok(true) something was downloaded, Ok(false)
	// nothing was and every error was optional, Err a required file
	// failed. downloads go to temporary_localpath (localpath without the
	// sandbox), sandboxed ones are moved into localpath after
	pub fn download(
		&mut self,
		payloads: &mut [Payload],
		localpath: &[u8],
		temporary_localpath: &[u8],
	) -> Result<bool, Errno> {
		self.prepare_resumable_downloads(payloads, localpath);
		let mut childsig = 0;
		let ret = match (&mut self.fetch, &mut self.sandbox) {
			(Some(f), _) => Self::download_fetchcb(
				&mut **f,
				payloads,
				temporary_localpath,
			),
			(None, Some(sb)) => {
				let (r, sig) = sb.download(
					self.settings,
					self.state,
					self.cb,
					payloads,
					temporary_localpath,
				);
				childsig = sig;
				r
			}
			(None, None) => download_internal(
				self.settings,
				self.state,
				self.cb,
				payloads,
			),
		};
		// the fetchcb path returns its error before finalizing, like the C
		if self.fetch.is_some() && ret.is_err() {
			return ret;
		}
		let mut finalize_ret = 0;
		if self.sandbox.is_some() {
			finalize_ret = finalize_download_locations(
				payloads, localpath, self.cb,
			);
			remove_temporary_download_dir(temporary_localpath);
		}
		if childsig != 0
			&& let Some(sb) = &mut self.sandbox
		{
			sb.raise(childsig);
		}
		if finalize_ret != 0 && ret == Ok(true) {
			return Err(Errno::Retrieve);
		}
		ret
	}

	// _alpm_download_dir_setup: dir itself, or with the sandbox a new
	// "<dir>download-XXXXXX/" owned by the sandbox user
	pub fn download_dir_setup(
		&mut self,
		dir: &[u8],
	) -> Result<Vec<u8>, Errno> {
		let Some(sb) = &self.sandbox else {
			return Ok(until_nul(dir).to_vec());
		};
		let (uid, gid) = match sb.lookup() {
			Ok(id) => id,
			Err(e) => {
				let user = sb.user();
				let m = match e {
					None => cat(&[
						b"download user '",
						user,
						b"' does not exist\n",
					]),
					Some(e) => cat(&[
						b"failed to get download user '",
						user,
						b"': ",
						&strerror(&e),
						b"\n",
					]),
				};
				self.cb.log(LogLevel::Error, &m);
				return Err(Errno::RetrievePrepare);
			}
		};
		let (mut newdir, made) =
			mkdtemp(&cat(&[until_nul(dir), b"download-"]));
		if let Err(e) = made {
			let m = cat(&[
				b"failed to create temporary download directory ",
				&newdir,
				b": ",
				&strerror(&e),
				b"\n",
			]);
			self.cb.log(LogLevel::Error, &m);
			return Err(Errno::RetrievePrepare);
		}
		if let Err(e) = chown(path(&newdir), Some(uid), Some(gid)) {
			let m = cat(&[
				b"failed to chown temporary download directory ",
				&newdir,
				b": ",
				&strerror(&e),
				b"\n",
			]);
			self.cb.log(LogLevel::Error, &m);
			return Err(Errno::RetrievePrepare);
		}
		newdir.push(b'/');
		Ok(newdir)
	}

	// alpm_fetch_pkgurl: the local path of every url, cached files as they
	// are (with their .sig when siglevel wants package signatures), the
	// rest downloaded into the first usable cachedir. siglevel is the
	// remote file siglevel
	pub fn fetch_pkgurl<U: AsRef<[u8]>>(
		&mut self,
		cachedirs: &mut Vec<Vec<u8>>,
		siglevel: c_int,
		urls: &[U],
	) -> Result<Vec<Vec<u8>>, Errno> {
		let cachedir = filecache_setup(cachedirs, self.cb);
		let tmp = self.download_dir_setup(&cachedir)?;
		let mut fetched = Vec::new();
		let mut payloads = Vec::new();
		for url in urls {
			let url = until_nul(url.as_ref());
			let base = url_basename(url);
			let mut found = base.and_then(|b| {
				filecache_find(cachedirs, b, self.cb)
			});
			if found.is_some() && siglevel & SIG_PACKAGE != 0 {
				let sig = get_fullpath(
					b"",
					base.unwrap_or_default(),
					b".sig",
				);
				// no .sig: forget the package file, download both
				if !filecache_exists(cachedirs, &sig, self.cb) {
					found = None;
				}
			}
			if let Some(f) = found {
				fetched.push(f);
				continue;
			}
			let mut p = Payload {
				fileurl: Some(url.to_vec()),
				remote_name: basename(url).to_vec(),
				..Payload::default()
			};
			let slash = url.iter().rposition(|&c| c == b'/');
			let pkg = slash.is_some_and(|i| {
				find_sub(&url[i..], b".pkg").is_some()
			});
			if pkg && !p.remote_name.is_empty() {
				// a usable package filename to download to
				p.destfile_name = Some(get_fullpath(
					&tmp,
					&p.remote_name,
					b"",
				));
				p.tempfile_name = get_fullpath(
					&tmp,
					&p.remote_name,
					b".part",
				);
				p.allow_resume = true;
			} else {
				// no filename: a temporary file, no resume
				p.unlink_on_fail = true;
				if !create_tempfile(&mut p, &tmp, self.cb) {
					// pm_errno as CHECK_HANDLE left it
					return Err(Errno::Ok);
				}
			}
			p.download_signature = siglevel & SIG_PACKAGE != 0;
			p.signature_optional =
				siglevel & SIG_PACKAGE_OPTIONAL != 0;
			payloads.push(p);
		}
		if payloads.is_empty() {
			return Ok(fetched);
		}
		let (num, total_size) = (payloads.len(), 0);
		self.cb.event(&Event::PkgRetrieveStart { num, total_size });
		if self.download(&mut payloads, &cachedir, &tmp).is_err() {
			let m = b"failed to retrieve some files\n";
			self.cb.log(LogLevel::Warning, m);
			self.cb.event(&Event::PkgRetrieveFailed {
				num,
				total_size,
			});
			return Err(Errno::Retrieve);
		}
		self.cb.event(&Event::PkgRetrieveDone { num, total_size });
		for p in &payloads {
			let name = p
				.destfile_name
				.as_ref()
				.unwrap_or(&p.tempfile_name);
			match filecache_find(cachedirs, basename(name), self.cb)
			{
				Some(f) => fetched.push(f),
				None => {
					let m = b"download completed successfully but no file \
						in the cache\n";
					self.cb.log(LogLevel::Warning, m);
					return Err(Errno::Retrieve);
				}
			}
		}
		Ok(fetched)
	}
}

// url_basename: after the last '/', None without one or when empty
fn url_basename(url: &[u8]) -> Option<&[u8]> {
	let i = url.iter().rposition(|&c| c == b'/')?;
	Some(&url[i + 1..]).filter(|b| !b.is_empty())
}

// _alpm_remove_temporary_download_dir: its files unlinked (names too long
// for PATH_MAX skipped), then rmdir
pub fn remove_temporary_download_dir(dir: &[u8]) {
	let dir = until_nul(dir);
	let Ok(entries) = fs::read_dir(path(dir)) else {
		return;
	};
	for e in entries.flatten() {
		let name = e.file_name();
		if dir.len() + name.len() + 2 > PATH_MAX {
			continue;
		}
		let _ = fs::remove_file(path(&cat(&[
			dir,
			b"/",
			name.as_bytes(),
		])));
	}
	let _ = fs::remove_dir(path(dir));
}
