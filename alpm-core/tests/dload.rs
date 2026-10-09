// alpm_core::dload without a network: file:// transfers, server error
// counting, the fetch callback path, the sandbox hooks with a stand-in
// Sandbox, the date and host helpers
#![allow(clippy::panic)]
use std::ffi::c_int;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use alpm_core::callbacks::{Callbacks, DownloadEvent, Event, Fetch, LogLevel};
use alpm_core::dload::{
	DownloadState, Downloader, Payload, ProxyEnv, Sandbox, Settings,
	download_internal, getdate_capped, gethost, http_date,
	remove_temporary_download_dir,
};
use alpm_core::error::Errno;
use alpm_core::util::{filecache_find, filecache_setup};

struct Tmp(PathBuf);

impl Tmp {
	fn new(tag: &str) -> Tmp {
		static N: AtomicUsize = AtomicUsize::new(0);
		let n = N.fetch_add(1, Ordering::Relaxed);
		let d = std::env::temp_dir().join(format!(
			"dload-unit-{tag}-{}-{n}",
			std::process::id()
		));
		let _ = fs::remove_dir_all(&d);
		fs::create_dir_all(&d).unwrap();
		Tmp(d)
	}

	fn p(&self, rel: &str) -> PathBuf {
		self.0.join(rel)
	}

	// "<dir>/" as the C passes directories
	fn dir(&self) -> Vec<u8> {
		[self.0.as_os_str().as_bytes(), b"/"].concat()
	}

	fn url(&self, rel: &str) -> Vec<u8> {
		[
			b"file://",
			self.0.as_os_str().as_bytes(),
			b"/",
			rel.as_bytes(),
		]
		.concat()
	}
}

impl Drop for Tmp {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.0);
	}
}

#[derive(Default)]
struct Rec {
	logs: Vec<(LogLevel, String)>,
	events: Vec<(String, DownloadEvent)>,
	alpm: Vec<Event<'static>>,
}

impl Callbacks for Rec {
	// errors and warnings: the debug lines are compared against the C
	fn log(&mut self, level: LogLevel, msg: &[u8]) {
		if level != LogLevel::Debug {
			self.logs.push((
				level,
				String::from_utf8_lossy(msg).into(),
			));
		}
	}

	fn download(&mut self, filename: &[u8], event: DownloadEvent) {
		let f = String::from_utf8_lossy(filename).into();
		self.events.push((f, event));
	}

	// dload sends the pkg_retrieve events only, they borrow nothing
	fn event(&mut self, event: &Event<'_>) {
		let e = match *event {
			Event::PkgRetrieveStart { num, total_size } => {
				Event::PkgRetrieveStart { num, total_size }
			}
			Event::PkgRetrieveDone { num, total_size } => {
				Event::PkgRetrieveDone { num, total_size }
			}
			Event::PkgRetrieveFailed { num, total_size } => {
				Event::PkgRetrieveFailed { num, total_size }
			}
			e => panic!("unexpected event {e:?}"),
		};
		self.alpm.push(e);
	}
}

impl Rec {
	// events without progress
	fn steps(&self) -> Vec<(String, DownloadEvent)> {
		let p = |e: &DownloadEvent| {
			matches!(e, DownloadEvent::Progress { .. })
		};
		self.events.iter().filter(|(_, e)| !p(e)).cloned().collect()
	}
}

fn payload(t: &Tmp, name: &str) -> Payload {
	let mut p = Payload::default();
	p.remote_name = name.into();
	p.destfile_name = Some([&t.dir()[..], name.as_bytes()].concat());
	p.tempfile_name = [&t.dir()[..], name.as_bytes(), b".part"].concat();
	p
}

fn set_mtime(p: &Path, t: u64) {
	let f = fs::File::options().write(true).open(p).unwrap();
	let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(t);
	f.set_times(fs::FileTimes::new().set_modified(t).set_accessed(t))
		.unwrap();
}

fn internal(payloads: &mut [Payload], rec: &mut Rec) -> Result<bool, Errno> {
	let mut state = DownloadState::default();
	download_internal(&Settings::default(), &mut state, rec, payloads)
}

#[test]
fn hosts() {
	let cases: &[(&[u8], Option<&[u8]>)] = &[
		(b"https://mirror.example/core/os", Some(b"mirror.example")),
		(b"http://u:p@h:8080/x", Some(b"h:8080")),
		(b"http://@h/x", Some(b"@h")),
		(b"http://a@b@c/x", Some(b"c")),
		(b"file:///var/cache", Some(b"disk")),
		(b"ftp://h", Some(b"h")),
		(b"nohost", None),
		(b"x//", Some(b"")),
	];
	for (url, want) in cases {
		assert_eq!(gethost(url).as_deref(), *want, "{url:?}");
	}
	let long = [&b"http://"[..], &[b'a'; 256], b"/x"].concat();
	assert_eq!(gethost(&long), None);
	let fits = [&b"http://"[..], &[b'a'; 255], b"/x"].concat();
	assert_eq!(gethost(&fits).map(|h| h.len()), Some(255));
}

#[test]
fn dates() {
	let date = |t| http_date(t).unwrap();
	assert_eq!(date(784111777), "Sun, 06 Nov 1994 08:49:37 GMT");
	assert_eq!(date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
	assert_eq!(http_date(1 << 40), None);
	for s in [
		&b"Sun, 06 Nov 1994 08:49:37 GMT"[..],
		b"Sunday, 06-Nov-94 08:49:37 GMT",
		b"Sun Nov  6 08:49:37 1994",
		b"Sun, 06 Nov 1994 09:49:37 +0100",
		b"Sun, 06 Nov 1994 03:49:37 EST",
	] {
		assert_eq!(getdate_capped(s), 784111777, "{s:?}");
	}
	assert_eq!(getdate_capped(b"garbage"), -1);
	// no time is midnight, a parsed -1 is 0
	assert_eq!(getdate_capped(b"06 Nov 1994"), 784080000);
	assert_eq!(getdate_capped(b"31 Dec 1969 23:59:59 GMT"), 0);
	assert_eq!(getdate_capped(b"Tue, 15 Mar 1582 22:12:44 GMT"), -1);
	for t in (0..4_000_000_000i64).step_by(86_399_999) {
		assert_eq!(getdate_capped(date(t).as_bytes()), t);
	}
}

#[test]
fn file_url_download() {
	let t = Tmp::new("file");
	let data: Vec<u8> = (0..50_000u32).map(|i| i as u8).collect();
	fs::write(t.p("src"), &data).unwrap();
	set_mtime(&t.p("src"), 1_000_000_000);
	let mut p = payload(&t, "f.pkg.tar.zst");
	p.fileurl = Some(t.url("src"));
	let mut rec = Rec::default();
	assert_eq!(internal(&mut [p], &mut rec), Ok(true));
	assert_eq!(fs::read(t.p("f.pkg.tar.zst")).unwrap(), data);
	let md = fs::metadata(t.p("f.pkg.tar.zst")).unwrap();
	assert_eq!(md.mtime(), 1_000_000_000);
	assert!(!t.p("f.pkg.tar.zst.part").exists());
	let name = "f.pkg.tar.zst".to_string();
	assert_eq!(
		rec.steps(),
		[
			(name.clone(), DownloadEvent::Init { optional: false }),
			(
				name.clone(),
				DownloadEvent::Completed {
					total: 50_000,
					result: 0
				}
			),
		]
	);
	let last = rec.events.iter().rev().nth(1).unwrap();
	assert_eq!(
		last.1,
		DownloadEvent::Progress {
			downloaded: 50_000,
			total: 50_000
		}
	);
}

#[test]
fn file_url_resume() {
	let t = Tmp::new("resume");
	let data: Vec<u8> = (0..9000u32).map(|i| (i * 7) as u8).collect();
	fs::write(t.p("src"), &data).unwrap();
	fs::write(t.p("f.pkg.part"), &data[..4000]).unwrap();
	let mut p = payload(&t, "f.pkg");
	p.fileurl = Some(t.url("src"));
	p.allow_resume = true;
	let mut ps = [p];
	let mut rec = Rec::default();
	assert_eq!(internal(&mut ps, &mut rec), Ok(true));
	assert_eq!(ps[0].initial_size(), 4000);
	assert_eq!(fs::read(t.p("f.pkg")).unwrap(), data);
	assert!(rec.steps().contains(&(
		"f.pkg".into(),
		DownloadEvent::Completed {
			total: 5000,
			result: 0
		}
	)));
}

// four file:// mirrors share the host "disk": three soft errors block
// it, so the fourth (which has the file) is never tried
#[test]
fn soft_errors_block_a_host() {
	let t = Tmp::new("missing");
	fs::create_dir(t.p("r4")).unwrap();
	fs::write(t.p("r4/core.db"), b"db").unwrap();
	let mut p = payload(&t, "core.db");
	p.filepath = Some(b"core.db".to_vec());
	p.servers = ["r1", "r2", "r3", "r4"].iter().map(|r| t.url(r)).collect();
	let mut rec = Rec::default();
	let mut state = DownloadState::default();
	let s = Settings::default();
	let r = download_internal(&s, &mut state, &mut rec, &mut [p]);
	assert_eq!(r, Err(Errno::Libcurl));
	assert_eq!(state.server_errors(b"disk"), Some(3));
	let levels: Vec<LogLevel> = rec.logs.iter().map(|(l, _)| *l).collect();
	use LogLevel::{Error, Warning};
	assert_eq!(levels, [Error, Error, Error, Warning], "{:?}", rec.logs);
	assert!(rec.logs[3].1.starts_with("too many errors from disk"));
	let retries = rec
		.events
		.iter()
		.filter(|(_, e)| matches!(e, DownloadEvent::Retry { .. }))
		.count();
	assert_eq!(retries, 2);
	assert!(!t.p("core.db").exists());
	assert!(!t.p("core.db.part").exists());
	// optional payloads never count
	let mut q = payload(&t, "extra.db");
	q.filepath = Some(b"extra.db".to_vec());
	q.servers = vec![t.url("r1")];
	q.errors_ok = true;
	let mut state = DownloadState::default();
	let r = download_internal(&s, &mut state, &mut rec, &mut [q]);
	assert_eq!(r, Ok(false));
	assert_eq!(state.server_errors(b"disk"), Some(0));
}

#[test]
fn required_failure_is_err() {
	let t = Tmp::new("required");
	let mut p = payload(&t, "core.db");
	p.fileurl = Some(t.url("nope"));
	let mut rec = Rec::default();
	assert_eq!(internal(&mut [p], &mut rec), Err(Errno::Libcurl));
	let want = format!(
		"failed retrieving file 'core.db' from disk : Could not open file {}\n",
		t.p("nope").display()
	);
	assert_eq!(rec.logs, [(LogLevel::Error, want)]);
	assert!(!t.p("core.db.part").exists());
}

#[test]
fn time_condition_on_file_url() {
	let t = Tmp::new("timecond");
	fs::create_dir(t.p("repo")).unwrap();
	fs::write(t.p("repo/core.db"), b"new").unwrap();
	set_mtime(&t.p("repo/core.db"), 1_000_000_000);
	fs::write(t.p("core.db"), b"old").unwrap();
	let mut p = payload(&t, "core.db");
	p.filepath = Some(b"core.db".to_vec());
	p.servers = vec![t.url("repo")];
	let settings = Settings::default();
	let mut state = DownloadState::default();
	let mut rec = Rec::default();
	let mut dl = Downloader {
		settings: &settings,
		state: &mut state,
		cb: &mut rec,
		fetch: None,
		sandbox: None,
	};
	// the destination is newer: up to date, nothing downloaded
	let mut ps = [p];
	assert_eq!(dl.download(&mut ps, &t.dir(), &t.dir()), Ok(false));
	assert_ne!(ps[0].mtime_existing_file, 0);
	assert_eq!(fs::read(t.p("core.db")).unwrap(), b"old");
	assert!(!t.p("core.db.part").exists());
}

struct Script {
	rets: Vec<(Vec<u8>, c_int)>,
	calls: Vec<Vec<u8>>,
}

impl Fetch for Script {
	fn fetch(&mut self, url: &[u8], _: &[u8], _: bool) -> c_int {
		self.calls.push(url.to_vec());
		self.rets
			.iter()
			.find(|(u, _)| u == url)
			.map_or(-1, |(_, r)| *r)
	}
}

#[test]
fn fetch_callback_path() {
	let t = Tmp::new("fetch");
	let mut a = payload(&t, "a.db");
	a.filepath = Some(b"a.db".to_vec());
	a.cache_servers = vec![b"http://cache".to_vec()];
	a.servers = vec![b"http://m1".to_vec(), b"http://m2".to_vec()];
	a.download_signature = true;
	let mut b = payload(&t, "b.pkg");
	b.fileurl = Some(b"http://u/b.pkg".to_vec());
	b.download_signature = true;
	b.signature_optional = true;
	let mut f = Script {
		rets: vec![
			(b"http://m2/a.db".to_vec(), 1),
			(b"http://m2/a.db.sig".to_vec(), 0),
			(b"http://u/b.pkg".to_vec(), 1),
		],
		calls: Vec::new(),
	};
	let settings = Settings::default();
	let mut state = DownloadState::default();
	let mut rec = Rec::default();
	let mut dl = Downloader {
		settings: &settings,
		state: &mut state,
		cb: &mut rec,
		fetch: Some(&mut f),
		sandbox: None,
	};
	// a's .sig download (required) counts as its result: 0, downloaded
	let r = dl.download(&mut [a, b], &t.dir(), &t.dir());
	assert_eq!(r, Ok(true));
	let calls: Vec<&[u8]> = f.calls.iter().map(|c| &c[..]).collect();
	assert_eq!(
		calls,
		[
			&b"http://cache/a.db"[..],
			b"http://m1/a.db",
			b"http://m2/a.db",
			b"http://m2/a.db.sig",
			b"http://u/b.pkg",
			b"http://u/b.pkg.sig",
		]
	);
	// a required failure stops at once
	let mut c = payload(&t, "c.db");
	c.fileurl = Some(b"http://u/c.db".to_vec());
	let mut d = payload(&t, "d.db");
	d.fileurl = Some(b"http://u/d.db".to_vec());
	let mut f = Script {
		rets: Vec::new(),
		calls: Vec::new(),
	};
	let mut dl = Downloader {
		settings: &settings,
		state: &mut state,
		cb: &mut rec,
		fetch: Some(&mut f),
		sandbox: None,
	};
	let r = dl.download(&mut [c, d], &t.dir(), &t.dir());
	assert_eq!(r, Err(Errno::ExternalDownload));
	assert_eq!(f.calls, [b"http://u/c.db".to_vec()]);
}

// a Sandbox standing in for the forked child: copies src into the
// temporary dir like a download, reports a signal to re-raise
struct FakeSandbox {
	ids: Option<(u32, u32)>,
	src: PathBuf,
	seen_parts: Vec<Vec<u8>>,
	raised: Vec<c_int>,
	sig: c_int,
}

impl Sandbox for FakeSandbox {
	fn user(&self) -> &[u8] {
		b"alpm"
	}

	fn lookup(&self) -> Result<(u32, u32), Option<io::Error>> {
		self.ids.ok_or(None)
	}

	fn download(
		&mut self,
		_: &Settings,
		_: &DownloadState,
		_: &mut dyn Callbacks,
		payloads: &mut [Payload],
		tmp: &[u8],
	) -> (Result<bool, Errno>, c_int) {
		let tmp = Path::new(std::ffi::OsStr::from_bytes(tmp));
		let mut parts: Vec<Vec<u8>> = fs::read_dir(tmp)
			.unwrap()
			.flatten()
			.map(|e| e.file_name().as_bytes().to_vec())
			.collect();
		parts.sort();
		self.seen_parts = parts;
		for p in payloads.iter() {
			let dest = p.destfile_name.as_ref().unwrap();
			let dest = Path::new(std::ffi::OsStr::from_bytes(dest));
			fs::copy(&self.src, dest).unwrap();
		}
		(Ok(true), self.sig)
	}

	fn raise(&mut self, sig: c_int) {
		self.raised.push(sig);
	}
}

fn own_ids(p: &Path) -> (u32, u32) {
	let md = fs::metadata(p).unwrap();
	(md.uid(), md.gid())
}

#[test]
fn sandbox_hooks() {
	let t = Tmp::new("sandbox");
	let cache = Tmp::new("sandbox-cache");
	fs::write(t.p("src"), b"package").unwrap();
	// .part files from an earlier run, in localpath
	fs::write(cache.p("a.pkg.part"), b"aa").unwrap();
	fs::write(cache.p("b.pkg.part"), b"bb").unwrap();
	let mut sb = FakeSandbox {
		ids: Some(own_ids(&t.0)),
		src: t.p("src"),
		seen_parts: Vec::new(),
		raised: Vec::new(),
		sig: 15,
	};
	let settings = Settings::default();
	let mut state = DownloadState::default();
	let mut rec = Rec::default();
	let mut dl = Downloader {
		settings: &settings,
		state: &mut state,
		cb: &mut rec,
		fetch: None,
		sandbox: Some(&mut sb),
	};
	let tmp = dl.download_dir_setup(&cache.dir()).unwrap();
	let tmp_path = Path::new(std::ffi::OsStr::from_bytes(&tmp)).to_owned();
	assert!(tmp.ends_with(b"/"));
	let name = tmp_path.file_name().unwrap().to_string_lossy().into_owned();
	assert!(name.starts_with("download-") && name.len() == 15, "{name}");
	let mode = fs::metadata(&tmp_path).unwrap().permissions().mode();
	assert_eq!(mode & 0o777, 0o700);
	let mk = |n: &str| {
		let mut p = Payload::default();
		p.remote_name = n.into();
		p.fileurl = Some(format!("http://u/{n}").into_bytes());
		p.destfile_name = Some([&tmp[..], n.as_bytes()].concat());
		p.tempfile_name = [&tmp[..], n.as_bytes(), b".part"].concat();
		p.allow_resume = true;
		p
	};
	let mut ps = [mk("a.pkg"), mk("b.pkg")];
	let r = dl.download(&mut ps, &cache.dir(), &tmp);
	// the first .part moved in, then prepare stopped
	assert_eq!(sb.seen_parts, [b"a.pkg.part".to_vec()]);
	assert!(cache.p("b.pkg.part").exists());
	assert_eq!(sb.raised, [15]);
	assert!(!tmp_path.exists(), "temporary dir removed");
	// moved into place, chowned to root only when running as root
	assert_eq!(r, Ok(true), "{:?}", rec.logs);
	assert_eq!(fs::read(cache.p("a.pkg")).unwrap(), b"package");
}

#[test]
fn sandbox_user_missing() {
	let cache = Tmp::new("nouser");
	let mut sb = FakeSandbox {
		ids: None,
		src: PathBuf::new(),
		seen_parts: Vec::new(),
		raised: Vec::new(),
		sig: 0,
	};
	let settings = Settings::default();
	let mut state = DownloadState::default();
	let mut rec = Rec::default();
	let mut dl = Downloader {
		settings: &settings,
		state: &mut state,
		cb: &mut rec,
		fetch: None,
		sandbox: Some(&mut sb),
	};
	let r = dl.download_dir_setup(&cache.dir());
	assert_eq!(r, Err(Errno::RetrievePrepare));
	let want = "download user 'alpm' does not exist\n".to_string();
	assert_eq!(rec.logs, [(LogLevel::Error, want)]);
	assert_eq!(fs::read_dir(&cache.0).unwrap().count(), 0);
}

#[test]
fn fetch_pkgurl_file_urls() {
	let t = Tmp::new("pkgurl");
	let cache = Tmp::new("pkgurl-cache");
	fs::write(t.p("x-1-1-any.pkg.tar.zst"), b"pkg").unwrap();
	fs::write(t.p("blob"), b"blob").unwrap();
	fs::write(cache.p("c-1-1-any.pkg.tar.zst"), b"cached").unwrap();
	let settings = Settings::default();
	let mut state = DownloadState::default();
	let mut rec = Rec::default();
	let mut dl = Downloader {
		settings: &settings,
		state: &mut state,
		cb: &mut rec,
		fetch: None,
		sandbox: None,
	};
	let mut dirs = vec![cache.dir()];
	let urls = [
		t.url("x-1-1-any.pkg.tar.zst"),
		b"http://never/c-1-1-any.pkg.tar.zst".to_vec(),
		t.url("blob"),
	];
	let got = dl.fetch_pkgurl(&mut dirs, 0, &urls).unwrap();
	assert_eq!(got.len(), 3);
	assert_eq!(
		got[0],
		[&cache.dir()[..], b"c-1-1-any.pkg.tar.zst"].concat()
	);
	assert_eq!(
		got[1],
		[&cache.dir()[..], b"x-1-1-any.pkg.tar.zst"].concat()
	);
	let tmpname = String::from_utf8_lossy(&got[2]).into_owned();
	assert!(tmpname.contains("/alpmtmp."), "{tmpname}");
	assert_eq!(fs::read(&tmpname).unwrap(), b"blob");
	assert_eq!(
		rec.alpm,
		[
			Event::PkgRetrieveStart {
				num: 2,
				total_size: 0
			},
			Event::PkgRetrieveDone {
				num: 2,
				total_size: 0
			},
		]
	);
}

#[test]
fn cache_dirs() {
	let t = Tmp::new("cachedirs");
	fs::write(t.p("file"), b"x").unwrap();
	fs::create_dir(t.p("dir")).unwrap();
	fs::create_dir(t.p("dir/pkg")).unwrap();
	fs::create_dir(t.p("ok")).unwrap();
	fs::write(t.p("ok/pkg"), b"x").unwrap();
	let d = |n: &str| [&t.dir()[..], n.as_bytes(), b"/"].concat();
	let mut rec = Rec::default();
	let dirs = vec![d("dir"), d("ok")];
	let found = filecache_find(&dirs, b"pkg", &mut rec);
	assert_eq!(found, Some([&d("ok")[..], b"pkg"].concat()));
	assert!(rec.logs[0].1.contains("is not a regular file: mode="));
	// a missing cachedir is made
	let mut dirs = vec![d("new/deep")];
	assert_eq!(filecache_setup(&mut dirs, &mut rec), d("new/deep"));
	assert!(t.p("new/deep").is_dir());
	// a regular file passes as made (mkdir's EEXIST counts as done)
	let mut dirs = vec![d("file")];
	assert_eq!(filecache_setup(&mut dirs, &mut rec), d("file"));
	// nothing usable: /tmp/ joins the list
	fs::create_dir(t.p("ro")).unwrap();
	fs::set_permissions(t.p("ro"), fs::Permissions::from_mode(0o555))
		.unwrap();
	let mut dirs = vec![d("ro")];
	assert_eq!(filecache_setup(&mut dirs, &mut rec), b"/tmp/");
	assert_eq!(dirs, [d("ro"), b"/tmp/".to_vec()]);
	// the temporary dir goes with its files
	fs::create_dir(t.p("tmpdir")).unwrap();
	fs::write(t.p("tmpdir/a.part"), b"a").unwrap();
	remove_temporary_download_dir(&d("tmpdir"));
	assert!(!t.p("tmpdir").exists());
}

// curl's proxy environment rules (proxy_detect_proxy, parse_proxy,
// proxy_check_noproxy): which variable wins, no_proxy matching
#[test]
fn proxy_env_rules() {
	use reqwest::Url;
	let env = |vars: &[(&str, &str)]| {
		let vars: Vec<(String, String)> = vars
			.iter()
			.map(|(k, v)| (k.to_string(), v.to_string()))
			.collect();
		ProxyEnv::new(move |n| {
			vars.iter()
				.find(|(k, _)| k == n)
				.map(|(_, v)| v.clone())
		})
	};
	let url = |s: &str| Url::parse(s).unwrap();
	let pick = |vars: &[(&str, &str)], target: &str| {
		env(vars)
			.proxy_for(&url(target))
			.map(|p| p.map(|u| u.to_string()))
	};
	let a = Ok(Some("http://a:3128/".to_string()));
	let b = Ok(Some("http://b:3128/".to_string()));
	let http = "http://mirror.example.org/x";
	let https = "https://mirror.example.org/x";
	// lowercase first; HTTP_PROXY is never read, HTTPS_PROXY is
	assert_eq!(pick(&[("http_proxy", "http://a:3128")], http), a);
	assert_eq!(pick(&[("HTTP_PROXY", "http://a:3128")], http), Ok(None));
	assert_eq!(pick(&[("HTTPS_PROXY", "http://a:3128")], https), a);
	assert_eq!(
		pick(
			&[
				("https_proxy", "http://a:3128"),
				("HTTPS_PROXY", "http://b:3128")
			],
			https
		),
		a
	);
	assert_eq!(pick(&[("https_proxy", "http://a:3128")], http), Ok(None));
	// all_proxy after the scheme's own, ALL_PROXY after all_proxy
	assert_eq!(
		pick(
			&[
				("http_proxy", "http://a:3128"),
				("all_proxy", "http://b:3128")
			],
			http
		),
		a
	);
	assert_eq!(pick(&[("all_proxy", "http://b:3128")], http), b);
	assert_eq!(pick(&[("ALL_PROXY", "http://b:3128")], https), b);
	assert_eq!(
		pick(
			&[
				("all_proxy", "http://a:3128"),
				("ALL_PROXY", "http://b:3128")
			],
			http
		),
		a
	);
	// an empty value is unset
	assert_eq!(
		pick(
			&[("http_proxy", ""), ("all_proxy", "http://b:3128")],
			http
		),
		b
	);
	// no scheme is http, no port is 1080, socks is not this downloader's
	assert_eq!(pick(&[("http_proxy", "a:3128")], http), a);
	assert_eq!(
		pick(&[("http_proxy", "http://a")], http),
		Ok(Some("http://a:1080/".to_string()))
	);
	assert_eq!(
		pick(&[("http_proxy", "https://u:p@a")], http),
		Ok(Some("https://u:p@a:1080/".to_string()))
	);
	// a scheme's default port given explicitly stays (the url crate
	// hides it)
	assert_eq!(
		pick(&[("http_proxy", "http://a:80")], http),
		Ok(Some("http://a/".to_string()))
	);
	assert_eq!(
		pick(&[("http_proxy", "https://u@a:443/x")], http),
		Ok(Some("https://u@a/x".to_string()))
	);
	assert_eq!(
		pick(&[("http_proxy", "http://[::1]:80")], http),
		Ok(Some("http://[::1]/".to_string()))
	);
	assert_eq!(
		pick(&[("http_proxy", "http://[::1]")], http),
		Ok(Some("http://[::1]:1080/".to_string()))
	);
	assert_eq!(
		pick(&[("http_proxy", "socks5h://a:1080")], http),
		Err("Unsupported proxy scheme for 'socks5h://a:1080'"
			.to_string())
	);
	assert_eq!(
		pick(&[("http_proxy", "http://")], http),
		Err("Unsupported proxy syntax in 'http://': Bad hostname"
			.to_string())
	);
	// no_proxy before NO_PROXY, "*" for all, names by tail at a dot,
	// dots around a token ignored, blanks and empty tokens skipped
	let np = |no: &str, target: &str| {
		pick(
			&[("http_proxy", "http://a:3128"), ("no_proxy", no)],
			target,
		) == Ok(None)
	};
	assert!(np("*", http));
	assert!(np("mirror.example.org", http));
	assert!(np("MIRROR.example.org", http));
	assert!(np("example.org", http));
	assert!(np(".example.org", http));
	assert!(np("example.org.", http));
	assert!(np(" foo.org , example.org", http));
	assert!(np("foo.org,,example.org", http));
	assert!(!np("xample.org", http));
	assert!(!np("mirror.example.org.uk", http));
	assert!(!np("example", http));
	assert!(!np("", http));
	assert!(np("example.org", "http://mirror.example.org./x"));
	// a blank ends a token, what follows is not another one
	assert!(!np("foo.org example.org", http));
	assert_eq!(
		pick(
			&[
				("http_proxy", "http://a:3128"),
				("NO_PROXY", "example.org")
			],
			http
		),
		Ok(None)
	);
	assert_eq!(
		pick(
			&[
				("http_proxy", "http://a:3128"),
				("no_proxy", "other.org"),
				("NO_PROXY", "example.org"),
			],
			http
		),
		a
	);
	// addresses: exact, or inside the CIDR; brackets off an IPv6 host
	assert!(np("127.0.0.1", "http://127.0.0.1:8080/x"));
	assert!(np("127.0.0.0/8", "http://127.0.0.1:8080/x"));
	assert!(np("10.0.0.0/8,127.0.0.0/8", "http://127.0.0.1/x"));
	assert!(!np("127.0.0.2", "http://127.0.0.1/x"));
	assert!(!np("127.0.0.0/33", "http://127.0.0.1/x"));
	assert!(!np("127.0.0.0/x", "http://127.0.0.1/x"));
	assert!(!np("127.0.0.1", "http://localhost/x"));
	assert!(np("::1", "http://[::1]/x"));
	assert!(np("fe80::/10", "http://[fe80::1]/x"));
	assert!(!np("fe80::/10", "http://[fec0::1]/x"));
	assert!(!np("127.0.0.1", "http://[::1]/x"));
	assert_eq!(ProxyEnv::new(|_| None).proxy_for(&url(http)), Ok(None));
}
