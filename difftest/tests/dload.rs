// alpm_core::dload against the C _alpm_download/alpm_fetch_pkgurl: both
// download from the same scripted HTTP servers on 127.0.0.1 (and file://
// urls) into their own dirs of one fixture. compared: return value,
// pm_errno on failure, download callback events (progress runs reduced
// to their last event: curl's progress timing is not deterministic),
// error/warning logs, the resulting files (contents, mode, server mtimes,
// .part leftovers) and the requests each side sent.
use std::ffi::c_int;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use alpm_core::callbacks::{DownloadEvent, LogLevel};
use alpm_core::dload::{DownloadState, Downloader, Payload, Settings};
use difftest::{
	CDload, Fetcher, Record, Recorder, Reply, Req, Rng, Server, Style,
	TempRoot, closed_port, iters, payload_layout_ok, test_helper,
	umask_lock, unsandbox,
};

const T0: i64 = 1_000_000_000;

// name, contents, mode, mtime when a server set it
type Files = Vec<(Vec<u8>, Vec<u8>, u32, Option<i64>)>;
type MkPayloads = Box<dyn Fn(&[u8]) -> Vec<Payload>>;

// one side's result, normalized for comparison
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
	ret: c_int,
	errno: c_int,
	downloads: Vec<(Vec<u8>, DownloadEvent)>,
	logs: Vec<(LogLevel, Vec<u8>)>,
	files: Files,
	requests: Vec<Req>,
	// most stalled responses at once
	peak: usize,
}

// progress events of a file between two of its other events: only the
// last one stays
fn reduce_progress(
	ev: &[(Vec<u8>, DownloadEvent)],
) -> Vec<(Vec<u8>, DownloadEvent)> {
	let mut out: Vec<(Vec<u8>, DownloadEvent)> = Vec::new();
	for (name, e) in ev {
		if matches!(e, DownloadEvent::Progress { .. }) {
			let prev = out.iter().rposition(|(n, _)| n == name);
			if let Some(i) = prev
				&& matches!(
					out[i].1,
					DownloadEvent::Progress { .. }
				) {
				out.remove(i);
			}
		}
		out.push((name.clone(), *e));
	}
	out
}

// dir prefixes and curl's timings out of a log line
fn norm_log(msg: &[u8], dir: &[u8]) -> Vec<u8> {
	let mut s = String::from_utf8_lossy(msg).into_owned();
	s = s.replace(&*String::from_utf8_lossy(dir), "<dir>/");
	for (pre, post) in [(" after ", " ms"), (" after ", " milliseconds")] {
		if let Some(i) = s.find(pre)
			&& let Some(j) = s[i + pre.len()..].find(post)
		{
			let num = &s[i + pre.len()..i + pre.len() + j];
			if num.bytes().all(|c| c.is_ascii_digit()) {
				s.replace_range(
					i + pre.len()..i + pre.len() + j,
					"#",
				);
			}
		}
	}
	// a time condition on a file this run wrote without a server time:
	// its write time, seconds apart between the sides (fixed server
	// times stay compared)
	let pre = ": using time condition ";
	if let Some(i) = s.find(pre) {
		let at = i + pre.len();
		let num = s[at..].trim_end_matches('\n');
		let now = alpm_core::log::now_secs();
		if num.parse::<i64>().is_ok_and(|t| (now - t).abs() < 3600) {
			s.replace_range(at..at + num.len(), "<now>");
		}
	}
	s.into_bytes()
}

// files under dir: name, contents, mode, mtime when a server set it
fn snapshot(dir: &Path) -> Files {
	let mut out = Vec::new();
	let Ok(rd) = fs::read_dir(dir) else {
		return out;
	};
	for e in rd.flatten() {
		let md = e.metadata().unwrap();
		let data = if md.is_file() {
			fs::read(e.path()).unwrap()
		} else {
			b"<dir>".to_vec()
		};
		let mtime = (md.mtime() < 1_500_000_000).then_some(md.mtime());
		let name = e.file_name().as_bytes().to_vec();
		out.push((name, data, md.permissions().mode() & 0o7777, mtime));
	}
	out.sort();
	out
}

fn outcome(
	ret: c_int,
	errno: c_int,
	rec: Record,
	dir: &Path,
	servers: &[&Server],
	sorted: bool,
) -> Outcome {
	let d = [dir.as_os_str().as_bytes(), b"/"].concat();
	let mut downloads = reduce_progress(&rec.downloads);
	let mut logs: Vec<_> =
		rec.logs.iter()
			.map(|(l, m)| (*l, norm_log(m, &d)))
			.collect();
	let mut requests: Vec<Req> =
		servers.iter().flat_map(|s| s.requests()).collect();
	if sorted {
		downloads.sort_by(|a, b| a.0.cmp(&b.0));
		logs.sort();
		requests.sort();
	}
	let peak = servers.iter().map(|s| s.peak()).max().unwrap_or(0);
	for s in servers {
		s.reset();
	}
	Outcome {
		ret,
		errno: if ret == -1 { errno } else { 0 },
		downloads,
		logs,
		files: snapshot(dir),
		requests,
		peak,
	}
}

fn rust_ret(r: Result<bool, alpm_core::error::Errno>) -> (c_int, c_int) {
	match r {
		Ok(true) => (0, 0),
		Ok(false) => (1, 0),
		Err(e) => (-1, e as c_int),
	}
}

// a download case: payloads per dir, files placed before, options
struct Case<'a> {
	servers: Vec<&'a Server>,
	payloads: &'a dyn Fn(&[u8]) -> Vec<Payload>,
	setup: &'a dyn Fn(&Path),
	parallel: u32,
	disable_timeout: bool,
	// event/log/request order only compared per file
	sorted: bool,
}

fn dir_bytes(p: &Path) -> Vec<u8> {
	[p.as_os_str().as_bytes(), b"/"].concat()
}

// runs C then Rust, each into its own fresh dir. file modes follow the
// umask the C's _getumask briefly sets to 0
fn run(case: &Case) -> (Outcome, Outcome) {
	let _umask = umask_lock();
	let fx = TempRoot::new("dload");
	let (cd, rd) = (fx.dir().join("c"), fx.dir().join("r"));
	for d in [&cd, &rd] {
		fs::create_dir(d).unwrap();
		(case.setup)(d);
	}
	for s in &case.servers {
		s.reset();
	}
	let c = {
		let mut h = CDload::new(&fx);
		h.set_parallel(case.parallel);
		h.set_disable_dl_timeout(case.disable_timeout);
		let dir = dir_bytes(&cd);
		let (ret, errno, rec) =
			h.download(&(case.payloads)(&dir), &dir, &dir);
		outcome(ret, errno, rec, &cd, &case.servers, case.sorted)
	};
	let r = {
		let settings = Settings {
			parallel_downloads: case.parallel,
			disable_dl_timeout: case.disable_timeout,
			..Settings::default()
		};
		let mut state = DownloadState::default();
		let mut rec = Recorder::default();
		let mut dl = Downloader {
			settings: &settings,
			state: &mut state,
			cb: &mut rec,
			fetch: None,
			sandbox: None,
		};
		let dir = dir_bytes(&rd);
		let mut payloads = (case.payloads)(&dir);
		let (ret, errno) =
			rust_ret(dl.download(&mut payloads, &dir, &dir));
		outcome(ret, errno, rec.0, &rd, &case.servers, case.sorted)
	};
	(c, r)
}

fn no_setup(_: &Path) {}

// a db-style payload: filepath over servers, into dir
fn db_payload(dir: &[u8], name: &str, servers: &[Vec<u8>]) -> Payload {
	let mut p = Payload::default();
	p.remote_name = name.as_bytes().to_vec();
	p.filepath = Some(name.as_bytes().to_vec());
	p.servers = servers.to_vec();
	p.destfile_name = Some([dir, name.as_bytes()].concat());
	p.tempfile_name = [dir, name.as_bytes(), b".part"].concat();
	p
}

// a package-style payload: one url, resumable .part
fn pkg_payload(dir: &[u8], name: &str, url: Vec<u8>) -> Payload {
	let mut p = Payload::default();
	p.remote_name = name.as_bytes().to_vec();
	p.fileurl = Some(url);
	p.destfile_name = Some([dir, name.as_bytes()].concat());
	p.tempfile_name = [dir, name.as_bytes(), b".part"].concat();
	p.allow_resume = true;
	p
}

fn body(n: usize, seed: u8) -> Vec<u8> {
	(0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
		.collect()
}

fn file(b: &[u8]) -> Reply {
	Reply::File {
		body: b.to_vec(),
		ranges: true,
		mtime: Some(T0),
	}
}

#[test]
fn payload_mirror_layout() {
	assert!(payload_layout_ok());
}

// a named case owning its servers
struct Scn {
	name: String,
	servers: Vec<Server>,
	payloads: MkPayloads,
	setup: Box<dyn Fn(&Path)>,
	parallel: u32,
	sorted: bool,
}

impl Scn {
	fn new(
		name: impl Into<String>,
		servers: Vec<Server>,
		payloads: impl Fn(&[u8], &[Server]) -> Vec<Payload> + 'static,
	) -> Scn {
		let urls: Vec<String> =
			servers.iter().map(Server::base).collect();
		let f = move |d: &[u8]| {
			// payload builders get stand-ins with the same urls
			payloads(d, &[])
				.into_iter()
				.map(|mut p| {
					let fix =
						|v: &mut Vec<u8>| {
							let s = String::from_utf8_lossy(v).into_owned();
							let mut s2 = s.clone();
							for (i, u) in urls
								.iter()
								.enumerate()
							{
								s2 = s2.replace(&format!("@{i}"), u);
							}
							if s2 != s {
								*v = s2.into_bytes();
							}
						};
					p.servers.iter_mut().for_each(fix);
					p.cache_servers
						.iter_mut()
						.for_each(fix);
					if let Some(u) = &mut p.fileurl {
						fix(u);
					}
					p
				})
				.collect()
		};
		Scn {
			name: name.into(),
			servers,
			payloads: Box::new(f),
			setup: Box::new(no_setup),
			parallel: 1,
			sorted: false,
		}
	}

	fn setup(mut self, f: impl Fn(&Path) + 'static) -> Scn {
		self.setup = Box::new(f);
		self
	}

	fn parallel(mut self, n: u32) -> Scn {
		self.parallel = n;
		self.sorted = n > 1;
		self
	}

	fn run(&self) -> (Outcome, Outcome) {
		let case = Case {
			servers: self.servers.iter().collect(),
			payloads: &*self.payloads,
			setup: &*self.setup,
			parallel: self.parallel,
			disable_timeout: false,
			sorted: self.sorted,
		};
		run(&case)
	}
}

fn srv(routes: &[(&str, Vec<Reply>)]) -> Server {
	styled(Style::Close, routes)
}

fn styled(style: Style, routes: &[(&str, Vec<Reply>)]) -> Server {
	let s = Server::start_styled(style);
	for (p, r) in routes {
		s.route(p, r.clone());
	}
	s
}

fn st(code: u16) -> Reply {
	Reply::Status(code, format!("<html>{code}</html>\n").into_bytes())
}

fn v(s: &str) -> Vec<u8> {
	s.as_bytes().to_vec()
}

// servers named "@<i>" in payloads stand for the scenario's i-th server
fn scenarios() -> Vec<Scn> {
	let b = body(3000, 1);
	let big = body(40000, 2);
	let mut out = Vec::new();
	let b2 = b.clone();
	out.push(Scn::new(
		"ok",
		vec![srv(&[("/core.db", vec![file(&b)])])],
		|d, _| vec![db_payload(d, "core.db", &[v("@0")])],
	));
	out.push(Scn::new("404 one server", vec![srv(&[])], |d, _| {
		vec![db_payload(d, "core.db", &[v("@0")])]
	}));
	out.push(Scn::new(
		"404 then mirror",
		vec![srv(&[]), srv(&[("/core.db", vec![file(&b)])])],
		|d, _| vec![db_payload(d, "core.db", &[v("@0"), v("@1")])],
	));
	out.push(Scn::new(
		"500 then 503 then mirror",
		vec![
			srv(&[("/core.db", vec![st(500)])]),
			srv(&[("/core.db", vec![st(503)])]),
			srv(&[("/core.db", vec![file(&b)])]),
		],
		|d, _| {
			vec![db_payload(
				d,
				"core.db",
				&[v("@0"), v("@1"), v("@2")],
			)]
		},
	));
	// four payloads on a failing host: blocked after 3 soft errors
	out.push(Scn::new(
		"soft error limit",
		vec![
			srv(&[]),
			srv(&[
				("/a.db", vec![file(&b)]),
				("/b.db", vec![file(&b)]),
				("/c.db", vec![file(&b)]),
				("/d.db", vec![file(&b)]),
			]),
		],
		|d, _| {
			["a.db", "b.db", "c.db", "d.db"]
				.iter()
				.map(|n| db_payload(d, n, &[v("@0"), v("@1")]))
				.collect()
		},
	));
	out.push(Scn::new(
		"truncated then resume on mirror",
		vec![
			srv(&[(
				"/p.pkg.tar.zst",
				vec![Reply::Truncated {
					body: big.clone(),
					sent: 1000,
				}],
			)]),
			srv(&[("/p.pkg.tar.zst", vec![file(&big)])]),
		],
		|d, _| {
			let mut p = db_payload(
				d,
				"p.pkg.tar.zst",
				&[v("@0"), v("@1")],
			);
			p.allow_resume = true;
			vec![p]
		},
	));
	out.push(Scn::new(
		"truncated no resume on mirror",
		vec![
			srv(&[(
				"/core.db",
				vec![Reply::Truncated {
					body: big.clone(),
					sent: 1000,
				}],
			)]),
			srv(&[("/core.db", vec![file(&big)])]),
		],
		|d, _| vec![db_payload(d, "core.db", &[v("@0"), v("@1")])],
	));
	out.push(Scn::new(
		"truncated last server",
		vec![srv(&[(
			"/p.pkg.tar.zst",
			vec![Reply::Truncated {
				body: big.clone(),
				sent: 1000,
			}],
		)])],
		|d, _| {
			let mut p = db_payload(d, "p.pkg.tar.zst", &[v("@0")]);
			p.allow_resume = true;
			vec![p]
		},
	));
	let part = big[..5000].to_vec();
	let part2 = part.clone();
	out.push(Scn::new(
		"resume from .part",
		vec![srv(&[("/p.pkg.tar.zst", vec![file(&big)])])],
		|d, _| {
			vec![pkg_payload(
				d,
				"p.pkg.tar.zst",
				v("@0/p.pkg.tar.zst"),
			)]
		},
	)
	.setup(move |d| {
		fs::write(d.join("p.pkg.tar.zst.part"), &part).unwrap()
	}));
	let nr = Reply::File {
		body: big.clone(),
		ranges: false,
		mtime: Some(T0),
	};
	out.push(Scn::new(
		"resume, server ignores range",
		vec![srv(&[("/p.pkg.tar.zst", vec![nr.clone()])])],
		|d, _| {
			vec![pkg_payload(
				d,
				"p.pkg.tar.zst",
				v("@0/p.pkg.tar.zst"),
			)]
		},
	)
	.setup(move |d| {
		fs::write(d.join("p.pkg.tar.zst.part"), &part2).unwrap()
	}));
	let whole = big.clone();
	out.push(Scn::new(
		"resume, .part complete, 416",
		vec![srv(&[("/p.pkg.tar.zst", vec![file(&big)])])],
		|d, _| {
			vec![pkg_payload(
				d,
				"p.pkg.tar.zst",
				v("@0/p.pkg.tar.zst"),
			)]
		},
	)
	.setup(move |d| {
		fs::write(d.join("p.pkg.tar.zst.part"), &whole).unwrap()
	}));
	let whole = big.clone();
	let n = big.len() as i64;
	out.push(Scn::new(
		"resume, .part complete, max_size",
		vec![srv(&[("/p.pkg.tar.zst", vec![file(&big)])])],
		move |d, _| {
			let mut p = pkg_payload(
				d,
				"p.pkg.tar.zst",
				v("@0/p.pkg.tar.zst"),
			);
			p.max_size = n;
			vec![p]
		},
	)
	.setup(move |d| {
		fs::write(d.join("p.pkg.tar.zst.part"), &whole).unwrap()
	}));
	let longer = [&big[..], b"tail"].concat();
	out.push(Scn::new(
		"resume, .part longer",
		vec![srv(&[("/p.pkg.tar.zst", vec![file(&big)])])],
		|d, _| {
			vec![pkg_payload(
				d,
				"p.pkg.tar.zst",
				v("@0/p.pkg.tar.zst"),
			)]
		},
	)
	.setup(move |d| {
		fs::write(d.join("p.pkg.tar.zst.part"), &longer).unwrap()
	}));
	let same = Reply::Raw(
		[
			b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 5000\r\n\r\n"
				.to_vec(),
			big[..5000].to_vec(),
		]
		.concat(),
	);
	let part3 = big[..5000].to_vec();
	out.push(Scn::new(
		"resume, 200 with length == offset",
		vec![srv(&[("/p.pkg.tar.zst", vec![same])])],
		|d, _| {
			vec![pkg_payload(
				d,
				"p.pkg.tar.zst",
				v("@0/p.pkg.tar.zst"),
			)]
		},
	)
	.setup(move |d| {
		fs::write(d.join("p.pkg.tar.zst.part"), &part3).unwrap()
	}));
	let wrong = Reply::Raw(
		[
			b"HTTP/1.1 206 Partial Content\r\nConnection: close\r\n\
			Content-Range: bytes 10-39999/40000\r\n\
			Content-Length: 39990\r\n\r\n"
				.to_vec(),
			big[10..].to_vec(),
		]
		.concat(),
	);
	let part4 = big[..5000].to_vec();
	out.push(Scn::new(
		"resume, wrong content-range",
		vec![srv(&[("/p.pkg.tar.zst", vec![wrong])])],
		|d, _| {
			vec![pkg_payload(
				d,
				"p.pkg.tar.zst",
				v("@0/p.pkg.tar.zst"),
			)]
		},
	)
	.setup(move |d| {
		fs::write(d.join("p.pkg.tar.zst.part"), &part4).unwrap()
	}));
	let part5 = big[..5000].to_vec();
	out.push(Scn::new("resume, 404", vec![srv(&[])], |d, _| {
		vec![pkg_payload(d, "p.pkg.tar.zst", v("@0/p.pkg.tar.zst"))]
	})
	.setup(move |d| {
		fs::write(d.join("p.pkg.tar.zst.part"), &part5).unwrap()
	}));
	let old = b2.clone();
	out.push(Scn::new(
		"if-modified-since 304",
		vec![srv(&[("/core.db", vec![file(&b)])])],
		|d, _| vec![db_payload(d, "core.db", &[v("@0")])],
	)
	.setup(move |d| {
		let p = d.join("core.db");
		fs::write(&p, &old).unwrap();
		set_mtime(&p, T0);
	}));
	let old = b2.clone();
	out.push(Scn::new(
		"time condition, server older",
		vec![srv(&[("/core.db", vec![file(&b)])])],
		|d, _| vec![db_payload(d, "core.db", &[v("@0")])],
	)
	.setup(move |d| fs::write(d.join("core.db"), &old).unwrap()));
	let old = b2.clone();
	out.push(Scn::new(
		"time condition, server newer",
		vec![srv(&[(
			"/core.db",
			vec![Reply::File {
				body: b.clone(),
				ranges: true,
				mtime: Some(1_400_000_000),
			}],
		)])],
		|d, _| vec![db_payload(d, "core.db", &[v("@0")])],
	)
	.setup(move |d| {
		let p = d.join("core.db");
		fs::write(&p, &old).unwrap();
		set_mtime(&p, T0);
	}));
	let old = b2.clone();
	out.push(Scn::new(
		"force over existing",
		vec![srv(&[("/core.db", vec![file(&b)])])],
		|d, _| {
			let mut p = db_payload(d, "core.db", &[v("@0")]);
			p.force = true;
			vec![p]
		},
	)
	.setup(move |d| {
		let p = d.join("core.db");
		fs::write(&p, &old).unwrap();
		set_mtime(&p, T0);
	}));
	out.push(Scn::new(
		"chunked",
		vec![srv(&[(
			"/core.db",
			vec![Reply::Chunked {
				body: b.clone(),
				cut: false,
			}],
		)])],
		|d, _| vec![db_payload(d, "core.db", &[v("@0")])],
	));
	out.push(Scn::new(
		"chunked cut",
		vec![srv(&[(
			"/core.db",
			vec![Reply::Chunked {
				body: b.clone(),
				cut: true,
			}],
		)])],
		|d, _| vec![db_payload(d, "core.db", &[v("@0")])],
	));
	out.push(Scn::new(
		"redirect",
		vec![srv(&[
			(
				"/core.db",
				vec![Reply::Redirect(
					302,
					"/real/core.db".into(),
				)],
			),
			("/real/core.db", vec![file(&b)]),
		])],
		|d, _| vec![db_payload(d, "core.db", &[v("@0")])],
	));
	let mut chain = Vec::new();
	for i in 0..11 {
		chain.push((
			format!("/r{i}"),
			vec![Reply::Redirect(301, format!("/r{}", i + 1))],
		));
	}
	chain.push(("/r11".to_string(), vec![file(&b)]));
	let routes: Vec<(&str, Vec<Reply>)> =
		chain.iter().map(|(p, r)| (p.as_str(), r.clone())).collect();
	out.push(Scn::new("redirects 10", vec![srv(&routes)], |d, _| {
		vec![pkg_payload(d, "x", v("@0/r1"))]
	}));
	out.push(Scn::new("redirects 11", vec![srv(&routes)], |d, _| {
		vec![pkg_payload(d, "x", v("@0/r0"))]
	}));
	out.push(Scn::new(
		"close without reply then mirror",
		vec![
			srv(&[("/core.db", vec![Reply::Close])]),
			srv(&[("/core.db", vec![file(&b)])]),
		],
		|d, _| vec![db_payload(d, "core.db", &[v("@0"), v("@1")])],
	));
	let dead = format!("http://127.0.0.1:{}", closed_port());
	out.push(Scn::new(
		"connection refused then mirror",
		vec![srv(&[("/core.db", vec![file(&b)])])],
		move |d, _| {
			vec![db_payload(
				d,
				"core.db",
				&[dead.clone().into_bytes(), v("@0")],
			)]
		},
	));
	out.push(Scn::new(
		"max size below content-length",
		vec![srv(&[("/core.db", vec![file(&b)])])],
		|d, _| {
			let mut p = db_payload(d, "core.db", &[v("@0")]);
			p.max_size = 100;
			vec![p]
		},
	));
	out.push(Scn::new(
		"max size, chunked",
		vec![srv(&[(
			"/core.db",
			vec![Reply::Chunked {
				body: b.clone(),
				cut: false,
			}],
		)])],
		|d, _| {
			let mut p = db_payload(d, "core.db", &[v("@0")]);
			p.max_size = 100;
			vec![p]
		},
	));
	out.push(Scn::new(
		"max size, 404 page bigger",
		vec![srv(&[(
			"/core.db",
			vec![Reply::Status(404, big.clone())],
		)])],
		|d, _| {
			let mut p = db_payload(d, "core.db", &[v("@0")]);
			p.max_size = 100;
			vec![p]
		},
	));
	out.push(Scn::new(
		"signature",
		vec![srv(&[
			("/core.db", vec![file(&b)]),
			("/core.db.sig", vec![file(&b[..100])]),
		])],
		|d, _| {
			let mut p = db_payload(d, "core.db", &[v("@0")]);
			p.download_signature = true;
			vec![p]
		},
	));
	out.push(Scn::new(
		"signature missing, required",
		vec![srv(&[("/core.db", vec![file(&b)])])],
		|d, _| {
			let mut p = db_payload(d, "core.db", &[v("@0")]);
			p.download_signature = true;
			p.unlink_on_fail = true;
			vec![p]
		},
	));
	out.push(Scn::new(
		"signature missing, optional",
		vec![srv(&[("/core.db", vec![file(&b)])])],
		|d, _| {
			let mut p = db_payload(d, "core.db", &[v("@0")]);
			p.download_signature = true;
			p.signature_optional = true;
			p.unlink_on_fail = true;
			vec![p]
		},
	));
	out.push(Scn::new(
		"signature too big",
		vec![srv(&[
			("/core.db", vec![file(&b)]),
			("/core.db.sig", vec![file(&big)]),
		])],
		|d, _| {
			let mut p = db_payload(d, "core.db", &[v("@0")]);
			p.download_signature = true;
			vec![p]
		},
	));
	out.push(Scn::new(
		"signature after redirect",
		vec![srv(&[
			(
				"/core.db",
				vec![Reply::Redirect(
					302,
					"/x/core.db?a=b".into(),
				)],
			),
			("/x/core.db", vec![file(&b)]),
			("/x/core.db.sig", vec![file(&b[..64])]),
		])],
		|d, _| {
			let mut p = db_payload(d, "core.db", &[v("@0")]);
			p.download_signature = true;
			vec![p]
		},
	));
	out.push(Scn::new("optional failure", vec![srv(&[])], |d, _| {
		let mut p = db_payload(d, "core.db", &[v("@0")]);
		p.errors_ok = true;
		vec![p]
	}));
	out.push(Scn::new("no servers", vec![], |d, _| {
		vec![db_payload(d, "core.db", &[])]
	}));
	out.push(Scn::new("invalid url", vec![], |d, _| {
		vec![pkg_payload(d, "x", v("nohost"))]
	}));
	let src = big.clone();
	let repo = move |d: &Path| {
		fs::create_dir(d.join("repo")).unwrap();
		let f = d.join("repo/f.pkg.tar.zst");
		fs::write(&f, &src).unwrap();
		set_mtime(&f, T0);
		fs::write(d.join("repo/core.db"), &src[..3000]).unwrap();
		set_mtime(&d.join("repo/core.db"), T0 + 5);
	};
	let repo = std::rc::Rc::new(repo);
	let r = repo.clone();
	out.push(Scn::new("file url", vec![], |d, _| {
		vec![pkg_payload(
			d,
			"f.pkg.tar.zst",
			furl(d, "repo/f.pkg.tar.zst"),
		)]
	})
	.setup(move |d| r(d)));
	out.push(Scn::new("file url missing", vec![], |d, _| {
		vec![pkg_payload(d, "f.pkg.tar.zst", furl(d, "repo/nope"))]
	}));
	let (r, part) = (repo.clone(), big[..7000].to_vec());
	out.push(Scn::new("file url resume", vec![], |d, _| {
		vec![pkg_payload(
			d,
			"f.pkg.tar.zst",
			furl(d, "repo/f.pkg.tar.zst"),
		)]
	})
	.setup(move |d| {
		r(d);
		fs::write(d.join("f.pkg.tar.zst.part"), &part).unwrap();
	}));
	let (r, part) = (repo.clone(), [&big[..], b"xx"].concat());
	out.push(Scn::new("file url .part longer", vec![], |d, _| {
		vec![pkg_payload(
			d,
			"f.pkg.tar.zst",
			furl(d, "repo/f.pkg.tar.zst"),
		)]
	})
	.setup(move |d| {
		r(d);
		fs::write(d.join("f.pkg.tar.zst.part"), &part).unwrap();
	}));
	let (r, whole) = (repo.clone(), big.clone());
	out.push(Scn::new("file url .part complete", vec![], |d, _| {
		vec![pkg_payload(
			d,
			"f.pkg.tar.zst",
			furl(d, "repo/f.pkg.tar.zst"),
		)]
	})
	.setup(move |d| {
		r(d);
		fs::write(d.join("f.pkg.tar.zst.part"), &whole).unwrap();
	}));
	let r = repo.clone();
	out.push(Scn::new("404 then file mirror", vec![srv(&[])], |d, _| {
		let f = [b"file://", d, b"repo"].concat();
		vec![db_payload(d, "core.db", &[v("@0"), f])]
	})
	.setup(move |d| r(d)));
	let r = repo.clone();
	let dead = format!("http://127.0.0.1:{}", closed_port()).into_bytes();
	out.push(Scn::new("file mirror after refused", vec![], move |d, _| {
		let f = [b"file://", d, b"repo"].concat();
		vec![db_payload(d, "core.db", &[dead.clone(), f])]
	})
	.setup(move |d| r(d)));
	let (r, old) = (repo.clone(), b.clone());
	out.push(Scn::new(
		"404 then file mirror, time condition",
		vec![srv(&[])],
		|d, _| {
			let f = [b"file://", d, b"repo"].concat();
			vec![db_payload(d, "core.db", &[v("@0"), f])]
		},
	)
	.setup(move |d| {
		r(d);
		fs::write(d.join("core.db"), &old).unwrap();
	}));
	let (r, old) = (repo.clone(), b.clone());
	let cut = Reply::Truncated {
		body: big[..3000].to_vec(),
		sent: 2500,
	};
	out.push(Scn::new(
		"resume onto file mirror, time condition",
		vec![srv(&[("/core.db", vec![cut])])],
		|d, _| {
			let f = [b"file://", d, b"repo"].concat();
			let mut p = db_payload(d, "core.db", &[v("@0"), f]);
			p.allow_resume = true;
			vec![p]
		},
	)
	.setup(move |d| {
		r(d);
		fs::write(d.join("core.db"), &old).unwrap();
	}));
	let (r, old) = (repo.clone(), b.clone());
	out.push(Scn::new("file url time condition", vec![], |d, _| {
		let f = [b"file://", d, b"repo"].concat();
		vec![db_payload(d, "core.db", &[f])]
	})
	.setup(move |d| {
		r(d);
		fs::write(d.join("core.db"), &old).unwrap();
	}));
	let (r, old) = (repo.clone(), b.clone());
	out.push(Scn::new("file url newer than dest", vec![], |d, _| {
		let f = [b"file://", d, b"repo"].concat();
		vec![db_payload(d, "core.db", &[f])]
	})
	.setup(move |d| {
		r(d);
		fs::write(d.join("core.db"), &old).unwrap();
		set_mtime(&d.join("core.db"), T0);
	}));
	let r = repo.clone();
	out.push(Scn::new("file url max size", vec![], |d, _| {
		let mut p = pkg_payload(
			d,
			"f.pkg.tar.zst",
			furl(d, "repo/f.pkg.tar.zst"),
		);
		p.max_size = 1000;
		vec![p]
	})
	.setup(move |d| r(d)));
	out.push(Scn::new(
		"cache server 404, then server",
		vec![srv(&[]), srv(&[("/core.db", vec![file(&b)])])],
		|d, _| {
			let mut p = db_payload(d, "core.db", &[v("@1")]);
			p.cache_servers = vec![v("@0")];
			vec![p]
		},
	));
	out.push(Scn::new(
		"cache server ok",
		vec![srv(&[("/core.db", vec![file(&b)])]), srv(&[])],
		|d, _| {
			let mut p = db_payload(d, "core.db", &[v("@1")]);
			p.cache_servers = vec![v("@0")];
			vec![p]
		},
	));
	out.push(Scn::new(
		"optional, 404 then mirror",
		vec![srv(&[]), srv(&[("/core.db", vec![file(&b)])])],
		|d, _| {
			let mut p =
				db_payload(d, "core.db", &[v("@0"), v("@1")]);
			p.errors_ok = true;
			vec![p]
		},
	));
	out.push(Scn::new(
		"required fails, later payloads skipped",
		vec![srv(&[("/b.db", vec![file(&b)])])],
		|d, _| {
			let mut a = db_payload(d, "a.db", &[v("@0")]);
			a.max_size = 9;
			vec![a, db_payload(d, "b.db", &[v("@0")])]
		},
	));
	out.push(Scn::new(
		"sorted by max size",
		vec![srv(&[
			("/a.db", vec![file(&b)]),
			("/b.db", vec![file(&b)]),
			("/c.db", vec![file(&b)]),
		])],
		|d, _| {
			let mut ps: Vec<Payload> = ["a.db", "b.db", "c.db"]
				.iter()
				.map(|n| db_payload(d, n, &[v("@0")]))
				.collect();
			ps[0].max_size = 5000;
			ps[2].max_size = 9000;
			ps
		},
	));
	let stall = Reply::Stall {
		body: b.clone(),
		at: 100,
		pause: Duration::from_millis(300),
		finish: true,
	};
	out.push(Scn::new(
		"parallel 2 of 5",
		vec![srv(&[
			("/a.db", vec![stall.clone()]),
			("/b.db", vec![stall.clone()]),
			("/c.db", vec![stall.clone()]),
			("/d.db", vec![stall.clone()]),
			("/e.db", vec![stall.clone()]),
			("/a.db.sig", vec![file(&b[..10])]),
		])],
		|d, _| {
			let mut ps: Vec<Payload> =
				["a.db", "b.db", "c.db", "d.db", "e.db"]
					.iter()
					.map(|n| db_payload(d, n, &[v("@0")]))
					.collect();
			ps[0].download_signature = true;
			ps
		},
	)
	.parallel(2));
	out.push(Scn::new(
		"parallel 4, one failing",
		vec![srv(&[
			("/a.db", vec![stall.clone()]),
			("/b.db", vec![st(500)]),
			("/c.db", vec![stall.clone()]),
		])],
		|d, _| {
			["a.db", "b.db", "c.db"]
				.iter()
				.map(|n| db_payload(d, n, &[v("@0")]))
				.collect()
		},
	)
	.parallel(4));
	out.push(Scn::new(
		"unlink on fail, 500",
		vec![srv(&[("/core.db", vec![st(500)])])],
		|d, _| {
			let mut p = db_payload(d, "core.db", &[v("@0")]);
			p.unlink_on_fail = true;
			vec![p]
		},
	));
	out
}

fn furl(d: &[u8], rel: &str) -> Vec<u8> {
	[b"file://", d, rel.as_bytes()].concat()
}

fn set_mtime(p: &Path, t: i64) {
	let f = fs::File::options().write(true).open(p).unwrap();
	let t = std::time::UNIX_EPOCH + Duration::from_secs(t as u64);
	f.set_times(fs::FileTimes::new().set_modified(t).set_accessed(t))
		.unwrap();
}

// the fields that differ, file contents as length and first byte
fn explain(c: &Outcome, r: &Outcome) -> String {
	let mut out = String::new();
	let files = |o: &Outcome| {
		o.files.iter()
			.map(|(n, d, m, t)| {
				let n = String::from_utf8_lossy(n).into_owned();
				(n, d.len(), *m, *t)
			})
			.collect::<Vec<_>>()
	};
	let logs = |o: &Outcome| {
		o.logs.iter()
			.map(|(l, m)| {
				format!("{l:?} {}", String::from_utf8_lossy(m))
			})
			.collect::<Vec<_>>()
	};
	let ev = |o: &Outcome| {
		o.downloads
			.iter()
			.map(|(n, e)| {
				format!("{} {e:?}", String::from_utf8_lossy(n))
			})
			.collect::<Vec<_>>()
	};
	if (c.ret, c.errno) != (r.ret, r.errno) {
		out += &format!(
			"ret C {} {} R {} {}\n",
			c.ret, c.errno, r.ret, r.errno
		);
	}
	if c.downloads != r.downloads {
		out += &format!(
			"events C {:#?}\nevents R {:#?}\n",
			ev(c),
			ev(r)
		);
	}
	if c.logs != r.logs {
		out += &format!(
			"logs C {:#?}\nlogs R {:#?}\n",
			logs(c),
			logs(r)
		);
	}
	if c.files != r.files {
		out += &format!(
			"files C {:?}\nfiles R {:?}\n",
			files(c),
			files(r)
		);
	}
	if c.peak != r.peak {
		out += &format!("peak C {} R {}\n", c.peak, r.peak);
	}
	if c.requests != r.requests {
		out += &format!(
			"req C {:#?}\nreq R {:#?}\n",
			c.requests, r.requests
		);
	}
	out
}

#[test]
fn fixed_cases() {
	compare_all(scenarios());
}

fn compare_all(scns: Vec<Scn>) {
	let mut bad = Vec::new();
	for s in scns {
		let (c, r) = s.run();
		if c != r {
			eprintln!("== {}\n{}", s.name, explain(&c, &r));
			bad.push(s.name.clone());
		}
	}
	assert!(bad.is_empty(), "mismatches: {bad:?}");
}

const STYLES: [(Style, &str); 5] = [
	(Style::Close, "close"),
	(Style::Drop, "drop"),
	(Style::KeepAlive, "keep-alive"),
	(Style::Http10, "http/1.0"),
	(Style::Stale, "stale"),
];

fn redir(code: u16, to: &str) -> Reply {
	Reply::Redirect(code, to.to_string())
}

fn with_sig(mut p: Payload) -> Vec<Payload> {
	p.download_signature = true;
	vec![p]
}

// redirects per connection style: Drop is pactest's server, where a
// connection kept for the next hop or the .sig is already closed
fn styled_redirects(out: &mut Vec<Scn>, style: Style, sname: &str) {
	let b = body(3000, 4);
	let sig = body(64, 5);
	for code in [301, 302, 303, 307, 308] {
		let s = styled(
			style,
			&[
				(
					"/core.db",
					vec![redir(code, "/real/core.db")],
				),
				("/real/core.db", vec![file(&b)]),
				("/real/core.db.sig", vec![file(&sig)]),
			],
		);
		out.push(Scn::new(
			format!("{sname} {code}"),
			vec![s],
			|d, _| with_sig(db_payload(d, "core.db", &[v("@0")])),
		));
	}
	// upgrade-download-pkg-and-sig-with-filename: the .sig url comes
	// from the effective url only when its name has .pkg (or the dbext)
	let s = styled(
		style,
		&[
			("/redir.pkg", vec![redir(303, "/redir-dest.pkg")]),
			("/redir-dest.pkg", vec![file(&b)]),
			("/redir-dest.pkg.sig", vec![file(&sig)]),
			("/cdn.pkg", vec![redir(303, "/cdn-1")]),
			("/cdn.pkg.sig", vec![redir(303, "/cdn-2")]),
			("/cdn-1", vec![file(&b[..2000])]),
			("/cdn-2", vec![file(&sig[..32])]),
			("/cdn-1.sig", vec![file(&sig[..16])]),
		],
	);
	out.push(Scn::new(format!("{sname} pkg sig"), vec![s], |d, _| {
		let mut ps = with_sig(pkg_payload(
			d,
			"redir.pkg",
			v("@0/redir.pkg"),
		));
		ps.extend(with_sig(pkg_payload(d, "cdn.pkg", v("@0/cdn.pkg"))));
		ps
	}));
	let s = styled(
		style,
		&[
			("/r0", vec![redir(302, "/r1")]),
			("/r1", vec![redir(307, "r2")]),
			("/r2", vec![redir(308, "/x/r3")]),
			("/x/r3", vec![file(&b)]),
		],
	);
	out.push(Scn::new(format!("{sname} chain"), vec![s], |d, _| {
		vec![pkg_payload(d, "x", v("@0/r0"))]
	}));
	let s = styled(
		style,
		&[
			("/core.db", vec![Reply::Unsized(b.clone())]),
			("/core.db.sig", vec![Reply::Unsized(sig.clone())]),
		],
	);
	out.push(Scn::new(format!("{sname} unsized"), vec![s], |d, _| {
		with_sig(db_payload(d, "core.db", &[v("@0")]))
	}));
	let s = styled(style, &[("/x", vec![Reply::Unsized(b.clone())])]);
	out.push(Scn::new(
		format!("{sname} unsized, max"),
		vec![s],
		|d, _| {
			let mut p = pkg_payload(d, "x", v("@0/x"));
			p.max_size = 100;
			vec![p]
		},
	));
	// two files and their .sigs in a row: curl keeps the connection
	let s = styled(
		style,
		&[
			("/core.db", vec![file(&b)]),
			("/core.db.sig", vec![file(&sig)]),
			("/extra.db", vec![redir(302, "/real/extra.db")]),
			("/real/extra.db", vec![file(&b[..1000])]),
		],
	);
	out.push(Scn::new(
		format!("{sname} two in a row"),
		vec![s],
		|d, _| {
			let mut ps =
				with_sig(db_payload(d, "core.db", &[v("@0")]));
			ps.extend(with_sig(db_payload(
				d,
				"extra.db",
				&[v("@0")],
			)));
			ps
		},
	));
	let s = styled(
		style,
		&[
			("/core.db", vec![redir(302, "/gone")]),
			("/gone", vec![st(404)]),
		],
	);
	let m = styled(style, &[("/core.db", vec![file(&b)])]);
	out.push(Scn::new(
		format!("{sname} redirect to 404, mirror"),
		vec![s, m],
		|d, _| vec![db_payload(d, "core.db", &[v("@0"), v("@1")])],
	));
}

// redirect loops end at curl's 10 follows. on a Drop or Stale server
// every hop reuses a dead connection in curl: see drop_loop_divergence
fn redirect_loops(out: &mut Vec<Scn>, style: Style, sname: &str) {
	let s = styled(
		style,
		&[
			("/a", vec![redir(302, "/b")]),
			("/b", vec![redir(301, "/a")]),
		],
	);
	out.push(Scn::new(format!("{sname} loop"), vec![s], |d, _| {
		vec![pkg_payload(d, "x", v("@0/a"))]
	}));
	let s = styled(style, &[("/s", vec![redir(303, "/s")])]);
	out.push(Scn::new(format!("{sname} self loop"), vec![s], |d, _| {
		vec![pkg_payload(d, "x", v("@0/s"))]
	}));
}

// redirects to other hosts, odd redirect responses, Content-Disposition
fn other_redirects(out: &mut Vec<Scn>) {
	let b = body(3000, 6);
	let sig = body(64, 7);
	for (style, sname) in [STYLES[0], STYLES[1]] {
		let s0 = Server::start_styled(style);
		let s1 = styled(
			style,
			&[
				("/mirror/core.db", vec![file(&b)]),
				("/mirror/core.db.sig", vec![file(&sig)]),
				("/blob/7", vec![file(&b)]),
				("/blob/8", vec![file(&sig[..20])]),
			],
		);
		let to = |p: &str| format!("{}{p}", s1.base());
		s0.route("/core.db", vec![redir(302, &to("/mirror/core.db"))]);
		s0.route("/extra.db", vec![redir(303, &to("/blob/7"))]);
		s0.route("/extra.db.sig", vec![redir(303, &to("/blob/8"))]);
		out.push(Scn::new(
			format!("{sname} other host"),
			vec![s0, s1],
			|d, _| {
				let mut ps = with_sig(db_payload(
					d,
					"core.db",
					&[v("@0")],
				));
				ps.extend(with_sig(db_payload(
					d,
					"extra.db",
					&[v("@0")],
				)));
				ps
			},
		));
	}
	let dead = format!("http://127.0.0.1:{}/core.db", closed_port());
	let s = srv(&[("/core.db", vec![redir(302, &dead)])]);
	let m = srv(&[("/core.db", vec![file(&b)])]);
	out.push(Scn::new("redirect to closed port", vec![s, m], |d, _| {
		vec![db_payload(d, "core.db", &[v("@0"), v("@1")])]
	}));
	let raw = |h: &str| Reply::Raw(h.as_bytes().to_vec());
	let no_loc = "HTTP/1.1 302 Found\r\nConnection: close\r\n\
		Content-Length: 0\r\n\r\n";
	let s = srv(&[("/core.db", vec![raw(no_loc)])]);
	out.push(Scn::new("redirect without location", vec![s], |d, _| {
		vec![db_payload(d, "core.db", &[v("@0")])]
	}));
	let s = srv(&[(
		"/core.db",
		vec![redir(302, "file:///nonexistent/core.db")],
	)]);
	out.push(Scn::new("redirect to file://", vec![s], |d, _| {
		vec![db_payload(d, "core.db", &[v("@0")])]
	}));
	// disabled and unknown schemes
	for to in ["foo://x/core.db", "ws://nohost.invalid/", "dict://x/d"] {
		let s = srv(&[("/core.db", vec![redir(302, to)])]);
		out.push(Scn::new(
			format!("redirect to {to}"),
			vec![s],
			|d, _| vec![db_payload(d, "core.db", &[v("@0")])],
		));
	}
	let s = srv(&[(
		"/core.db",
		vec![redir(302, "http://nohost.invalid/core.db")],
	)]);
	let m = srv(&[("/core.db", vec![file(&b)])]);
	out.push(Scn::new("redirect to unknown host", vec![s, m], |d, _| {
		vec![db_payload(d, "core.db", &[v("@0"), v("@1")])]
	}));
	// 3xx codes reqwest does not follow
	for code in [300, 304, 305, 306, 399] {
		let s = srv(&[
			("/core.db", vec![redir(code, "/real/core.db")]),
			("/real/core.db", vec![file(&b)]),
		]);
		out.push(Scn::new(
			format!("redirect {code}"),
			vec![s],
			|d, _| vec![db_payload(d, "core.db", &[v("@0")])],
		));
	}
	let moved = "HTTP/1.1 301 Moved Permanently\r\nConnection: close\r\n\
		Location: /real/core.db\r\nContent-Length: 11\r\n\r\nmoved here\n";
	let s = srv(&[
		("/core.db", vec![raw(moved)]),
		("/real/core.db", vec![file(&b)]),
	]);
	out.push(Scn::new("redirect with a body", vec![s], |d, _| {
		vec![db_payload(d, "core.db", &[v("@0")])]
	}));
	let moved10 = "HTTP/1.0 302 Found\r\nLocation: /real/core.db\r\n\
		\r\nmoved here, no length\n";
	let s = srv(&[
		("/core.db", vec![raw(moved10)]),
		("/real/core.db", vec![file(&b)]),
	]);
	out.push(Scn::new("http/1.0 redirect, unsized", vec![s], |d, _| {
		vec![db_payload(d, "core.db", &[v("@0")])]
	}));
	// libalpm ignores Content-Disposition: names come from the url
	let cd = |n: &str| {
		vec![format!(
			"Content-Disposition: attachment; filename=\"{n}\""
		)]
	};
	let s = styled(
		Style::Drop,
		&[
			("/cd.pkg", vec![redir(303, "/cdn-3")]),
			("/cd.pkg.sig", vec![redir(303, "/cdn-4")]),
			(
				"/cdn-3",
				vec![Reply::Headers(cd("alt.pkg"), b.clone())],
			),
			(
				"/cdn-4",
				vec![Reply::Headers(
					cd("alt.pkg.sig"),
					sig.clone(),
				)],
			),
			(
				"/core.db",
				vec![Reply::Headers(cd("x.db"), b.clone())],
			),
			(
				"/core.db.sig",
				vec![Reply::Headers(cd("y"), sig.clone())],
			),
		],
	);
	out.push(Scn::new("content-disposition", vec![s], |d, _| {
		let mut ps = with_sig(pkg_payload(d, "cd.pkg", v("@0/cd.pkg")));
		ps.extend(with_sig(db_payload(d, "core.db", &[v("@0")])));
		ps
	}));
}

#[test]
fn redirect_cases() {
	let mut out = Vec::new();
	for (style, sname) in STYLES {
		styled_redirects(&mut out, style, sname);
		if !matches!(style, Style::Drop | Style::Stale) {
			redirect_loops(&mut out, style, sname);
		}
	}
	other_redirects(&mut out);
	compare_all(out);
}

// pinned divergence: curl counts a reconnect for every hop that reused a
// connection the server had closed, without reset between hops
// (Curl_retry_request, at most 5), so on a server that promises
// keep-alive and closes, the 6th same-host hop fails. the port never
// reuses a connection and follows all 10
// the error lines of an outcome, its debug lines left out
fn errors(o: &Outcome) -> Vec<&[u8]> {
	let e = o.logs.iter().filter(|l| l.0 == LogLevel::Error);
	e.map(|l| &l.1[..]).collect()
}

#[test]
fn drop_loop_divergence() {
	let s = styled(
		Style::Drop,
		&[
			("/a", vec![redir(302, "/b")]),
			("/b", vec![redir(301, "/a")]),
		],
	);
	let scn = Scn::new("drop loop", vec![s], |d, _| {
		vec![pkg_payload(d, "x", v("@0/a"))]
	});
	let (c, r) = scn.run();
	let tail = |o: &Outcome| {
		let m = String::from_utf8_lossy(errors(o)[0]).into_owned();
		(o.requests.len(), m.split(" : ").nth(1).map(str::to_string))
	};
	let died = "Connection died, tried 5 times before giving up\n";
	let max = "Maximum (10) redirects followed\n";
	assert_eq!(tail(&c), (6, Some(died.to_string())));
	assert_eq!(tail(&r), (11, Some(max.to_string())));
	assert_eq!((c.ret, c.files.len()), (r.ret, r.files.len()));
}

// Rust only (curl's CURLAUTH_ANY waits for a 401): url credentials go
// along a redirect on the same scheme, host and port, not elsewhere
#[test]
fn redirect_auth() {
	let b = body(500, 8);
	let other = srv(&[("/core.db", vec![file(&b)])]);
	let s = srv(&[
		("/same", vec![redir(302, "/core.db")]),
		("/core.db", vec![file(&b)]),
		(
			"/away",
			vec![redir(302, &format!("{}/core.db", other.base()))],
		),
	]);
	let creds = |p: &str| {
		format!("http://u:p%40ss@127.0.0.1:{}{p}", s.port())
			.into_bytes()
	};
	let fx = TempRoot::new("dload-auth");
	let dir = dir_bytes(fx.dir());
	let mut ps = vec![
		pkg_payload(&dir, "a", creds("/same")),
		pkg_payload(&dir, "b", creds("/away")),
	];
	let settings = Settings::default();
	let mut state = DownloadState::default();
	let mut rec = Recorder::default();
	let mut dl = Downloader {
		settings: &settings,
		state: &mut state,
		cb: &mut rec,
		fetch: None,
		sandbox: None,
	};
	assert_eq!(dl.download(&mut ps, &dir, &dir), Ok(true));
	let auth = |s: &Server| {
		s.requests()
			.into_iter()
			.map(|q| (q.path, q.auth))
			.collect::<Vec<_>>()
	};
	// base64("u:p@ss")
	let basic = Some("Basic dTpwQHNz".to_string());
	let want = vec![
		("/same".to_string(), basic.clone()),
		("/core.db".to_string(), basic.clone()),
		("/away".to_string(), basic),
	];
	assert_eq!(auth(&s), want);
	assert_eq!(auth(&other), vec![("/core.db".to_string(), None)]);
}

// pinned divergence: a chunked HTTP/1.0 response is decoded by curl and
// a parse error to hyper (RFC 9112 6.1: faulty framing), no hyper option
// allows it
#[test]
fn http10_chunked_divergence() {
	let b = body(3000, 9);
	let s = styled(
		Style::Http10,
		&[(
			"/core.db",
			vec![Reply::Chunked {
				body: b.clone(),
				cut: false,
			}],
		)],
	);
	let scn = Scn::new("http/1.0 chunked", vec![s], |d, _| {
		vec![db_payload(d, "core.db", &[v("@0")])]
	});
	let (c, r) = scn.run();
	assert_eq!((c.ret, errors(&c).len()), (0, 0));
	assert_eq!(c.files[0].1, b);
	assert_eq!((r.ret, r.files.len()), (-1, 0));
	let m = String::from_utf8_lossy(errors(&r)[0]).into_owned();
	assert!(m.contains(" : Recv failure: "), "{m}");
}

// the fetchcb path: payloads over cache servers/servers or one url, a
// script deciding each fetch by url; ret, pm_errno and every call compared
fn fetch_case(rng: &mut Rng) -> (Vec<(Vec<u8>, c_int)>, MkPayloads) {
	let hosts: Vec<Vec<u8>> = (0..3)
		.map(|i| format!("http://m{i}.example").into_bytes())
		.collect();
	let n = 1 + rng.below(4);
	let mut specs = Vec::new();
	let mut table = Vec::new();
	for i in 0..n {
		let name = format!("f{i}.pkg");
		let by_url = rng.below(3) == 0;
		let cache: Vec<Vec<u8>> =
			hosts[..rng.below(2)].iter().rev().cloned().collect();
		let servers: Vec<Vec<u8>> = hosts[..rng.below(4)].to_vec();
		let flags = rng.next_u64();
		specs.push((
			name.clone(),
			by_url,
			cache.clone(),
			servers.clone(),
			flags,
		));
		let mut urls =
			vec![format!("http://u.example/{name}").into_bytes()];
		for h in cache.iter().chain(&servers) {
			urls.push([&h[..], b"/", name.as_bytes()].concat());
		}
		for u in urls {
			let ret = [-1, 0, 1][rng.below(3)];
			let rets = [-1, 0, 1][rng.below(3)];
			table.push((u.clone(), ret));
			table.push(([&u[..], b".sig"].concat(), rets));
		}
	}
	let mk = move |d: &[u8]| {
		specs.iter()
			.map(|(name, by_url, cache, servers, flags)| {
				let mut p = if *by_url {
					let u = format!(
						"http://u.example/{name}"
					)
					.into_bytes();
					pkg_payload(d, name, u)
				} else {
					let mut p =
						db_payload(d, name, servers);
					p.cache_servers = cache.clone();
					p
				};
				p.force = flags & 1 != 0;
				p.errors_ok = flags & 2 != 0;
				p.download_signature = flags & 4 != 0;
				p.signature_optional = flags & 8 != 0;
				p
			})
			.collect()
	};
	(table, Box::new(mk))
}

fn script(table: Vec<(Vec<u8>, c_int)>) -> Fetcher {
	Fetcher::new(Box::new(move |url, _, _| {
		table.iter().find(|(u, _)| u == url).map_or(-1, |(_, r)| *r)
	}))
}

fn strip_dir(
	calls: Vec<(Vec<u8>, Vec<u8>, bool)>,
	dir: &[u8],
) -> Vec<(Vec<u8>, Vec<u8>, bool)> {
	calls.into_iter()
		.map(|(u, l, f)| (u, norm_log(&l, dir), f))
		.collect()
}

#[test]
fn fetchcb_fuzz() {
	let mut rng = Rng::new(0xfe7c);
	let fx = TempRoot::new("dload-fetch");
	let dir = dir_bytes(fx.dir());
	for i in 0..(iters() / 100).max(200) {
		let (table, mk) = fetch_case(&mut rng);
		let _umask = umask_lock();
		let mut h = CDload::new(&fx);
		h.set_fetch(Some(script(table.clone())));
		let (cret, cerr, crec) = h.download(&mk(&dir), &dir, &dir);
		let ccalls = strip_dir(h.set_fetch(None).unwrap().calls, &dir);
		drop(h);
		let settings = Settings::default();
		let mut state = DownloadState::default();
		let mut rec = Recorder::default();
		let mut f = script(table);
		let mut dl = Downloader {
			settings: &settings,
			state: &mut state,
			cb: &mut rec,
			fetch: Some(&mut f),
			sandbox: None,
		};
		let (rret, rerr) =
			rust_ret(dl.download(&mut mk(&dir), &dir, &dir));
		let rcalls = strip_dir(f.calls, &dir);
		let cerr = if cret == -1 { cerr } else { 0 };
		assert_eq!(
			(cret, cerr, &ccalls, &crec),
			(rret, rerr, &rcalls, &rec.0),
			"case {i}"
		);
	}
}

// alpm_fetch_pkgurl: cached files, downloads into the cachedir (a
// missing first cachedir is created), siglevels, temp names for urls
// without a package name; the Rust side plain and in the sandbox helper
// (the C sandbox needs real root)
#[test]
fn fetch_pkgurl_cases() {
	let s = Server::start();
	let b = body(5000, 3);
	s.route("/a-1-1-x86_64.pkg.tar.zst", vec![file(&b)]);
	s.route("/a-1-1-x86_64.pkg.tar.zst.sig", vec![file(&b[..90])]);
	s.route("/b-1-1-any.pkg.tar.xz", vec![file(&b[..4000])]);
	s.route("/download", vec![file(&b[..3000])]);
	s.route("/download.sig", vec![file(&b[..80])]);
	let u = |p: &str| s.url(p);
	let cases: Vec<(&str, Vec<Vec<u8>>, c_int, bool)> = vec![
		("one pkg", vec![u("/a-1-1-x86_64.pkg.tar.zst")], 0, false),
		(
			"two pkgs",
			vec![
				u("/a-1-1-x86_64.pkg.tar.zst"),
				u("/b-1-1-any.pkg.tar.xz"),
			],
			0,
			false,
		),
		("cached", vec![u("/c-1-1-any.pkg.tar.zst")], 0, true),
		(
			"cached, sig wanted",
			vec![u("/c-1-1-any.pkg.tar.zst")],
			1,
			true,
		),
		(
			"sig required",
			vec![u("/a-1-1-x86_64.pkg.tar.zst")],
			1,
			false,
		),
		(
			"sig required, missing",
			vec![u("/b-1-1-any.pkg.tar.xz")],
			1,
			false,
		),
		(
			"sig optional, missing",
			vec![u("/b-1-1-any.pkg.tar.xz")],
			3,
			false,
		),
		("404", vec![u("/nope-1-1-any.pkg.tar.zst")], 0, false),
		("no package name", vec![u("/download")], 0, false),
		("no package name, sig", vec![u("/download")], 1, false),
		("no package name, 404", vec![u("/gone")], 0, false),
		("trailing slash", vec![u("/x/")], 0, false),
		(
			"mixed",
			vec![
				u("/c-1-1-any.pkg.tar.zst"),
				u("/download"),
				u("/b-1-1-any.pkg.tar.xz"),
			],
			0,
			true,
		),
	];
	// each case plain and through the sandbox helper (pretend root)
	for (name, urls, level, cached) in cases {
		for sandboxed in [false, true] {
			compare_pkgurl(
				&s, name, &urls, level, cached, sandboxed,
			);
		}
	}
}

// upgrade-download-pkg-and-sig-with-filename's map per connection style:
// 303s to the same names and cdn-style names, Content-Disposition, a 404
#[test]
fn fetch_pkgurl_redirects() {
	let cd = |n: &str, b: &str| {
		let h = format!(
			"Content-Disposition: attachment; filename=\"{n}\""
		);
		Reply::Headers(vec![h], b.as_bytes().to_vec())
	};
	let txt = |b: &str| file(b.as_bytes());
	let routes = [
		("/simple.pkg", vec![txt("simple")]),
		("/simple.pkg.sig", vec![cd("simple.sig-alt", "simple.sig")]),
		("/cd.pkg", vec![cd("cd-alt.pkg", "cd")]),
		("/cd.pkg.sig", vec![txt("cd.sig")]),
		("/redir.pkg", vec![redir(303, "/redir-dest.pkg")]),
		("/redir-dest.pkg", vec![txt("redir-dest")]),
		("/redir-dest.pkg.sig", vec![txt("redir-dest.sig")]),
		("/redir-cdn.pkg", vec![redir(303, "/cdn-1")]),
		("/redir-cdn.pkg.sig", vec![redir(303, "/cdn-2")]),
		("/cdn-1", vec![txt("redir-dest")]),
		("/cdn-2", vec![txt("redir-dest.sig")]),
		("/cd-redir-cdn.pkg", vec![redir(303, "/cdn-3")]),
		("/cd-redir-cdn.pkg.sig", vec![redir(303, "/cdn-4")]),
		("/cdn-3", vec![cd("cdn-alt.pkg", "cdn-alt")]),
		("/cdn-4", vec![cd("cdn-alt.pkg.sig", "cdn-alt.sig")]),
	];
	let paths = [
		"/simple.pkg",
		"/cd.pkg",
		"/redir.pkg",
		"/redir-cdn.pkg",
		"/cd-redir-cdn.pkg",
		"/404",
	];
	for (style, sname) in STYLES {
		let s = styled(style, &routes);
		let urls: Vec<Vec<u8>> =
			paths.iter().map(|p| s.url(p)).collect();
		for level in [0, 1, 3] {
			let name = format!("{sname} level {level}");
			compare_pkgurl(&s, &name, &urls, level, false, false);
			let name = format!("{sname} level {level}, no 404");
			let ok = &urls[..urls.len() - 1];
			compare_pkgurl(&s, &name, ok, level, false, false);
		}
	}
}

// one alpm_fetch_pkgurl call per side, from fresh cachedirs ("missing"
// does not exist, "cache" holds c-1-1-any.pkg.tar.zst when cached)
fn compare_pkgurl(
	s: &Server,
	name: &str,
	urls: &[Vec<u8>],
	level: c_int,
	cached: bool,
	sandboxed: bool,
) {
	let _umask = umask_lock();
	let fx = TempRoot::new("dload-pkgurl");
	let side = |tag: &str| {
		let base = fx.dir().join(tag);
		fs::create_dir(&base).unwrap();
		let cache = base.join("cache");
		if cached {
			fs::create_dir(&cache).unwrap();
			fs::write(
				cache.join("c-1-1-any.pkg.tar.zst"),
				b"cached",
			)
			.unwrap();
		}
		vec![dir_bytes(&base.join("missing")), dir_bytes(&cache)]
	};
	let (cdirs, rdirs) = (side("c"), side("r"));
	let c = {
		let mut h = CDload::new(&fx);
		h.set_remote_file_siglevel(level);
		for d in &cdirs {
			h.add_cachedir(d);
		}
		let (ret, errno, got, rec) = h.fetch_pkgurl(urls);
		let dirs = h.cachedirs();
		pkgurl_outcome(
			ret,
			errno,
			got,
			rec,
			dirs,
			&fx.dir().join("c"),
			s,
		)
	};
	let r = {
		let settings = Settings::default();
		let mut state = DownloadState::default();
		let mut rec = Recorder::default();
		let mut helper = test_helper(b"root", false, false);
		let mut dl = Downloader {
			settings: &settings,
			state: &mut state,
			cb: &mut rec,
			fetch: None,
			sandbox: sandboxed.then_some(&mut helper as _),
		};
		let mut dirs = rdirs.clone();
		let (ret, errno, got) =
			match dl.fetch_pkgurl(&mut dirs, level, urls) {
				Ok(g) => (0, 0, g),
				Err(e) => (-1, e as c_int, Vec::new()),
			};
		if sandboxed {
			unsandbox(&mut rec.0.logs);
		}
		pkgurl_outcome(
			ret,
			errno,
			got,
			rec.0,
			dirs,
			&fx.dir().join("r"),
			s,
		)
	};
	assert_eq!(c, r, "case {name}, sandboxed {sandboxed}");
}

// alpmtmp.XXXXXX names are random on both sides
fn norm_tmp(b: &[u8]) -> Vec<u8> {
	let mut out = b.to_vec();
	let pat = b"alpmtmp.";
	let mut i = 0;
	while i + pat.len() + 6 <= out.len() {
		if &out[i..i + pat.len()] == pat {
			out[i + pat.len()..i + pat.len() + 6]
				.copy_from_slice(b"XXXXXX");
			i += pat.len() + 6;
		} else {
			i += 1;
		}
	}
	out
}

type PkgurlOutcome = (
	c_int,
	c_int,
	Vec<Vec<u8>>,
	Record,
	Vec<Vec<u8>>,
	Vec<(Vec<u8>, Files)>,
	Vec<Req>,
);

fn pkgurl_outcome(
	ret: c_int,
	errno: c_int,
	got: Vec<Vec<u8>>,
	mut rec: Record,
	dirs: Vec<Vec<u8>>,
	base: &Path,
	s: &Server,
) -> PkgurlOutcome {
	let d = dir_bytes(base);
	let n = |b: &[u8]| norm_tmp(&norm_log(b, &d));
	rec.downloads = reduce_progress(&rec.downloads)
		.into_iter()
		.map(|(f, e)| (n(&f), e))
		.collect();
	rec.logs = rec.logs.iter().map(|(l, m)| (*l, n(m))).collect();
	let mut trees = Vec::new();
	for sub in ["missing", "cache"] {
		let files = snapshot(&base.join(sub))
			.into_iter()
			.map(|(f, data, m, t)| (norm_tmp(&f), data, m, t))
			.collect();
		trees.push((sub.as_bytes().to_vec(), files));
	}
	let reqs = s.requests();
	s.reset();
	let got = got.iter().map(|g| n(g)).collect();
	let dirs = dirs.iter().map(|g| n(g)).collect();
	(
		ret,
		if ret == -1 { errno } else { 0 },
		got,
		rec,
		dirs,
		trees,
		reqs,
	)
}

// _alpm_filecache_find/_setup and the dir helpers on odd cachedirs
#[test]
fn filecache_and_dirs() {
	// _alpm_makepath runs under umask(0)
	let _umask = umask_lock();
	let fx = TempRoot::new("dload-cache");
	let mk = |tag: &str| {
		let b = fx.dir().join(tag);
		fs::create_dir_all(b.join("dir/pkg.tar.zst")).unwrap();
		fs::create_dir_all(b.join("ro")).unwrap();
		fs::create_dir_all(b.join("nobits")).unwrap();
		fs::create_dir_all(b.join("ok")).unwrap();
		fs::write(b.join("ok/pkg.tar.zst"), b"x").unwrap();
		fs::write(b.join("file"), b"x").unwrap();
		fs::set_permissions(
			b.join("ro"),
			fs::Permissions::from_mode(0o555),
		)
		.unwrap();
		fs::set_permissions(
			b.join("nobits"),
			fs::Permissions::from_mode(0o555),
		)
		.unwrap();
		let t = b.join("tmpdir");
		fs::create_dir_all(t.join("sub")).unwrap();
		for f in ["a", "b.part", "c.sig"] {
			fs::write(t.join(f), f).unwrap();
		}
		b
	};
	let (cb, rb) = (mk("c"), mk("r"));
	let lists: Vec<Vec<&str>> = vec![
		vec!["ok"],
		vec!["dir", "ok"],
		vec!["missing/deep", "ok"],
		vec!["file", "ro", "ok"],
		vec!["file"],
		vec!["ro"],
	];
	for (i, names) in lists.iter().enumerate() {
		let dirs = |b: &Path| -> Vec<Vec<u8>> {
			names.iter()
				.map(|n| dir_bytes(&b.join(format!("{n}{i}"))))
				.collect()
		};
		// fresh copies per list: setup may create dirs
		for (b, _) in [(&cb, 0), (&rb, 1)] {
			for n in names {
				let src = b.join(n.split('/').next().unwrap());
				let dst = b.join(format!(
					"{}{i}",
					n.split('/').next().unwrap()
				));
				if src.exists() && !dst.exists() {
					copy_tree(&src, &dst);
				}
			}
		}
		let (cdirs, rdirs) = (dirs(&cb), dirs(&rb));
		let c = {
			let mut h = CDload::new(&fx);
			for d in &cdirs {
				h.add_cachedir(d);
			}
			let (found, frec) = h.filecache_find(b"pkg.tar.zst");
			let (setup, srec) = h.filecache_setup();
			let all = h.cachedirs();
			let tmp = h.download_dir_setup(&setup);
			let d = dir_bytes(&cb);
			let n = |v: &[u8]| norm_log(v, &d);
			let nr = |r: Record| -> Vec<_> {
				r.logs.iter().map(|(l, m)| (*l, n(m))).collect()
			};
			let all: Vec<_> = all.iter().map(|a| n(a)).collect();
			let found = found.map(|f| n(&f));
			(
				found,
				nr(frec),
				n(&setup),
				nr(srec),
				all,
				tmp.map(|t| n(&t)),
			)
		};
		let r = {
			let mut rec = Recorder::default();
			let mut all = rdirs.clone();
			let found = alpm_core::util::filecache_find(
				&all,
				b"pkg.tar.zst",
				&mut rec,
			);
			let frec = std::mem::take(&mut rec.0);
			let setup = alpm_core::util::filecache_setup(
				&mut all, &mut rec,
			);
			let srec = std::mem::take(&mut rec.0);
			let settings = Settings::default();
			let mut state = DownloadState::default();
			let mut dl = Downloader {
				settings: &settings,
				state: &mut state,
				cb: &mut rec,
				fetch: None,
				sandbox: None,
			};
			let tmp = dl.download_dir_setup(&setup).ok();
			let d = dir_bytes(&rb);
			let n = |v: &[u8]| norm_log(v, &d);
			let nr = |r: Record| -> Vec<_> {
				r.logs.iter().map(|(l, m)| (*l, n(m))).collect()
			};
			let all: Vec<_> = all.iter().map(|a| n(a)).collect();
			let found = found.map(|f| n(&f));
			(
				found,
				nr(frec),
				n(&setup),
				nr(srec),
				all,
				tmp.map(|t| n(&t)),
			)
		};
		assert_eq!(c, r, "cachedirs {names:?}");
	}
	// _alpm_remove_temporary_download_dir: files go, a subdir keeps it
	let h = CDload::new(&fx);
	h.remove_temporary_download_dir(&dir_bytes(&cb.join("tmpdir")));
	drop(h);
	alpm_core::dload::remove_temporary_download_dir(&dir_bytes(
		&rb.join("tmpdir"),
	));
	assert_eq!(tree(&cb.join("tmpdir")), tree(&rb.join("tmpdir")));
	fs::remove_dir(cb.join("tmpdir/sub")).unwrap();
	fs::remove_dir(rb.join("tmpdir/sub")).unwrap();
	let h = CDload::new(&fx);
	h.remove_temporary_download_dir(&dir_bytes(&cb.join("tmpdir")));
	drop(h);
	alpm_core::dload::remove_temporary_download_dir(&dir_bytes(
		&rb.join("tmpdir"),
	));
	assert_eq!(cb.join("tmpdir").exists(), rb.join("tmpdir").exists());
	assert!(!cb.join("tmpdir").exists());
	for b in [&cb, &rb] {
		for n in fs::read_dir(b).unwrap().flatten() {
			let _ = fs::set_permissions(
				n.path(),
				fs::Permissions::from_mode(0o755),
			);
		}
	}
}

fn copy_tree(src: &Path, dst: &Path) {
	let md = fs::metadata(src).unwrap();
	if md.is_dir() {
		fs::create_dir(dst).unwrap();
		for e in fs::read_dir(src).unwrap().flatten() {
			copy_tree(&e.path(), &dst.join(e.file_name()));
		}
		fs::set_permissions(dst, md.permissions()).unwrap();
	} else {
		fs::copy(src, dst).unwrap();
	}
}

fn tree(p: &Path) -> Vec<Vec<u8>> {
	let mut out = Vec::new();
	if let Ok(rd) = fs::read_dir(p) {
		for e in rd.flatten() {
			out.push(e.file_name().as_bytes().to_vec());
		}
	}
	out.sort();
	out
}

// curl's low-speed abort and disable_dl_timeout: no response for 11 s
// times out on both sides (10 s rule, before any byte), a 12 s stall
// with the timeout off finishes. slow: about 45 s
#[test]
fn low_speed_timeout() {
	let b = body(3000, 4);
	let s = srv(&[
		("/hang.db", vec![Reply::Hang(Duration::from_secs(11))]),
		("/core.db", vec![file(&b)]),
	]);
	let mk = |d: &[u8]| vec![db_payload(d, "hang.db", &[s.url("")])];
	let case = Case {
		servers: vec![&s],
		payloads: &mk,
		setup: &no_setup,
		parallel: 1,
		disable_timeout: false,
		sorted: false,
	};
	let (c, r) = run(&case);
	assert_eq!(c, r, "{}", explain(&c, &r));
	assert_eq!(c.ret, -1);
	let s2 = srv(&[(
		"/core.db",
		vec![Reply::Stall {
			body: b.clone(),
			at: 1000,
			pause: Duration::from_secs(12),
			finish: true,
		}],
	)]);
	let mk = |d: &[u8]| vec![db_payload(d, "core.db", &[s2.url("")])];
	let case = Case {
		servers: vec![&s2],
		payloads: &mk,
		setup: &no_setup,
		parallel: 1,
		disable_timeout: true,
		sorted: false,
	};
	let (c, r) = run(&case);
	assert_eq!(c, r, "{}", explain(&c, &r));
	assert_eq!(c.ret, 0);
}

// the C keeps dload_interrupted and the environment process wide: these
// cases run in a fresh test process each
fn in_child(test: &str, env: &[(&str, &str)]) {
	let exe = std::env::current_exe().unwrap();
	let mut cmd = Command::new(exe);
	cmd.args([
		"--exact",
		test,
		"--ignored",
		"--nocapture",
		"--test-threads=1",
	]);
	cmd.env("DLOAD_CHILD", "1");
	for (k, val) in env {
		cmd.env(k, val);
	}
	let out = cmd.output().unwrap();
	assert!(
		out.status.success(),
		"{test}:\n{}\n{}",
		String::from_utf8_lossy(&out.stdout),
		String::from_utf8_lossy(&out.stderr)
	);
}

#[test]
fn sticky_size_abort() {
	in_child("sticky_size_abort_child", &[]);
}

#[test]
fn user_agent() {
	in_child(
		"user_agent_child",
		&[("HTTP_USER_AGENT", "pacman/7.1.0 (test)")],
	);
}

// two _alpm_download calls on one handle: a resumed .part that goes over
// max_size during the transfer sets the abort for good, the next call's
// payload aborts too
#[test]
#[ignore = "run by sticky_size_abort in its own process"]
fn sticky_size_abort_child() {
	assert!(std::env::var_os("DLOAD_CHILD").is_some());
	let b = body(30000, 5);
	let s = srv(&[
		("/p.pkg.tar.zst", vec![file(&b)]),
		("/core.db", vec![file(&b)]),
	]);
	let fx = TempRoot::new("dload-sticky");
	let (cd, rd) = (fx.dir().join("c"), fx.dir().join("r"));
	let part = b[..20000].to_vec();
	let first = |d: &[u8]| {
		let mut p = pkg_payload(
			d,
			"p.pkg.tar.zst",
			s.url("/p.pkg.tar.zst"),
		);
		p.max_size = 25000;
		vec![p]
	};
	let second = |d: &[u8]| {
		let mut p = db_payload(d, "core.db", &[s.url("")]);
		p.unlink_on_fail = true;
		vec![p]
	};
	for d in [&cd, &rd] {
		fs::create_dir(d).unwrap();
		fs::write(d.join("p.pkg.tar.zst.part"), &part).unwrap();
	}
	let mut c = Vec::new();
	{
		let mut h = CDload::new(&fx);
		let dir = dir_bytes(&cd);
		for mk in [&first as &dyn Fn(&[u8]) -> Vec<Payload>, &second] {
			let (ret, errno, rec) =
				h.download(&mk(&dir), &dir, &dir);
			let mut o = outcome(ret, errno, rec, &cd, &[&s], false);
			// the aborted transfer may or may not have sent its request
			o.requests.clear();
			c.push(o);
		}
	}
	let mut r = Vec::new();
	let settings = Settings::default();
	let mut state = DownloadState::default();
	let dir = dir_bytes(&rd);
	for mk in [&first as &dyn Fn(&[u8]) -> Vec<Payload>, &second] {
		let mut rec = Recorder::default();
		let mut dl = Downloader {
			settings: &settings,
			state: &mut state,
			cb: &mut rec,
			fetch: None,
			sandbox: None,
		};
		let (ret, errno) =
			rust_ret(dl.download(&mut mk(&dir), &dir, &dir));
		let mut o = outcome(ret, errno, rec.0, &rd, &[&s], false);
		o.requests.clear();
		r.push(o);
	}
	assert!(state.is_interrupted());
	for (c, r) in c.iter().zip(&r) {
		assert_eq!(c, r, "{}", explain(c, r));
	}
	assert_eq!(c[1].ret, -1, "second call aborts too");
}

#[test]
#[ignore = "run by user_agent in its own process"]
fn user_agent_child() {
	assert!(std::env::var_os("DLOAD_CHILD").is_some());
	let b = body(2000, 6);
	let s = srv(&[("/core.db", vec![file(&b)])]);
	let mk = |d: &[u8]| vec![db_payload(d, "core.db", &[s.url("")])];
	let case = Case {
		servers: vec![&s],
		payloads: &mk,
		setup: &no_setup,
		parallel: 1,
		disable_timeout: false,
		sorted: false,
	};
	let (c, r) = run(&case);
	assert_eq!(c, r, "{}", explain(&c, &r));
	assert_eq!(c.requests[0].agent.as_deref(), Some("pacman/7.1.0 (test)"));
}

// body lengths off 4096 multiples: at an exact stdio block the C's
// unflushed size depends on curl's write sizes
fn fuzz_len(rng: &mut Rng, max: usize) -> usize {
	loop {
		let n = 1 + rng.below(max);
		if !n.is_multiple_of(4096) {
			return n;
		}
	}
}

fn fuzz_reply(
	rng: &mut Rng,
	b: &[u8],
	other: Option<&str>,
	path: &str,
) -> Reply {
	let mtime = [None, Some(T0), Some(T0 + 77)][rng.below(3)];
	match rng.below(12) {
		0..=3 => Reply::File {
			body: b.to_vec(),
			ranges: rng.below(4) != 0,
			mtime,
		},
		4 => st([404, 500, 403][rng.below(3)]),
		5 => {
			let sent = loop {
				let s = rng.below(b.len());
				if !s.is_multiple_of(4096) || s == 0 {
					break s;
				}
			};
			Reply::Truncated {
				body: b.to_vec(),
				sent,
			}
		}
		6 => Reply::Chunked {
			body: b.to_vec(),
			cut: rng.below(2) == 0,
		},
		7 if other.is_some() => Reply::Redirect(
			302,
			format!("{}{path}", other.unwrap()),
		),
		8 => Reply::Close,
		9 => Reply::Status(404, body(fuzz_len(rng, 20000), 9)),
		_ => Reply::File {
			body: b.to_vec(),
			ranges: true,
			mtime,
		},
	}
}

// random mirrors (http, a closed port, file://), payloads, .part and
// destination files, flags; parallel downloads only where payloads share
// no host (soft error counts would depend on completion order)
fn fuzz_scn(rng: &mut Rng) -> Scn {
	let nmirrors = 1 + rng.below(3);
	let names = ["core.db", "extra.db", "p-1-1-any.pkg.tar.zst"];
	let npay = 1 + rng.below(3);
	let bodies: Vec<Vec<u8>> = (0..npay)
		.map(|i| body(fuzz_len(rng, 20000), i as u8))
		.collect();
	// KeepAlive left out: its 1 s idle close per run
	let styles = [Style::Close, Style::Drop, Style::Http10];
	let picks: Vec<Style> =
		(0..nmirrors).map(|_| styles[rng.below(3)]).collect();
	let servers: Vec<Server> =
		picks.iter().map(|&st| Server::start_styled(st)).collect();
	let bases: Vec<String> = servers.iter().map(Server::base).collect();
	for (m, s) in servers.iter().enumerate() {
		let other = (nmirrors > 1)
			.then(|| bases[(m + 1) % nmirrors].as_str());
		for (i, b) in bodies.iter().enumerate() {
			let p = format!("/{}", names[i]);
			let r = match (picks[m], fuzz_reply(rng, b, other, &p))
			{
				// see http10_chunked_divergence
				(
					Style::Http10,
					Reply::Chunked { body, .. },
				) => Reply::Unsized(body),
				(_, r) => r,
			};
			s.route(&p, vec![r]);
			let sig = match rng.below(4) {
				0 => st(404),
				1 => file(&body(fuzz_len(rng, 20000), 7)),
				_ => file(&b[..b.len().min(200)]),
			};
			s.route(&format!("{p}.sig"), vec![sig]);
		}
	}
	let dead = format!("http://127.0.0.1:{}", closed_port()).into_bytes();
	struct Spec {
		by_url: Option<usize>,
		mirrors: Vec<usize>,
		cache: Vec<usize>,
		flags: u64,
		max: i64,
		part: Option<usize>,
		dest: Option<bool>,
	}
	let mut specs = Vec::new();
	let mut parallel_ok = true;
	let mut used = Vec::new();
	for b in &bodies {
		// mirror indices, nmirrors = dead, nmirrors + 1 = file://
		let pick = |rng: &mut Rng| rng.below(nmirrors + 2);
		let by_url = (rng.below(3) == 0).then(|| pick(rng));
		let mut mirrors: Vec<usize> =
			(0..rng.below(4)).map(|_| pick(rng)).collect();
		mirrors.dedup();
		let cache: Vec<usize> =
			(0..rng.below(2)).map(|_| pick(rng)).collect();
		let flags = rng.next_u64();
		let resume = flags & 1 != 0;
		let max = match rng.below(6) {
			0 if !resume => 100,
			1 if !resume => b.len() as i64,
			2 if !resume => b.len() as i64 - 1,
			3 => 1 << 30,
			_ => 0,
		};
		let part = (rng.below(3) == 0).then(|| rng.below(b.len() + 50));
		let dest = (rng.below(4) == 0).then(|| rng.below(2) == 0);
		let mine: Vec<usize> = by_url
			.iter()
			.chain(&mirrors)
			.chain(&cache)
			.copied()
			.collect();
		if mine.iter().any(|m| used.contains(m)) || flags & 16 != 0 {
			parallel_ok = false;
		}
		used.extend(mine);
		specs.push(Spec {
			by_url,
			mirrors,
			cache,
			flags,
			max,
			part,
			dest,
		});
	}
	let parallel = if parallel_ok {
		1 + rng.below(3) as u32
	} else {
		1
	};
	let bases2 = bases.clone();
	let base = move |d: &[u8], m: usize| -> Vec<u8> {
		match m.checked_sub(nmirrors) {
			None => bases2[m].clone().into_bytes(),
			Some(0) => dead.clone(),
			Some(_) => [b"file://", d, b"repo"].concat(),
		}
	};
	let parts: Vec<(Option<usize>, Option<bool>)> =
		specs.iter().map(|s| (s.part, s.dest)).collect();
	let mk =
		move |d: &[u8], _: &[Server]| -> Vec<Payload> {
			specs.iter()
				.enumerate()
				.map(|(i, s)| {
					let name = names[i];
					let mut p =
						match s.by_url {
							Some(m) => {
								let u = [&base(d, m)[..], b"/", name.as_bytes()].concat();
								let mut p = pkg_payload(d, name, u);
								p.allow_resume = false;
								p
							}
							None => {
								let ms: Vec<Vec<u8>> =
							s.mirrors.iter().map(|&m| base(d, m)).collect();
								let mut p = db_payload(d, name, &ms);
								p.cache_servers =
							s.cache.iter().map(|&m| base(d, m)).collect();
								p
							}
						};
					p.allow_resume = s.flags & 1 != 0;
					p.errors_ok = s.flags & 2 != 0;
					p.unlink_on_fail = s.flags & 4 != 0;
					p.download_signature = s.flags & 8 != 0;
					p.signature_optional =
						s.flags & 32 != 0;
					p.force = s.flags & 64 != 0;
					p.max_size = s.max;
					p
				})
				.collect()
		};
	let setup_bodies = bodies.clone();
	let setup = move |d: &Path| {
		fs::create_dir(d.join("repo")).unwrap();
		for (i, b) in setup_bodies.iter().enumerate() {
			let f = d.join("repo").join(names[i]);
			fs::write(&f, b).unwrap();
			set_mtime(&f, T0 + i as i64);
			let (part, dest) = parts[i];
			if let Some(n) = part {
				let mut data = b[..n.min(b.len())].to_vec();
				data.resize(n, b'z');
				fs::write(
					d.join(format!("{}.part", names[i])),
					data,
				)
				.unwrap();
			}
			if let Some(old) = dest {
				let f = d.join(names[i]);
				fs::write(&f, b"old").unwrap();
				if old {
					set_mtime(&f, T0 + 77);
				}
			}
		}
	};
	let mut scn = Scn::new("fuzz", servers, mk).setup(setup);
	if parallel > 1 {
		scn = scn.parallel(parallel);
	}
	scn
}

#[test]
fn download_fuzz() {
	let mut rng = Rng::new(0xd10ad);
	let n = (iters() / 1000).max(100);
	// ret 0/1/-1, retries, resumes, .sig downloads, parallel runs,
	// warnings (server blocked), leftover .part files
	let mut seen = [0usize; 8];
	for i in 0..n {
		let scn = fuzz_scn(&mut rng);
		let (c, r) = scn.run();
		assert!(c == r, "case {i}\n{}", explain(&c, &r));
		seen[(c.ret + 1) as usize] += 1;
		let has = |f: &dyn Fn(&DownloadEvent) -> bool| {
			c.downloads.iter().any(|(_, e)| f(e))
		};
		seen[3] += usize::from(has(&|e| {
			matches!(e, DownloadEvent::Retry { .. })
		}));
		seen[4] += usize::from(
			c.requests.iter().any(|q| q.range.is_some()),
		);
		seen[5] += usize::from(
			c.downloads.iter().any(|(n, _)| n.ends_with(b".sig")),
		);
		seen[6] += usize::from(scn.parallel > 1);
		seen[7] += usize::from(
			c.files.iter().any(|f| f.0.ends_with(b".part")),
		);
	}
	eprintln!("fuzz coverage {seen:?} of {n}");
	assert!(seen.iter().all(|&k| k >= n / 50), "coverage {seen:?}");
}
