// C side of lib/libalpm/package.c, internal symbols from the static archive
//
// C packages are built from a Package through a #[repr(C)] mirror of
// struct _alpm_pkg_t, every string and list malloc'd through libc so
// _alpm_pkg_free releases them exactly as for a parsed package.
use std::cmp::Ordering;
use std::ffi::{CStr, c_char, c_int, c_ulong, c_void};
use std::ptr;

use crate::handle::{alpm_option_set_ignoregroups, alpm_option_set_ignorepkgs};
use crate::strdup;
use crate::{CList, alpm_list_add, alpm_list_free, cstr, opt_ptr, take};

use alpm_core::backup::Backup;
use alpm_core::deps::{DepMod, Depend};
use alpm_core::filelist::{File, FileList};
use alpm_core::package::{Package, PkgFrom, PkgReason, PkgXData};

// alpm_pkg_xdata_t
#[repr(C)]
struct CPkgXData {
	name: *mut c_char,
	value: *mut c_char,
}

// alpm_depend_t
#[repr(C)]
pub(crate) struct CDepend {
	pub(crate) name: *mut c_char,
	pub(crate) version: *mut c_char,
	pub(crate) desc: *mut c_char,
	pub(crate) name_hash: c_ulong,
	pub(crate) depmod: c_int,
}

// alpm_backup_t
#[repr(C)]
struct CBackup {
	name: *mut c_char,
	hash: *mut c_char,
}

// alpm_file_t, off_t is 64 bit in the meson build
#[repr(C)]
struct CFile {
	name: *mut c_char,
	size: i64,
	mode: u32,
}

// alpm_filelist_t
#[repr(C)]
pub(crate) struct CFileList {
	count: usize,
	files: *mut CFile,
}

// struct _alpm_pkg_t, package.h, field for field. alpm_time_t is int64_t,
// off_t 64 bit, enums are int, origin_data a union of two pointers
#[repr(C)]
pub(crate) struct CPkg {
	name_hash: c_ulong,
	filename: *mut c_char,
	base: *mut c_char,
	name: *mut c_char,
	version: *mut c_char,
	desc: *mut c_char,
	url: *mut c_char,
	packager: *mut c_char,
	sha256sum: *mut c_char,
	base64_sig: *mut c_char,
	arch: *mut c_char,
	builddate: i64,
	installdate: i64,
	size: i64,
	isize: i64,
	download_size: i64,
	pub(crate) handle: *mut c_void,
	licenses: *mut CList,
	replaces: *mut CList,
	groups: *mut CList,
	backup: *mut CList,
	depends: *mut CList,
	optdepends: *mut CList,
	checkdepends: *mut CList,
	makedepends: *mut CList,
	conflicts: *mut CList,
	provides: *mut CList,
	pub(crate) removes: *mut CList,
	pub(crate) oldpkg: *mut CPkg,
	ops: *const c_void,
	files: CFileList,
	pub(crate) origin_data: *mut c_void,
	origin: c_int,
	reason: c_int,
	scriptlet: c_int,
	xdata: *mut CList,
	infolevel: c_int,
	validation: c_int,
}

// lp64 size of struct _alpm_pkg_t. the getter test pins the offsets up
// to validation, the last field
const _: () = assert!(size_of::<CPkg>() == 296);

unsafe extern "C" {
	static default_pkg_ops: u8;

	fn calloc(n: usize, size: usize) -> *mut c_void;
	fn _alpm_handle_new() -> *mut c_void;

	fn _alpm_pkg_new() -> *mut CPkg;
	pub(crate) fn _alpm_pkg_free(pkg: *mut CPkg);
	fn _alpm_pkg_dup(pkg: *mut CPkg, new_ptr: *mut *mut CPkg) -> c_int;
	fn _alpm_pkg_cmp(p1: *const c_void, p2: *const c_void) -> c_int;
	fn _alpm_pkg_compare_versions(
		spkg: *mut CPkg,
		lpkg: *mut CPkg,
	) -> c_int;
	fn alpm_pkg_find(
		haystack: *mut CList,
		needle: *const c_char,
	) -> *mut CPkg;

	fn alpm_pkg_get_filename(pkg: *mut CPkg) -> *const c_char;
	fn alpm_pkg_get_base(pkg: *mut CPkg) -> *const c_char;
	pub(crate) fn alpm_pkg_get_name(pkg: *mut CPkg) -> *const c_char;
	fn alpm_pkg_get_version(pkg: *mut CPkg) -> *const c_char;
	fn alpm_pkg_get_origin(pkg: *mut CPkg) -> c_int;
	pub(crate) fn alpm_pkg_get_desc(pkg: *mut CPkg) -> *const c_char;
	fn alpm_pkg_get_url(pkg: *mut CPkg) -> *const c_char;
	fn alpm_pkg_get_builddate(pkg: *mut CPkg) -> i64;
	fn alpm_pkg_get_installdate(pkg: *mut CPkg) -> i64;
	fn alpm_pkg_get_packager(pkg: *mut CPkg) -> *const c_char;
	fn alpm_pkg_get_sha256sum(pkg: *mut CPkg) -> *const c_char;
	fn alpm_pkg_get_base64_sig(pkg: *mut CPkg) -> *const c_char;
	fn alpm_pkg_get_arch(pkg: *mut CPkg) -> *const c_char;
	fn alpm_pkg_get_size(pkg: *mut CPkg) -> i64;
	fn alpm_pkg_get_isize(pkg: *mut CPkg) -> i64;
	fn alpm_pkg_get_reason(pkg: *mut CPkg) -> c_int;
	pub(crate) fn alpm_pkg_get_validation(pkg: *mut CPkg) -> c_int;
	fn alpm_pkg_get_licenses(pkg: *mut CPkg) -> *mut CList;
	fn alpm_pkg_get_groups(pkg: *mut CPkg) -> *mut CList;
	fn alpm_pkg_get_depends(pkg: *mut CPkg) -> *mut CList;
	fn alpm_pkg_get_optdepends(pkg: *mut CPkg) -> *mut CList;
	fn alpm_pkg_get_checkdepends(pkg: *mut CPkg) -> *mut CList;
	fn alpm_pkg_get_makedepends(pkg: *mut CPkg) -> *mut CList;
	fn alpm_pkg_get_conflicts(pkg: *mut CPkg) -> *mut CList;
	pub(crate) fn alpm_pkg_get_provides(pkg: *mut CPkg) -> *mut CList;
	fn alpm_pkg_get_replaces(pkg: *mut CPkg) -> *mut CList;
	pub(crate) fn alpm_pkg_get_files(pkg: *mut CPkg) -> *mut CFileList;
	pub(crate) fn alpm_pkg_get_backup(pkg: *mut CPkg) -> *mut CList;
	fn alpm_pkg_get_xdata(pkg: *mut CPkg) -> *mut CList;
	pub(crate) fn alpm_pkg_has_scriptlet(pkg: *mut CPkg) -> c_int;

	pub(crate) fn alpm_pkg_compute_requiredby(pkg: *mut CPkg)
	-> *mut CList;
	pub(crate) fn alpm_pkg_compute_optionalfor(
		pkg: *mut CPkg,
	) -> *mut CList;
	pub(crate) fn alpm_pkg_should_ignore(
		handle: *mut c_void,
		pkg: *mut CPkg,
	) -> c_int;
}

thread_local! {
	// getters write handle->pm_errno and dup refuses a NULL handle. one
	// calloc'd handle per test thread, never freed: _alpm_handle_free
	// runs curl_global_cleanup, which is not thread safe
	// SAFETY: _alpm_handle_new only callocs and sets lockfd
	static HANDLE: *mut c_void = unsafe { _alpm_handle_new() };
}

// malloc'd copy, NULL for None
fn dup_str(s: Option<&[u8]>) -> *mut c_char {
	match s {
		None => ptr::null_mut(),
		// SAFETY: cstr gives a valid C string, strdup copies it
		Some(s) => unsafe { strdup(cstr(s).as_ptr()) },
	}
}

// zeroed libc allocation of n T, freed by the matching libalpm function
fn alloc<T>(n: usize) -> *mut T {
	// SAFETY: plain allocation, checked below
	let p = unsafe { calloc(n, size_of::<T>()) }.cast::<T>();
	assert!(!p.is_null());
	p
}

// boxes v into libc memory owned by the C from here on
fn c_box<T>(v: T) -> *mut c_void {
	let p = alloc::<T>(1);
	// SAFETY: p is a fresh allocation for one T
	unsafe { p.write(v) };
	p.cast()
}

fn c_list<T>(items: &[T], f: impl Fn(&T) -> *mut c_void) -> *mut CList {
	items.iter().fold(ptr::null_mut(), |list, x| {
		// SAFETY: list is NULL or built by alpm_list_add, data is owned
		// by the list from here on
		unsafe { alpm_list_add(list, f(x)) }
	})
}

fn c_deps(deps: &[Depend]) -> *mut CList {
	c_list(deps, |d| {
		c_box(CDepend {
			name: dup_str(Some(&d.name)),
			version: dup_str(d.version.as_deref()),
			desc: dup_str(d.desc.as_deref()),
			name_hash: d.name_hash,
			depmod: d.depmod as c_int,
		})
	})
}

fn c_strs(strs: &[Vec<u8>]) -> *mut CList {
	c_list(strs, |s| dup_str(Some(s)).cast())
}

fn c_files(fl: &FileList) -> CFileList {
	if fl.files.is_empty() {
		return CFileList {
			count: 0,
			files: ptr::null_mut(),
		};
	}
	let files = alloc::<CFile>(fl.files.len());
	for (i, f) in fl.files.iter().enumerate() {
		// SAFETY: i < the count allocated
		unsafe {
			files.add(i).write(CFile {
				name: dup_str(Some(&f.name)),
				size: f.size,
				mode: f.mode,
			})
		};
	}
	CFileList {
		count: fl.files.len(),
		files,
	}
}

fn c_origin(origin: &Option<PkgFrom>) -> (c_int, *mut c_void) {
	match origin {
		None => (0, ptr::null_mut()),
		Some(PkgFrom::File(f)) => (1, dup_str(Some(f)).cast()),
		Some(PkgFrom::LocalDb) => (2, ptr::null_mut()),
		Some(PkgFrom::SyncDb) => (3, ptr::null_mut()),
	}
}

// a C package owned by the rust side, _alpm_pkg_free on drop
pub(crate) struct CPkgBox(pub(crate) *mut CPkg);

impl Drop for CPkgBox {
	fn drop(&mut self) {
		// SAFETY: built by new() or returned by _alpm_pkg_dup, every
		// pointer in it is libc allocated or NULL, not used afterwards
		unsafe { _alpm_pkg_free(self.0) }
	}
}

impl CPkgBox {
	pub(crate) fn new(pkg: &Package) -> Self {
		// SAFETY: calloc'd struct of the size the C uses
		let p = unsafe { _alpm_pkg_new() };
		assert!(!p.is_null());
		let (origin, origin_data) = c_origin(&pkg.origin);
		let backup = c_list(&pkg.backup, |b| {
			c_box(CBackup {
				name: dup_str(Some(&b.name)),
				hash: dup_str(b.hash.as_deref()),
			})
		});
		let xdata = c_list(&pkg.xdata, |x| {
			c_box(CPkgXData {
				name: dup_str(Some(&x.name)),
				value: dup_str(Some(&x.value)),
			})
		});
		let c = CPkg {
			name_hash: pkg.name_hash,
			filename: dup_str(pkg.filename.as_deref()),
			base: dup_str(pkg.base.as_deref()),
			name: dup_str(pkg.name.as_deref()),
			version: dup_str(pkg.version.as_deref()),
			desc: dup_str(pkg.desc.as_deref()),
			url: dup_str(pkg.url.as_deref()),
			packager: dup_str(pkg.packager.as_deref()),
			sha256sum: dup_str(pkg.sha256sum.as_deref()),
			base64_sig: dup_str(pkg.base64_sig.as_deref()),
			arch: dup_str(pkg.arch.as_deref()),
			builddate: pkg.builddate,
			installdate: pkg.installdate,
			size: pkg.size,
			isize: pkg.isize,
			download_size: pkg.download_size,
			handle: HANDLE.with(|h| *h),
			licenses: c_strs(&pkg.licenses),
			replaces: c_deps(&pkg.replaces),
			groups: c_strs(&pkg.groups),
			backup,
			depends: c_deps(&pkg.depends),
			optdepends: c_deps(&pkg.optdepends),
			checkdepends: c_deps(&pkg.checkdepends),
			makedepends: c_deps(&pkg.makedepends),
			conflicts: c_deps(&pkg.conflicts),
			provides: c_deps(&pkg.provides),
			removes: ptr::null_mut(),
			oldpkg: ptr::null_mut(),
			ops: (&raw const default_pkg_ops).cast(),
			files: c_files(&pkg.files),
			origin_data,
			origin,
			reason: pkg.reason as c_int,
			scriptlet: pkg.scriptlet,
			xdata,
			infolevel: pkg.infolevel,
			validation: pkg.validation,
		};
		// SAFETY: p is the calloc'd struct, all zero so nothing leaks
		unsafe { p.write(c) };
		CPkgBox(p)
	}
}

// copies a C string out, NULL is None
pub(crate) fn field(p: *const c_char) -> Option<Vec<u8>> {
	// SAFETY: p is NULL or a nul-terminated string owned by the package
	(!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
}

// the data pointers of a list, nodes stay owned by the C
pub(crate) fn list_data(head: *const CList) -> Vec<*mut c_void> {
	let mut out = Vec::new();
	let mut p = head;
	while !p.is_null() {
		// SAFETY: p is a node of a list built by alpm_list_add
		unsafe {
			out.push((*p).data);
			p = (*p).next;
		}
	}
	out
}

// list data read as T, which the caller states
fn read_list<T, R>(head: *const CList, f: impl Fn(&T) -> R) -> Vec<R> {
	list_data(head)
		.into_iter()
		// SAFETY: each data pointer is a live T owned by the list
		.map(|p| f(unsafe { &*p.cast::<T>() }))
		.collect()
}

pub(crate) fn read_strs(head: *const CList) -> Vec<Vec<u8>> {
	list_data(head)
		.into_iter()
		.map(|p| field(p.cast()).unwrap())
		.collect()
}

fn depmod_from_c(m: c_int) -> DepMod {
	match m {
		1 => DepMod::Any,
		2 => DepMod::Eq,
		3 => DepMod::Ge,
		4 => DepMod::Le,
		5 => DepMod::Gt,
		6 => DepMod::Lt,
		_ => panic!("unknown alpm_depmod_t {m}"),
	}
}

pub(crate) fn read_deps(head: *const CList) -> Vec<Depend> {
	read_list(head, |d: &CDepend| Depend {
		name: field(d.name).unwrap(),
		version: field(d.version),
		desc: field(d.desc),
		name_hash: d.name_hash,
		depmod: depmod_from_c(d.depmod),
	})
}

fn read_backup(head: *const CList) -> Vec<Backup> {
	read_list(head, |b: &CBackup| Backup {
		name: field(b.name).unwrap(),
		hash: field(b.hash),
	})
}

fn read_xdata(head: *const CList) -> Vec<PkgXData> {
	read_list(head, |x: &CPkgXData| PkgXData {
		name: field(x.name).unwrap(),
		value: field(x.value).unwrap(),
	})
}

pub(crate) fn read_files(fl: *const CFileList) -> FileList {
	// SAFETY: fl points into a live package
	let fl = unsafe { &*fl };
	let read = |i: usize| {
		// SAFETY: i < count entries behind files
		let f = unsafe { &*fl.files.add(i) };
		File {
			name: field(f.name).unwrap(),
			size: f.size,
			mode: f.mode,
		}
	};
	FileList {
		files: (0..fl.count).map(read).collect(),
	}
}

fn reason_from_c(r: c_int) -> PkgReason {
	match r {
		0 => PkgReason::Explicit,
		1 => PkgReason::Depend,
		2 => PkgReason::Unknown,
		_ => panic!("unknown alpm_pkgreason_t {r}"),
	}
}

// origin_data.file is only read for ALPM_PKG_FROM_FILE
fn origin_from_c(origin: c_int, data: *mut c_void) -> Option<PkgFrom> {
	match origin {
		0 => None,
		1 => Some(PkgFrom::File(field(data.cast()).unwrap())),
		2 => Some(PkgFrom::LocalDb),
		3 => Some(PkgFrom::SyncDb),
		_ => panic!("unknown alpm_pkgfrom_t {origin}"),
	}
}

// every modelled field straight through the mirror
pub(crate) fn read_pkg(p: *const CPkg) -> Package {
	// SAFETY: p is a live package built by CPkgBox or _alpm_pkg_dup
	let c = unsafe { &*p };
	Package {
		name_hash: c.name_hash,
		filename: field(c.filename),
		base: field(c.base),
		name: field(c.name),
		version: field(c.version),
		desc: field(c.desc),
		url: field(c.url),
		packager: field(c.packager),
		sha256sum: field(c.sha256sum),
		base64_sig: field(c.base64_sig),
		arch: field(c.arch),
		builddate: c.builddate,
		installdate: c.installdate,
		size: c.size,
		isize: c.isize,
		download_size: c.download_size,
		licenses: read_strs(c.licenses),
		replaces: read_deps(c.replaces),
		groups: read_strs(c.groups),
		backup: read_backup(c.backup),
		depends: read_deps(c.depends),
		optdepends: read_deps(c.optdepends),
		checkdepends: read_deps(c.checkdepends),
		makedepends: read_deps(c.makedepends),
		conflicts: read_deps(c.conflicts),
		provides: read_deps(c.provides),
		files: read_files(&c.files),
		origin: origin_from_c(c.origin, c.origin_data),
		reason: reason_from_c(c.reason),
		scriptlet: c.scriptlet,
		xdata: read_xdata(c.xdata),
		infolevel: c.infolevel,
		validation: c.validation,
	}
}

// built through the mirror, read back through it, freed by the C
pub fn c_pkg_roundtrip(pkg: &Package) -> Package {
	read_pkg(CPkgBox::new(pkg).0)
}

// the exported alpm_pkg_get_* on a mirror-built package. fields without
// a getter (name_hash, download_size, infolevel, the origin file) stay
// default, so a wrong mirror offset shows up as a mismatch
pub fn c_pkg_getters(pkg: &Package) -> Package {
	let b = CPkgBox::new(pkg);
	let p = b.0;
	// SAFETY: p is live with default_pkg_ops and a handle, the getters
	// return pointers into it, copied out before b drops
	unsafe {
		Package {
			filename: field(alpm_pkg_get_filename(p)),
			base: field(alpm_pkg_get_base(p)),
			name: field(alpm_pkg_get_name(p)),
			version: field(alpm_pkg_get_version(p)),
			desc: field(alpm_pkg_get_desc(p)),
			url: field(alpm_pkg_get_url(p)),
			packager: field(alpm_pkg_get_packager(p)),
			sha256sum: field(alpm_pkg_get_sha256sum(p)),
			base64_sig: field(alpm_pkg_get_base64_sig(p)),
			arch: field(alpm_pkg_get_arch(p)),
			builddate: alpm_pkg_get_builddate(p),
			installdate: alpm_pkg_get_installdate(p),
			size: alpm_pkg_get_size(p),
			isize: alpm_pkg_get_isize(p),
			licenses: read_strs(alpm_pkg_get_licenses(p)),
			replaces: read_deps(alpm_pkg_get_replaces(p)),
			groups: read_strs(alpm_pkg_get_groups(p)),
			backup: read_backup(alpm_pkg_get_backup(p)),
			depends: read_deps(alpm_pkg_get_depends(p)),
			optdepends: read_deps(alpm_pkg_get_optdepends(p)),
			checkdepends: read_deps(alpm_pkg_get_checkdepends(p)),
			makedepends: read_deps(alpm_pkg_get_makedepends(p)),
			conflicts: read_deps(alpm_pkg_get_conflicts(p)),
			provides: read_deps(alpm_pkg_get_provides(p)),
			files: read_files(alpm_pkg_get_files(p)),
			origin: match alpm_pkg_get_origin(p) {
				1 => Some(PkgFrom::File(Vec::new())),
				o => origin_from_c(o, ptr::null_mut()),
			},
			reason: reason_from_c(alpm_pkg_get_reason(p)),
			scriptlet: alpm_pkg_has_scriptlet(p),
			xdata: read_xdata(alpm_pkg_get_xdata(p)),
			validation: alpm_pkg_get_validation(p),
			..Package::default()
		}
	}
}

// _alpm_pkg_dup of a mirror-built package, handle and ops set
pub fn c_pkg_dup(pkg: &Package) -> Package {
	let b = CPkgBox::new(pkg);
	let mut out = ptr::null_mut();
	// SAFETY: b.0 is live, the C writes a fresh package to out
	let rc = unsafe { _alpm_pkg_dup(b.0, &mut out) };
	assert_eq!(rc, 0);
	read_pkg(CPkgBox(out).0)
}

// C precondition: both names set
pub fn c_pkg_cmp(a: &Package, b: &Package) -> Ordering {
	assert!(a.name.is_some() && b.name.is_some(), "C strcmp on NULL");
	let (a, b) = (CPkgBox::new(a), CPkgBox::new(b));
	// SAFETY: both live, the C only reads the names
	unsafe { _alpm_pkg_cmp(a.0.cast(), b.0.cast()) }.cmp(&0)
}

pub fn c_pkg_compare_versions(spkg: &Package, localpkg: &Package) -> Ordering {
	let (a, b) = (CPkgBox::new(spkg), CPkgBox::new(localpkg));
	// SAFETY: both live, the C only reads the versions
	unsafe { _alpm_pkg_compare_versions(a.0, b.0) }.cmp(&0)
}

// None maps to NULL, for list entries and the needle. index found.
// C precondition: no NULL name in a package whose hash matches
pub fn c_pkg_find(
	haystack: &[Option<&Package>],
	needle: Option<&[u8]>,
) -> Option<usize> {
	let pkgs: Vec<Option<CPkgBox>> =
		haystack.iter().map(|p| p.map(CPkgBox::new)).collect();
	let ptrs: Vec<*mut CPkg> = pkgs
		.iter()
		.map(|b| b.as_ref().map_or(ptr::null_mut(), |b| b.0))
		.collect();
	let list = c_list(&ptrs, |&p| p.cast());
	let needle = needle.map(cstr);
	// SAFETY: list holds live packages or NULL, the C only reads them
	let r = unsafe { alpm_pkg_find(list, opt_ptr(&needle)) };
	// SAFETY: list nodes only, the packages are freed with pkgs
	unsafe { alpm_list_free(list) };
	if r.is_null() {
		return None;
	}
	ptrs.iter().position(|&p| p == r)
}

// copies out a list of malloc'd strings, frees list and strings
pub(crate) fn take_strs(list: *mut CList) -> Vec<Vec<u8>> {
	let out = list_data(list)
		.into_iter()
		.map(|p| take(p.cast()).unwrap())
		.collect();
	// SAFETY: the strings were freed by take, the nodes go here
	unsafe { alpm_list_free(list) };
	out
}

// a Rust-owned list of C strings for the call of f, the C only reads it
pub(crate) fn with_strs<R>(
	strs: &[Vec<u8>],
	f: impl FnOnce(*mut CList) -> R,
) -> R {
	let owned: Vec<_> = strs.iter().map(|s| cstr(s)).collect();
	let mut list = ptr::null_mut();
	for s in &owned {
		// SAFETY: list is NULL or built by alpm_list_add, data stays
		// owned by `owned`
		list = unsafe {
			alpm_list_add(list, s.as_ptr().cast_mut().cast())
		};
	}
	let r = f(list);
	// SAFETY: nodes malloc'd by alpm_list_add, data not owned by the list
	unsafe { alpm_list_free(list) };
	r
}

// alpm_pkg_should_ignore with the thread's handle holding these
// ignorepkg/ignoregroup lists (cleared again after). C precondition: name
// set when ignorepkg is not empty (fnmatch on NULL)
pub fn c_pkg_should_ignore(
	ignorepkg: &[Vec<u8>],
	ignoregroup: &[Vec<u8>],
	pkg: &Package,
) -> bool {
	assert!(pkg.name.is_some() || ignorepkg.is_empty(), "NULL name");
	let h = HANDLE.with(|h| *h);
	// SAFETY: h is the thread's live handle, the set calls dup the
	// strings, NULL clears
	unsafe {
		with_strs(ignorepkg, |l| alpm_option_set_ignorepkgs(h, l));
		with_strs(ignoregroup, |l| alpm_option_set_ignoregroups(h, l));
	}
	let b = CPkgBox::new(pkg);
	// SAFETY: b.0 is live with h as its handle
	let r = unsafe { alpm_pkg_should_ignore(h, b.0) } != 0;
	// SAFETY: as above
	unsafe {
		alpm_option_set_ignorepkgs(h, ptr::null_mut());
		alpm_option_set_ignoregroups(h, ptr::null_mut());
	}
	r
}
