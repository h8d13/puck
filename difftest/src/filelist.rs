// C side of lib/libalpm/filelist.c, internal symbols from the static archive
use std::ffi::{CStr, CString, c_char, c_void};

use crate::{CList, alpm_list_free, cstr};

use alpm_core::filelist::{File, FileList};

// alpm_file_t, off_t is 64 bit in the meson build
#[repr(C)]
struct CFile {
	name: *mut c_char,
	size: i64,
	mode: u32,
}

// alpm_filelist_t
#[repr(C)]
struct CFileList {
	count: usize,
	files: *mut CFile,
}

// alpm_list_t
unsafe extern "C" {
	fn _alpm_filelist_sort(filelist: *mut CFileList);
	fn alpm_filelist_contains(
		filelist: *const CFileList,
		path: *const c_char,
	) -> *mut CFile;
	fn _alpm_filelist_difference(
		a: *mut CFileList,
		b: *mut CFileList,
	) -> *mut CList;
	fn _alpm_filelist_intersection(
		a: *mut CFileList,
		b: *mut CFileList,
	) -> *mut CList;
}

// collects the data pointers and frees the nodes, not the data
fn take_list(head: *mut CList) -> Vec<*mut c_void> {
	let mut out = Vec::new();
	let mut p = head;
	while !p.is_null() {
		// SAFETY: p is a node of a list built by alpm_list_add
		unsafe {
			out.push((*p).data);
			p = (*p).next;
		}
	}
	// SAFETY: head is NULL or a list malloc'd by libalpm, not used again
	unsafe { alpm_list_free(head) };
	out
}

// C copy of a filelist, names owned on the rust side
struct Owned {
	_names: Vec<CString>,
	files: Vec<CFile>,
}

impl Owned {
	fn new(fl: &FileList) -> Self {
		let names: Vec<CString> =
			fl.files.iter().map(|f| cstr(f.name())).collect();
		let files =
			fl.files.iter()
				.zip(&names)
				.map(|(f, n)| CFile {
					name: n.as_ptr().cast_mut(),
					size: f.size,
					mode: f.mode,
				})
				.collect();
		Owned {
			_names: names,
			files,
		}
	}

	// the array pointer stays valid while self is not moved or resized
	fn list(&mut self) -> CFileList {
		CFileList {
			count: self.files.len(),
			files: self.files.as_mut_ptr(),
		}
	}

	// index of the entry whose name is p
	fn index_of(&self, p: *const c_void) -> usize {
		self.files
			.iter()
			.position(|f| f.name.cast_const().cast() == p)
			.unwrap()
	}
}

pub fn c_filelist_sort(fl: &FileList) -> FileList {
	let mut o = Owned::new(fl);
	let mut l = o.list();
	// SAFETY: l describes o.files, the C permutes it in place
	unsafe { _alpm_filelist_sort(&mut l) };
	let files = o
		.files
		.iter()
		.map(|f| {
			// SAFETY: names still point into o._names
			let name = unsafe { CStr::from_ptr(f.name) };
			File::new(name.to_bytes().to_vec(), f.size, f.mode)
		})
		.collect();
	FileList { files }
}

// None maps to NULL. index of the entry found. C precondition: sorted
pub fn c_filelist_contains(
	fl: Option<&FileList>,
	path: &[u8],
) -> Option<usize> {
	let path = cstr(path);
	let mut o = fl.map(Owned::new);
	let l = o.as_mut().map(Owned::list);
	let lp = l.as_ref().map_or(std::ptr::null(), |l| l as *const _);
	// SAFETY: lp is NULL or describes o.files, path is a valid C string
	let r = unsafe { alpm_filelist_contains(lp, path.as_ptr()) };
	if r.is_null() {
		return None;
	}
	let files = &o.as_ref().unwrap().files;
	// SAFETY: bsearch returns a pointer into files
	let i = unsafe { r.offset_from(files.as_ptr()) };
	Some(usize::try_from(i).unwrap())
}

type ListFn =
	unsafe extern "C" fn(*mut CFileList, *mut CFileList) -> *mut CList;

// indices into a of the names in the C list
fn merge(f: ListFn, a: &FileList, b: &FileList) -> Vec<usize> {
	let (mut oa, mut ob) = (Owned::new(a), Owned::new(b));
	let (mut la, mut lb) = (oa.list(), ob.list());
	// SAFETY: la/lb describe oa/ob, the C only reads them and returns a
	// list of name pointers from la it does not own
	let head = unsafe { f(&mut la, &mut lb) };
	take_list(head)
		.into_iter()
		.map(|p| oa.index_of(p))
		.collect()
}

pub fn c_filelist_difference(a: &FileList, b: &FileList) -> Vec<usize> {
	merge(_alpm_filelist_difference, a, b)
}

// C precondition: no empty names
pub fn c_filelist_intersection(a: &FileList, b: &FileList) -> Vec<usize> {
	let empty = a.files.iter().chain(&b.files).any(|f| f.name().is_empty());
	assert!(!empty, "empty name, C would read out of bounds");
	merge(_alpm_filelist_intersection, a, b)
}
