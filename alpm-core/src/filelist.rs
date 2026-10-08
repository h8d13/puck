// port of lib/libalpm/filelist.c
//
// names are read as C strings, cut at the first nul. sort, contains and
// difference order like strcmp (unsigned bytes), intersection goes through
// _alpm_filelist_pathcmp, which orders differently, see pathcmp.

use std::cmp::Ordering;
use std::ffi::c_char;

use crate::util::until_nul;

// alpm_file_t. size is off_t, 64 bit as meson sets _FILE_OFFSET_BITS=64,
// mode is mode_t, u32 on linux
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct File {
	pub name: Vec<u8>,
	pub size: i64,
	pub mode: u32,
}

// alpm_filelist_t, count is files.len()
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileList {
	pub files: Vec<File>,
}

fn name(f: &File) -> &[u8] {
	until_nul(&f.name)
}

// strcmp on two names: one walk that stops at the first difference or
// nul, without cutting both at their nul first (sort and its pre-sorted
// check run this once per pair of a package's files)
fn strcmp(a: &File, b: &File) -> Ordering {
	let (a, b) = (&a.name, &b.name);
	let n =
		a.iter().zip(b)
			.take_while(|&(x, y)| x == y && *x != 0)
			.count();
	let at = |s: &[u8]| s.get(n).copied().unwrap_or(0);
	at(a).cmp(&at(b))
}

// _alpm_filelist_pathcmp: strcmp where one side ending right where the
// other has a '/' skips that '/', so "usr" equals "usr/". the C returns
// *p1 - *p2 on plain char: signed on x86_64, there bytes >= 0x80 sort
// below ascii, unlike strcmp. c_char keeps that per platform
fn pathcmp(a: &[u8], b: &[u8]) -> Ordering {
	let n = a.iter().zip(b).take_while(|(x, y)| x == y).count();
	let (mut a, mut b) = (&a[n..], &b[n..]);
	if a.is_empty() && b.first() == Some(&b'/') {
		b = &b[1..];
	} else if b.is_empty() && a.first() == Some(&b'/') {
		a = &a[1..];
	}
	let head = |s: &[u8]| s.first().map_or(0, |&c| c as c_char);
	head(a).cmp(&head(b))
}

// the C tests directories with name[strlen - 1], empty names count as
// files here
fn is_dir(s: &[u8]) -> bool {
	s.last() == Some(&b'/')
}

impl FileList {
	// _alpm_filelist_sort: C qsorts by strcmp unless already sorted.
	// a stable sort keeps sorted input as is too, and fixes the order of
	// equal names that qsort leaves unspecified
	pub fn sort(&mut self) {
		// the C's pre-sorted check: written lists are sorted, one pass
		// and no scratch allocation
		if self.files.windows(2).all(|w| strcmp(&w[0], &w[1]).is_le()) {
			return;
		}
		self.files.sort_by(strcmp);
	}

	// alpm_filelist_contains: binary search, files must be sorted.
	// with duplicate names any one of them may come back, like bsearch
	pub fn contains(&self, path: &[u8]) -> Option<&File> {
		let path = until_nul(path);
		let i = self
			.files
			.binary_search_by(|f| name(f).cmp(path))
			.ok()?;
		Some(&self.files[i])
	}

	// _alpm_filelist_difference: names of self missing from other, a
	// merge walk that assumes both sorted. names borrow from self, the C
	// list does not own its strings either
	pub fn difference(&self, other: &FileList) -> Vec<&[u8]> {
		let (a, b) = (&self.files, &other.files);
		let (mut i, mut j) = (0, 0);
		let mut out = Vec::new();
		while i < a.len() && j < b.len() {
			match name(&a[i]).cmp(name(&b[j])) {
				Ordering::Less => {
					out.push(name(&a[i]));
					i += 1;
				}
				Ordering::Greater => j += 1,
				Ordering::Equal => {
					i += 1;
					j += 1;
				}
			}
		}
		out.extend(a[i..].iter().map(name));
		out
	}

	// _alpm_filelist_intersection: names of self also in other, compared
	// with pathcmp, shared directories left out. same merge walk and
	// borrowing as difference
	pub fn intersection(&self, other: &FileList) -> Vec<&[u8]> {
		let (a, b) = (&self.files, &other.files);
		let (mut i, mut j) = (0, 0);
		let mut out = Vec::new();
		while i < a.len() && j < b.len() {
			let (x, y) = (name(&a[i]), name(&b[j]));
			match pathcmp(x, y) {
				Ordering::Less => i += 1,
				Ordering::Greater => j += 1,
				Ordering::Equal => {
					if !is_dir(x) || !is_dir(y) {
						out.push(x);
					}
					i += 1;
					j += 1;
				}
			}
		}
		out
	}
}
