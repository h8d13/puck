// unit tests for alpm_core::filelist
use alpm_core::filelist::*;

fn list(names: &[&[u8]]) -> FileList {
	let files = names.iter().map(|n| File::new(n.to_vec(), 0, 0)).collect();
	FileList { files }
}

fn names(fl: &FileList) -> Vec<&[u8]> {
	fl.files.iter().map(File::name).collect()
}

#[test]
fn sort_is_bytewise() {
	let mut fl =
		list(&[b"usr/", b"etc/", b"usr/bin/", b"\xc3", b"Z", b"a"]);
	fl.sort();
	let want: &[&[u8]] =
		&[b"Z", b"a", b"etc/", b"usr/", b"usr/bin/", b"\xc3"];
	assert_eq!(names(&fl), want);
}

#[test]
fn contains_cases() {
	let fl = list(&[b"etc/", b"etc/fstab", b"usr/"]);
	let found = |p: &[u8]| fl.contains(p).map(|f| f.name().to_vec());
	assert_eq!(found(b"etc/fstab").unwrap(), b"etc/fstab");
	assert_eq!(found(b"etc/fstab\0x").unwrap(), b"etc/fstab");
	assert!(fl.contains(b"usr").is_none());
	assert!(fl.contains(b"").is_none());
	assert!(list(&[]).contains(b"etc/").is_none());
}

#[test]
fn difference_cases() {
	let a = list(&[b"a", b"b", b"c", b"d"]);
	let b = list(&[b"b", b"d", b"e"]);
	let want: &[&[u8]] = &[b"a", b"c"];
	assert_eq!(a.difference(&b), want);
	assert_eq!(a.difference(&list(&[])), names(&a));
	assert!(list(&[]).difference(&a).is_empty());
}

#[test]
fn intersection_cases() {
	// file vs dir of the same path is a conflict, dir vs dir is not
	let a = list(&[b"etc/", b"usr", b"var/", b"x"]);
	let b = list(&[b"etc/", b"usr/", b"var", b"y"]);
	let want: &[&[u8]] = &[b"usr", b"var/"];
	assert_eq!(a.intersection(&b), want);
	assert!(a.intersection(&list(&[])).is_empty());
	// a missing trailing '/' only matches at the very end
	let a = list(&[b"usr", b"usrx"]);
	let b = list(&[b"usr/bin"]);
	assert!(a.intersection(&b).is_empty());
}

#[test]
fn new_cuts_at_nul() {
	assert_eq!(
		File::new(b"etc/fstab\0x".to_vec(), 1, 2).name(),
		b"etc/fstab"
	);
	assert_eq!(File::new(b"\0".to_vec(), 0, 0).name(), b"");
	assert_eq!(File::new(b"usr/".to_vec(), 0, 0).name(), b"usr/");
}
