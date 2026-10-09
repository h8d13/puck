// alpm_core::filelist against the C in filelist.c
use alpm_core::filelist::{File, FileList};
use alpm_core::internals::util::until_nul;
use difftest::{
	Rng, c_filelist_contains, c_filelist_difference,
	c_filelist_intersection, c_filelist_sort, iters,
};

// '/' for pathcmp's trailing slash rule, '-' and '.' sort just below '/',
// 0xc3 sorts last for strcmp but first for signed char
const ALPHABET: &[u8] = b"ab//-.\xc3";
// a nul ends the C's strdup'd name, File::new cuts there too. never
// first: intersection's C reads out of bounds on empty names
const TAIL: &[u8] = b"ab//-.\xc3\0";

fn name(rng: &mut Rng) -> Vec<u8> {
	let mut n = vec![rng.pick(ALPHABET)];
	n.extend(rng.bytes(TAIL, 5));
	n
}

fn random_list(rng: &mut Rng) -> FileList {
	let files = (0..rng.below(9))
		.map(|_| {
			let name = name(rng);
			File::new(
				name,
				rng.next_u64() as i64,
				rng.next_u64() as u32,
			)
		})
		.collect();
	FileList { files }
}

// f with its name edited, through File::new like any other
fn renamed(f: &File, edit: impl FnOnce(&mut Vec<u8>)) -> File {
	let mut name = f.name().to_vec();
	edit(&mut name);
	File::new(name, f.size, f.mode)
}

// b drawn from a with edits, so merges hit equal names often
fn related(rng: &mut Rng, a: &FileList) -> FileList {
	let mut b = a.clone();
	for _ in 0..rng.below(4) {
		let i = rng.below(b.files.len() + 1);
		match rng.below(4) {
			0 if i < b.files.len() => {
				b.files.remove(i);
			}
			1 if i < b.files.len() => {
				b.files[i] =
					renamed(&b.files[i], |n| n.push(b'/'));
			}
			2 if i < b.files.len() => {
				b.files[i] = renamed(&b.files[i], |n| {
					n.pop();
					if n.is_empty() {
						n.push(b'a');
					}
				});
			}
			_ => b.files.insert(i, File::new(name(rng), 0, 0)),
		}
	}
	b
}

fn has_dups(fl: &FileList) -> bool {
	let mut n: Vec<_> = fl.files.iter().map(File::name).collect();
	n.sort();
	n.windows(2).any(|w| w[0] == w[1])
}

fn show(fl: &FileList) -> Vec<String> {
	fl.files.iter()
		.map(|f| String::from_utf8_lossy(f.name()).into_owned())
		.collect()
}

// positions in a of names borrowed from it
fn indices(a: &FileList, names: &[&[u8]]) -> Vec<usize> {
	names.iter()
		.map(|n| {
			a.files.iter()
				.position(|f| f.name().as_ptr() == n.as_ptr())
				.unwrap()
		})
		.collect()
}

#[test]
fn sort_fuzz() {
	let mut rng = Rng::new(0x5027);
	for _ in 0..iters() {
		let fl = random_list(&mut rng);
		let c = c_filelist_sort(&fl);
		let mut r = fl.clone();
		r.sort();
		// qsort leaves the order of equal names unspecified
		if has_dups(&fl) {
			let n = |l: &FileList| {
				l.files.iter()
					.map(|f| f.name().to_vec())
					.collect::<Vec<_>>()
			};
			assert_eq!(n(&c), n(&r), "{:?}", show(&fl));
		} else {
			assert_eq!(c, r, "{:?}", show(&fl));
		}
	}
}

#[test]
fn contains_fuzz() {
	let mut rng = Rng::new(0xc047);
	for _ in 0..iters() {
		let mut fl = random_list(&mut rng);
		fl.sort();
		let path = match rng.below(3) {
			0 if !fl.files.is_empty() => fl.files
				[rng.below(fl.files.len())]
			.name()
			.to_vec(),
			_ => name(&mut rng),
		};
		// bsearch may return any of equal names. the C gets path as a
		// C string, the port cuts it itself
		let c = c_filelist_contains(Some(&fl), until_nul(&path));
		let c = c.map(|i| fl.files[i].name());
		let r = fl.contains(&path).map(File::name);
		assert_eq!(c, r, "{:?} in {:?}", show(&fl), path);
	}
}

#[test]
fn merge_fuzz() {
	let mut rng = Rng::new(0x3e59);
	for _ in 0..iters() {
		let mut a = random_list(&mut rng);
		let mut b = related(&mut rng, &a);
		// the merge walks are defined on unsorted input too
		if rng.below(4) != 0 {
			a.sort();
			b.sort();
		}
		let (x, y) = (&a, &b);
		assert_eq!(
			c_filelist_difference(x, y),
			indices(x, &x.difference(y)),
			"{:?} - {:?}",
			show(x),
			show(y)
		);
		assert_eq!(
			c_filelist_intersection(x, y),
			indices(x, &x.intersection(y)),
			"{:?} & {:?}",
			show(x),
			show(y)
		);
		assert_eq!(
			c_filelist_intersection(y, x),
			indices(y, &y.intersection(x)),
			"{:?} & {:?}",
			show(y),
			show(x)
		);
	}
}

#[test]
fn merge_edge_cases() {
	let list = |names: &[&[u8]]| FileList {
		files: names
			.iter()
			.map(|n| File::new(n.to_vec(), 0, 0))
			.collect(),
	};
	type Names<'a> = &'a [&'a [u8]];
	let cases: &[(Names, Names)] = &[
		(&[b"usr"], &[b"usr/"]),
		(&[b"usr/"], &[b"usr/"]),
		(&[b"usr/"], &[b"usr"]),
		(&[b"usr"], &[b"usr/bin"]),
		(&[b"/"], &[b"/"]),
		(&[b"a", b"\xc3"], &[b"\xc3"]),
		(&[b"a/", b"a/\xc3"], &[b"a", b"a/\xc3"]),
		(&[], &[b"a"]),
	];
	for &(a, b) in cases {
		let (a, b) = (list(a), list(b));
		for (x, y) in [(&a, &b), (&b, &a)] {
			assert_eq!(
				c_filelist_difference(x, y),
				indices(x, &x.difference(y))
			);
			assert_eq!(
				c_filelist_intersection(x, y),
				indices(x, &x.intersection(y)),
				"{:?} & {:?}",
				show(x),
				show(y)
			);
		}
	}
}

// contract the future C ABI shim has to keep
#[test]
fn c_null_contract() {
	assert_eq!(c_filelist_contains(None, b"a"), None);
	assert_eq!(c_filelist_contains(Some(&FileList::default()), b""), None);
}
