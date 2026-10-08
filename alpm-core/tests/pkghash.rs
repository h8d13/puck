// unit tests for alpm_core::pkghash
use alpm_core::package::Package;
use alpm_core::pkghash::PkgHash;
use alpm_core::util::hash_sdbm;

fn named(name: &[u8]) -> Package {
	Package {
		name_hash: hash_sdbm(name),
		name: Some(name.into()),
		..Package::default()
	}
}

fn names(h: &PkgHash) -> Vec<&[u8]> {
	h.iter().map(Package::name_bytes).collect()
}

#[test]
fn create_sizes() {
	let h = PkgHash::<Package>::new(0).unwrap();
	assert_eq!((h.len(), h.buckets(), h.limit()), (0, 11, 7));
	// 100 / 0.58 + 1 = 173, next prime 179
	assert_eq!(PkgHash::<Package>::new(100).unwrap().buckets(), 179);
	assert!(PkgHash::<Package>::new(566_293).is_some());
	assert!(PkgHash::<Package>::new(566_294).is_none());
	assert!(PkgHash::<Package>::new(u32::MAX).is_none());
}

#[test]
fn add_orders() {
	let mut h = PkgHash::new(0).unwrap();
	for n in [&b"c"[..], b"a", b"b"] {
		assert!(h.add(named(n)).is_ok());
	}
	assert_eq!(names(&h), [&b"c"[..], b"a", b"b"]);
	// sorted add goes before the first strictly greater name
	h.add_sorted(named(b"b")).unwrap();
	assert_eq!(names(&h), [&b"b"[..], b"c", b"a", b"b"]);
	h.add_sorted(named(b"d")).unwrap();
	assert_eq!(names(&h).last(), Some(&&b"d"[..]));
}

#[test]
fn find_remove_and_rehash() {
	let mut h = PkgHash::new(0).unwrap();
	for i in 0..100 {
		h.add_sorted(named(format!("p{i:03}").as_bytes())).unwrap();
	}
	assert_eq!(h.len(), 100);
	assert!(h.buckets() > 100);
	assert!(h.find(b"p042").is_some());
	let gone = h.remove(&named(b"p042")).unwrap();
	assert_eq!(gone.name_bytes(), b"p042");
	assert!(h.find(b"p042").is_none());
	assert!(h.remove(&named(b"p042")).is_none());
	// the backward shift keeps every other entry reachable
	for i in (0..100).filter(|&i| i != 42) {
		let n = format!("p{i:03}");
		assert!(h.find(n.as_bytes()).is_some(), "{n}");
	}
	assert_eq!(h.len(), 99);
	assert!(names(&h).is_sorted());
}

#[test]
fn duplicates_and_stale_hash() {
	let mut h = PkgHash::new(0).unwrap();
	let mut a = named(b"a");
	a.size = 1;
	h.add(a).unwrap();
	h.add(named(b"a")).unwrap();
	// the first in probe order wins
	assert_eq!(h.find(b"a").unwrap().size, 1);
	assert_eq!(h.remove(&named(b"a")).unwrap().size, 1);
	assert_eq!(h.find(b"a").unwrap().size, 0);
	// find hashes the name, remove trusts the key's stored hash
	let mut stale = named(b"s");
	stale.name_hash = 3;
	h.add(stale.clone()).unwrap();
	assert!(h.find(b"s").is_none());
	assert!(h.remove(&stale).is_some());
}

#[test]
fn borrowed_entries() {
	let pool = [named(b"x"), named(b"y")];
	let mut h = PkgHash::<&Package>::new(1).unwrap();
	h.add(&pool[1]).unwrap();
	h.add_sorted(&pool[0]).unwrap();
	assert!(std::ptr::eq(*h.find(b"y").unwrap(), &pool[1]));
	assert_eq!(names2(&h), [&b"x"[..], b"y"]);
}

fn names2<'a>(h: &'a PkgHash<&Package>) -> Vec<&'a [u8]> {
	h.iter().map(|p| p.name_bytes()).collect()
}

#[test]
fn mutable_access() {
	let mut h = PkgHash::new(0).unwrap();
	for n in [&b"b"[..], b"a", b"b"] {
		h.add(named(n)).unwrap();
	}
	// find_mut hits the entry find returns, the first in probe order
	h.find_mut(b"b").unwrap().size = 7;
	assert_eq!(h.find(b"b").unwrap().size, 7);
	assert_eq!(h.iter().map(|p| p.size).collect::<Vec<_>>(), [7, 0, 0]);
	assert!(h.find_mut(b"c").is_none());
	// iter_mut walks the list order
	for (i, p) in h.iter_mut().enumerate() {
		p.isize = i as i64;
	}
	let sizes: Vec<i64> = h.iter().map(|p| p.isize).collect();
	assert_eq!(sizes, [0, 1, 2]);
	assert_eq!(names(&h), [&b"b"[..], b"a", b"b"]);
	let mut a = named(b"a");
	a.isize = 9;
	// merged before the first "b", then the first "b" in probe order goes
	h.add_sorted(a).unwrap();
	h.remove(&named(b"b")).unwrap();
	let order: Vec<i64> = h.iter_mut().map(|p| p.isize).collect();
	assert_eq!(order, [9, 1, 2]);
}
