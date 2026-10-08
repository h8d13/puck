// alpm_core::pkghash against the C in pkghash.c: list order, lookups,
// removals and table counts after every step of random op sequences
use std::borrow::Borrow;

use alpm_core::package::Package;
use alpm_core::pkghash::PkgHash;
use alpm_core::util::hash_sdbm;
use difftest::{CPkgHash, Rng, iters};

// a pool package with its index, what the C side reports
struct Entry<'a> {
	id: usize,
	pkg: &'a Package,
}

impl Borrow<Package> for Entry<'_> {
	fn borrow(&self) -> &Package {
		self.pkg
	}
}

fn named(name: &[u8]) -> Package {
	Package {
		name_hash: hash_sdbm(name),
		name: Some(name.into()),
		..Package::default()
	}
}

// short names over a tiny alphabet: duplicates and bucket collisions are
// common. a few hashes are stale, so find and remove disagree on them
fn random_pkg(rng: &mut Rng) -> Package {
	let mut p = named(&rng.bytes(b"abc\xc3", 4));
	if rng.below(10) == 0 {
		p.name_hash = rng.below(40) as u64;
	}
	p
}

struct Pair<'a> {
	pool: &'a [Package],
	c: CPkgHash,
	r: PkgHash<Entry<'a>>,
	log: Vec<String>,
}

impl<'a> Pair<'a> {
	fn new(size: u32, pool: &'a [Package]) -> Self {
		let c = CPkgHash::new(size, pool).unwrap();
		let r = PkgHash::new(size).unwrap();
		let log = vec![format!("create({size})")];
		Pair { pool, c, r, log }
	}

	fn fail(&self) -> String {
		self.log.join(" ")
	}

	fn check(&self) {
		let list: Vec<usize> = self.r.iter().map(|e| e.id).collect();
		assert_eq!(self.c.list(), list, "list after {}", self.fail());
		let counts = (self.r.len(), self.r.buckets(), self.r.limit());
		assert_eq!(
			self.c.counts(),
			counts,
			"counts after {}",
			self.fail()
		);
	}

	fn add(&mut self, id: usize, sorted: bool) {
		self.log.push(format!(
			"add{}({id})",
			if sorted { "_sorted" } else { "" }
		));
		let e = Entry {
			id,
			pkg: &self.pool[id],
		};
		let r = match sorted {
			false => self.r.add(e),
			true => self.r.add_sorted(e),
		};
		assert_eq!(
			self.c.add(id, sorted),
			r.is_ok(),
			"{}",
			self.fail()
		);
	}

	fn remove(&mut self, key: &Package) {
		let name =
			String::from_utf8_lossy(key.name_bytes()).into_owned();
		self.log.push(format!("remove({name:?}, {})", key.name_hash));
		let r = self.r.remove(key).map(|e| e.id);
		assert_eq!(self.c.remove(key), r, "{}", self.fail());
	}

	fn find(&mut self, name: &[u8]) {
		let r = self.r.find(name).map(|e| e.id);
		let shown = String::from_utf8_lossy(name);
		assert_eq!(
			self.c.find(name),
			r,
			"find({shown:?}) after {}",
			self.fail()
		);
	}
}

fn run_sequence(rng: &mut Rng, size: u32, pool: &[Package], ops: usize) {
	let mut p = Pair::new(size, pool);
	p.check();
	for _ in 0..ops {
		match rng.below(10) {
			0..=2 => p.add(rng.below(pool.len()), false),
			3..=5 => p.add(rng.below(pool.len()), true),
			6..=7 => {
				let key = match rng.below(3) {
					0 => random_pkg(rng),
					_ => pool[rng.below(pool.len())]
						.clone(),
				};
				p.remove(&key);
			}
			_ => p.find(&rng.bytes(b"abc\xc3", 4)),
		}
		p.check();
	}
	for e in pool {
		p.find(e.name_bytes());
	}
}

#[test]
fn sequence_fuzz() {
	let mut rng = Rng::new(0x9a5b);
	// a sequence is many C calls, iters() counts single ops
	for _ in 0..iters() / 50 {
		let pool: Vec<Package> = (0..1 + rng.below(40))
			.map(|_| random_pkg(&mut rng))
			.collect();
		let size = rng.below(12) as u32;
		let ops = rng.below(80);
		run_sequence(&mut rng, size, &pool, ops);
	}
}

// through every growth step up to past 5000 buckets, removing a share
#[test]
fn growth() {
	let mut rng = Rng::new(0x6e0);
	let pool: Vec<Package> = (0..6000)
		.map(|i| named(format!("p{i}").as_bytes()))
		.collect();
	let mut p = Pair::new(0, &pool);
	for (i, e) in pool.iter().enumerate() {
		p.add(i, rng.below(2) == 0);
		if rng.below(4) == 0 {
			p.remove(&pool[rng.below(i + 1)].clone());
		}
		p.log.clear();
		let (_, buckets, _) = p.c.counts();
		assert_eq!(p.r.buckets(), buckets, "add {i}");
		p.find(e.name_bytes());
	}
	p.check();
	assert!(p.r.buckets() > 5000, "{}", p.r.buckets());
}

#[test]
fn create_sizes() {
	let mut rng = Rng::new(0x51e);
	// largest table is 976369 buckets: 566294 and up are refused
	let mut sizes: Vec<u32> = (566_280..566_310).collect();
	sizes.extend([0, 1, 5, 6, 7, 1000, 2_000_000]);
	sizes.extend((0..200).map(|_| rng.below(600_000) as u32));
	for size in sizes {
		let c = CPkgHash::new(size, &[]).map(|c| c.counts());
		let r = PkgHash::<Package>::new(size)
			.map(|r| (r.len(), r.buckets(), r.limit()));
		assert_eq!(c, r, "create({size})");
	}
}
