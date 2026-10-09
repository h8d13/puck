// port of lib/libalpm/pkghash.c, the package cache: open addressing table
// for lookup by name plus a list for iteration.
//
// the bucket layout is kept exactly (prime sizes, linear probing, the
// backward shift on remove): with duplicate names it decides which entry
// find and remove hit. entries live in a slab, the table and the list
// order hold slab indices. _alpm_pkghash_free is Drop.

use std::borrow::Borrow;
use std::ffi::c_ulong;

use crate::package::{Package, has_name, pkg_cmp};
use crate::util::{hash_sdbm, until_nul};

// last prime is the largest table, the C gives up past it
const PRIME_LIST: [u32; 145] = [
	11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79,
	83, 89, 97, 103, 109, 113, 127, 137, 139, 149, 157, 167, 179, 193, 199,
	211, 227, 241, 257, 277, 293, 313, 337, 359, 383, 409, 439, 467, 503,
	541, 577, 619, 661, 709, 761, 823, 887, 953, 1031, 1109, 1193, 1289,
	1381, 1493, 1613, 1741, 1879, 2029, 2179, 2357, 2549, 2753, 2971, 3209,
	3469, 3739, 4027, 4349, 4703, 5087, 5503, 5953, 6427, 6949, 7517, 8123,
	8783, 9497, 10273, 11113, 12011, 12983, 14033, 15173, 16411, 17749,
	19183, 20753, 22447, 24281, 26267, 28411, 30727, 33223, 35933, 38873,
	42043, 45481, 49201, 53201, 57557, 62233, 67307, 72817, 78779, 85229,
	92203, 99733, 107897, 116731, 126271, 136607, 147793, 159871, 172933,
	187091, 202409, 218971, 236897, 256279, 277261, 299951, 324503, 351061,
	379787, 410857, 444487, 480881, 520241, 562841, 608903, 658753, 712697,
	771049, 834181, 902483, 976369,
];

const MAX_HASH_LOAD: f64 = 0.68;
const INITIAL_HASH_LOAD: f64 = 0.58;

// alpm_pkghash_t. P is the stored handle: an owned Package for a db cache,
// or a reference / Rc where the packages live elsewhere
#[derive(Clone, Debug)]
pub struct PkgHash<P = Package> {
	// slab index per bucket, None is an empty bucket
	table: Vec<Option<usize>>,
	slab: Vec<Option<P>>,
	// slab holes left by remove, reused by add
	holes: Vec<usize>,
	// slab indices in pkghash->list order
	list: Vec<usize>,
	// list in pkg_cmp order (no add broke it): merge_pos bisects, so a
	// db load's add_sorted calls do not each scan the list
	ordered: bool,
	limit: usize,
}

// bucket count and load limit of _alpm_pkghash_create(size), computed in
// double and truncated back to unsigned. sizes past the prime table find no
// bucket count
fn table_size(size: u32) -> Option<(usize, usize)> {
	let size = (f64::from(size) / INITIAL_HASH_LOAD + 1.0) as u32;
	let buckets = *PRIME_LIST.iter().find(|&&p| p > size)?;
	let limit = (f64::from(buckets) * MAX_HASH_LOAD) as u32;
	Some((buckets as usize, limit as usize))
}

// rehash growth: doubling below 500 buckets, slower above
fn grown(buckets: u32) -> u32 {
	match buckets {
		..500 => buckets * 2,
		500..2000 => buckets * 3 / 2,
		2000..5000 => buckets * 4 / 3,
		_ => buckets + 1,
	}
}

// get_hash_position: first empty bucket probing from the home bucket
fn free_bucket(table: &[Option<usize>], name_hash: c_ulong) -> usize {
	let n = table.len();
	let mut pos = (name_hash % n as c_ulong) as usize;
	while table[pos].is_some() {
		pos = (pos + 1) % n;
	}
	pos
}

impl<P: Borrow<Package>> PkgHash<P> {
	// _alpm_pkghash_create: room for at least size entries before a
	// rehash. None past the largest table (ERANGE in the C)
	pub fn new(size: u32) -> Option<Self> {
		let (buckets, limit) = table_size(size)?;
		Some(PkgHash {
			table: vec![None; buckets],
			slab: Vec::new(),
			holes: Vec::new(),
			list: Vec::new(),
			ordered: true,
			limit,
		})
	}

	// entries
	pub fn len(&self) -> usize {
		self.list.len()
	}

	pub fn is_empty(&self) -> bool {
		self.list.is_empty()
	}

	pub fn buckets(&self) -> usize {
		self.table.len()
	}

	// entries allowed before the next add rehashes
	pub fn limit(&self) -> usize {
		self.limit
	}

	// pkghash->list order
	pub fn iter(&self) -> impl Iterator<Item = &P> {
		self.list.iter().map(|&i| self.entry(i))
	}

	// pkghash->list order, for loading cached packages in place. name
	// and name_hash must not change, the buckets are not rehashed
	pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut P> {
		let mut slots: Vec<Option<&mut P>> =
			self.slab.iter_mut().map(Option::as_mut).collect();
		self.list.iter().map(move |&i| {
			slots[i].take().expect("slab index points at a hole")
		})
	}

	// the entry at list position i, without walking the list
	pub fn at(&self, i: usize) -> Option<&P> {
		Some(self.entry(*self.list.get(i)?))
	}

	// at for loading in place, same rules as iter_mut
	pub fn at_mut(&mut self, i: usize) -> Option<&mut P> {
		let slot = &mut self.slab[*self.list.get(i)?];
		Some(slot.as_mut().expect("slab index points at a hole"))
	}

	fn entry(&self, i: usize) -> &P {
		self.slab[i].as_ref().expect("slab index points at a hole")
	}

	fn name_hash(&self, i: usize) -> c_ulong {
		self.entry(i).borrow().name_hash
	}

	fn hash_at(&self, bucket: usize) -> c_ulong {
		self.name_hash(self.table[bucket].expect("bucket is empty"))
	}

	// alpm_list_mmerge of one node: before the first entry sorting
	// strictly after it, so equal names keep insertion order
	fn merge_pos(&self, pkg: &Package) -> usize {
		let after = |&i: &usize| {
			pkg_cmp(self.entry(i).borrow(), pkg).is_gt()
		};
		if self.ordered {
			// alpm_list_add_sorted's special case: the last item
			// first, a db read in name order appends every time
			if self.list.last().is_none_or(|i| !after(i)) {
				return self.list.len();
			}
			return self.list.partition_point(|i| !after(i));
		}
		self.list.iter().position(after).unwrap_or(self.list.len())
	}

	// rehash: next size up, buckets refilled in old bucket order so
	// probing collisions land as in the C. false when no larger table
	fn rehash(&mut self) -> bool {
		let Some((buckets, limit)) =
			table_size(grown(self.buckets() as u32))
		else {
			return false;
		};
		let old =
			std::mem::replace(&mut self.table, vec![None; buckets]);
		for i in old.into_iter().flatten() {
			let pos = free_bucket(&self.table, self.name_hash(i));
			self.table[pos] = Some(i);
		}
		self.limit = limit;
		true
	}

	fn add_pkg(&mut self, pkg: P, sorted: bool) -> Result<(), P> {
		if self.len() >= self.limit && !self.rehash() {
			return Err(pkg);
		}
		let pos = free_bucket(&self.table, pkg.borrow().name_hash);
		let at = match sorted {
			false => self.list.len(),
			true => self.merge_pos(pkg.borrow()),
		};
		if let Some(&last) = self.list.last().filter(|_| !sorted) {
			let p = self.entry(last).borrow();
			self.ordered &= pkg_cmp(p, pkg.borrow()).is_le();
		}
		let i = match self.holes.pop() {
			Some(i) => {
				self.slab[i] = Some(pkg);
				i
			}
			None => {
				self.slab.push(Some(pkg));
				self.slab.len() - 1
			}
		};
		self.table[pos] = Some(i);
		self.list.insert(at, i);
		Ok(())
	}

	// _alpm_pkghash_add: appended to the list. Err hands pkg back when
	// the table cannot grow
	pub fn add(&mut self, pkg: P) -> Result<(), P> {
		self.add_pkg(pkg, false)
	}

	// _alpm_pkghash_add_sorted: merged into the list by name
	pub fn add_sorted(&mut self, pkg: P) -> Result<(), P> {
		self.add_pkg(pkg, true)
	}

	// _alpm_pkghash_find: slab index of the first entry in probe order
	fn find_index(&self, name: &[u8]) -> Option<usize> {
		let (name, hash) = (until_nul(name), hash_sdbm(name));
		let n = self.buckets();
		let mut pos = (hash % n as c_ulong) as usize;
		while let Some(i) = self.table[pos] {
			if has_name(self.entry(i).borrow(), name, hash) {
				return Some(i);
			}
			pos = (pos + 1) % n;
		}
		None
	}

	// _alpm_pkghash_find
	pub fn find(&self, name: &[u8]) -> Option<&P> {
		self.find_index(name).map(|i| self.entry(i))
	}

	// the entry find returns, for loading it in place. name and
	// name_hash must not change
	pub fn find_mut(&mut self, name: &[u8]) -> Option<&mut P> {
		let i = self.find_index(name)?;
		self.slab[i].as_mut()
	}

	// _alpm_pkghash_remove: drops the first entry in probe order with
	// pkg's name and stored name_hash, returns it
	pub fn remove(&mut self, pkg: &Package) -> Option<P> {
		let n = self.buckets();
		let mut pos = (pkg.name_hash % n as c_ulong) as usize;
		while let Some(i) = self.table[pos] {
			if has_name(
				self.entry(i).borrow(),
				pkg.name_bytes(),
				pkg.name_hash,
			) {
				self.table[pos] = None;
				self.refill(pos);
				return Some(self.release(i));
			}
			pos = (pos + 1) % n;
		}
		None
	}

	fn release(&mut self, i: usize) -> P {
		let at = self.list.iter().position(|&j| j == i).unwrap();
		self.list.remove(at);
		self.holes.push(i);
		self.slab[i].take().unwrap()
	}

	// the backward shift after a remove: entries of the cluster after
	// the hole that would probe into it move up, one at a time, until
	// nothing moves
	fn refill(&mut self, mut pos: usize) {
		let n = self.buckets();
		let mut stop = (pos + 1) % n;
		while self.table[stop].is_some() && stop != pos {
			stop = (stop + 1) % n;
		}
		stop = (n + stop - 1) % n;
		loop {
			let prev = self.move_one_entry(pos, stop);
			if prev == pos {
				break;
			}
			pos = prev;
		}
	}

	// move_one_entry: walks back from end to start, moves the first
	// entry whose probe now ends at start there. returns where it
	// stopped, start when nothing moved
	fn move_one_entry(&mut self, start: usize, mut end: usize) -> usize {
		let n = self.buckets();
		while end != start {
			if free_bucket(&self.table, self.hash_at(end)) == start
			{
				self.table[start] = self.table[end].take();
				break;
			}
			end = (n + end - 1) % n;
		}
		end
	}
}
