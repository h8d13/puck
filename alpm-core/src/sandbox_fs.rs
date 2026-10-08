// port of lib/libalpm/sandbox_fs.c through the landlock crate
//
// the C asks the kernel for its Landlock ABI and drops REFER below 2 and
// TRUNCATE below 3 from the handled rights. the crate keeps the ABI
// number to itself: support of a right is probed with a HardRequirement
// ruleset (handle_access fails for a right the kernel lacks), the number
// in the last debug line comes from the RestrictionStatus. no_new_privs
// stays with the caller like in the C (sandbox::setup_child).
use std::error::Error;
use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;

use landlock::{
	AccessFs, BitFlags, CompatLevel, Compatible, LandlockStatus,
	PathBeneath, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetError,
};
use rustix::fs::{Mode, OFlags};

use crate::dload::{Callbacks, LogLevel, strerror};
use crate::util::until_nul;

// _LANDLOCK_ACCESS_FS_READ
fn fs_read() -> BitFlags<AccessFs> {
	AccessFs::ReadFile | AccessFs::ReadDir
}

// _LANDLOCK_ACCESS_FS_WRITE
fn fs_write() -> BitFlags<AccessFs> {
	AccessFs::WriteFile
		| AccessFs::RemoveDir
		| AccessFs::RemoveFile
		| AccessFs::MakeChar
		| AccessFs::MakeDir
		| AccessFs::MakeReg
		| AccessFs::MakeSock
		| AccessFs::MakeFifo
		| AccessFs::MakeBlock
		| AccessFs::MakeSym
}

// whether the running kernel handles every right in access
fn supported(access: BitFlags<AccessFs>) -> bool {
	Ruleset::default()
		.set_compatibility(CompatLevel::HardRequirement)
		.handle_access(access)
		.is_ok()
}

// strerror(errno) of the failed landlock call inside a crate error
fn os_error(e: &RulesetError) -> Vec<u8> {
	let mut cur: Option<&dyn Error> = Some(e);
	while let Some(err) = cur {
		if let Some(io) = err.downcast_ref::<io::Error>() {
			return strerror(io);
		}
		cur = err.source();
	}
	e.to_string().into_bytes()
}

// open(path, O_PATH | O_CLOEXEC | O_DIRECTORY)
fn open_dir(path: &[u8]) -> io::Result<rustix::fd::OwnedFd> {
	let flags = OFlags::PATH | OFlags::CLOEXEC | OFlags::DIRECTORY;
	let p = OsStr::from_bytes(until_nul(path));
	Ok(rustix::fs::open(p, flags, Mode::empty())?)
}

fn error(cb: &mut dyn Callbacks, parts: &[&[u8]]) -> bool {
	cb.log(LogLevel::Error, &parts.concat());
	false
}

// _alpm_sandbox_fs_restrict_writes_to: / read-only, path read-write, no
// execution anywhere, for the calling thread and what it starts later
pub fn restrict_writes_to(cb: &mut dyn Callbacks, path: &[u8]) -> bool {
	if !supported(AccessFs::ReadFile.into()) {
		return error(
			cb,
			&[b"restricting filesystem access failed because \
			Landlock is not supported by the kernel!\n"],
		);
	}
	let mut handled = fs_read() | fs_write() | AccessFs::Execute;
	if supported(AccessFs::Refer.into()) {
		handled |= AccessFs::Refer;
	} else {
		cb.log(
			LogLevel::Debug,
			b"Landlock ABI < 2, LANDLOCK_ACCESS_FS_REFER \
			is not supported\n",
		);
	}
	if supported(AccessFs::Truncate.into()) {
		handled |= AccessFs::Truncate;
	} else {
		cb.log(
			LogLevel::Debug,
			b"Landlock ABI < 3, LANDLOCK_ACCESS_FS_TRUNCATE \
			is not supported\n",
		);
	}

	let ruleset = Ruleset::default()
		.set_compatibility(CompatLevel::HardRequirement)
		.handle_access(handled)
		.and_then(|r| r.create());
	let ruleset = match ruleset {
		Ok(r) => r.no_new_privs(false),
		Err(e) => {
			return error(
				cb,
				&[
					b"restricting filesystem access failed \
					because the Landlock ruleset could not \
					be created: ",
					&os_error(&e),
					b"\n",
				],
			);
		}
	};

	let root = match open_dir(b"/") {
		Ok(fd) => fd,
		Err(e) => {
			return error(
				cb,
				&[
					b"opening the root filesystem to make it \
					read-only via Landlock failed: ",
					&strerror(&e),
					b"\n",
				],
			);
		}
	};
	let ruleset = match ruleset.add_rule(PathBeneath::new(root, fs_read()))
	{
		Ok(r) => r,
		Err(e) => {
			return error(
				cb,
				&[
					b"restricting filesystem access failed \
					because the Landlock rule for / could \
					not be added: ",
					&os_error(&e),
					b"\n",
				],
			);
		}
	};

	let dir = match open_dir(path) {
		Ok(fd) => fd,
		Err(e) => {
			return error(
				cb,
				&[
					b"opening the download directory to make \
					it writable via Landlock failed: ",
					&strerror(&e),
					b"\n",
				],
			);
		}
	};
	// a subset of the handled rights, smaller on older ABIs
	let allowed = (fs_read() | fs_write() | AccessFs::Truncate) & handled;
	let status = match ruleset.add_rule(PathBeneath::new(dir, allowed)) {
		Err(e) => {
			return error(
				cb,
				&[
					b"restricting filesystem access failed \
					because the Landlock rule for the \
					temporary download directory could not \
					be added: ",
					&os_error(&e),
					b"\n",
				],
			);
		}
		Ok(r) => match r.restrict_self() {
			Ok(s) => s,
			Err(e) => {
				return error(
					cb,
					&[
						b"restricting filesystem access \
						failed because the Landlock \
						ruleset could not be applied: ",
						&os_error(&e),
						b"\n",
					],
				);
			}
		},
	};
	// the kernel's own number when it is newer than the crate
	let abi = match status.landlock {
		LandlockStatus::Available {
			effective_abi,
			kernel_abi,
		} => kernel_abi.unwrap_or(effective_abi as i32),
		_ => 0,
	};
	let msg = [
		&b"filesystem access has been restricted to "[..],
		until_nul(path),
		format!(", Landlock ABI is {abi}\n").as_bytes(),
	]
	.concat();
	cb.log(LogLevel::Debug, &msg);
	true
}
