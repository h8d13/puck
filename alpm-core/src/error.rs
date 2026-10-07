// port of lib/libalpm/error.c: alpm_errno_t and alpm_strerror
//
// messages are the untranslated gettext msgids, what the C returns in the
// C locale. alpm_errno(handle) is not ported, it only reads a handle field.

use std::ffi::c_int;
use std::fmt;

// alpm_errno_t from alpm.h, same order so the discriminants match
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum Errno {
	Ok = 0,
	Memory,
	System,
	Badperms,
	NotAFile,
	NotADir,
	WrongArgs,
	DiskSpace,
	HandleNull,
	HandleNotNull,
	HandleLock,
	DbOpen,
	DbCreate,
	DbNull,
	DbNotNull,
	DbNotFound,
	DbInvalid,
	DbInvalidSig,
	DbVersion,
	DbWrite,
	DbRemove,
	ServerBadUrl,
	ServerNone,
	TransNotNull,
	TransNull,
	TransDupTarget,
	TransDupFilename,
	TransNotInitialized,
	TransNotPrepared,
	TransAbort,
	TransType,
	TransNotLocked,
	TransHookFailed,
	PkgNotFound,
	PkgIgnored,
	PkgInvalid,
	PkgInvalidChecksum,
	PkgInvalidSig,
	PkgMissingSig,
	PkgOpen,
	PkgCantRemove,
	PkgInvalidName,
	PkgInvalidArch,
	SigMissing,
	SigInvalid,
	UnsatisfiedDeps,
	ConflictingDeps,
	FileConflicts,
	RetrievePrepare,
	Retrieve,
	InvalidRegex,
	Libarchive,
	Libcurl,
	ExternalDownload,
	Gpgme,
	MissingCapabilitySignatures,
}

impl Errno {
	// every variant in discriminant order, ALL[i] as c_int == i
	pub const ALL: [Errno; 56] = {
		use Errno::*;
		[
			Ok,
			Memory,
			System,
			Badperms,
			NotAFile,
			NotADir,
			WrongArgs,
			DiskSpace,
			HandleNull,
			HandleNotNull,
			HandleLock,
			DbOpen,
			DbCreate,
			DbNull,
			DbNotNull,
			DbNotFound,
			DbInvalid,
			DbInvalidSig,
			DbVersion,
			DbWrite,
			DbRemove,
			ServerBadUrl,
			ServerNone,
			TransNotNull,
			TransNull,
			TransDupTarget,
			TransDupFilename,
			TransNotInitialized,
			TransNotPrepared,
			TransAbort,
			TransType,
			TransNotLocked,
			TransHookFailed,
			PkgNotFound,
			PkgIgnored,
			PkgInvalid,
			PkgInvalidChecksum,
			PkgInvalidSig,
			PkgMissingSig,
			PkgOpen,
			PkgCantRemove,
			PkgInvalidName,
			PkgInvalidArch,
			SigMissing,
			SigInvalid,
			UnsatisfiedDeps,
			ConflictingDeps,
			FileConflicts,
			RetrievePrepare,
			Retrieve,
			InvalidRegex,
			Libarchive,
			Libcurl,
			ExternalDownload,
			Gpgme,
			MissingCapabilitySignatures,
		]
	};

	pub fn from_raw(err: c_int) -> Option<Errno> {
		usize::try_from(err)
			.ok()
			.and_then(|i| Self::ALL.get(i).copied())
	}

	// alpm_strerror. Ok has no case in the C switch, falls to default
	pub fn strerror(self) -> &'static str {
		use Errno::*;
		match self {
			Memory => "out of memory!",
			System => "unexpected system error",
			Badperms => "permission denied",
			NotAFile => "could not find or read file",
			NotADir => "could not find or read directory",
			WrongArgs => "wrong or NULL argument passed",
			DiskSpace => "not enough free disk space",
			HandleNull => "library not initialized",
			HandleNotNull => "library already initialized",
			HandleLock => "unable to lock database",
			DbOpen => "could not open database",
			DbCreate => "could not create database",
			DbNull => "database not initialized",
			DbNotNull => "database already registered",
			DbNotFound => "could not find database",
			DbInvalid => "invalid or corrupted database",
			DbInvalidSig => {
				"invalid or corrupted database (PGP signature)"
			}
			DbVersion => "database is incorrect version",
			DbWrite => "could not update database",
			DbRemove => "could not remove database entry",
			ServerBadUrl => "invalid url for server",
			ServerNone => "no servers configured for repository",
			TransNotNull => "transaction already initialized",
			TransNull => "transaction not initialized",
			TransDupTarget => "duplicate target",
			TransDupFilename => "duplicate filename",
			TransNotInitialized => "transaction not initialized",
			TransNotPrepared => "transaction not prepared",
			TransAbort => "transaction aborted",
			TransType => {
				"operation not compatible with the transaction type"
			}
			TransNotLocked => {
				"transaction commit attempt when database is not \
				 locked"
			}
			TransHookFailed => "failed to run transaction hooks",
			PkgNotFound => "could not find or read package",
			PkgIgnored => "operation cancelled due to ignorepkg",
			PkgInvalid => "invalid or corrupted package",
			PkgInvalidChecksum => {
				"invalid or corrupted package (checksum)"
			}
			PkgInvalidSig => {
				"invalid or corrupted package (PGP signature)"
			}
			PkgMissingSig => "package missing required signature",
			PkgOpen => "cannot open package file",
			PkgCantRemove => "cannot remove all files for package",
			PkgInvalidName => "package filename is not valid",
			PkgInvalidArch => "package architecture is not valid",
			SigMissing => "missing PGP signature",
			SigInvalid => "invalid PGP signature",
			UnsatisfiedDeps => "could not satisfy dependencies",
			ConflictingDeps => "conflicting dependencies",
			FileConflicts => "conflicting files",
			RetrievePrepare => "failed to initialize download",
			Retrieve => "failed to retrieve some files",
			InvalidRegex => "invalid regular expression",
			Libarchive => "libarchive error",
			Libcurl => "download library error",
			Gpgme => "gpgme error",
			ExternalDownload => {
				"error invoking external downloader"
			}
			MissingCapabilitySignatures => {
				"compiled without signature support"
			}
			Ok => UNEXPECTED,
		}
	}
}

const UNEXPECTED: &str = "unexpected error";

// alpm_strerror on a raw value: out of range values hit the C default
pub fn strerror(err: c_int) -> &'static str {
	Errno::from_raw(err).map_or(UNEXPECTED, Errno::strerror)
}

impl fmt::Display for Errno {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.strerror())
	}
}

impl std::error::Error for Errno {}
