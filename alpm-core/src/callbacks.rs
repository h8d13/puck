// the frontend callbacks of alpm.h: handle->logcb, eventcb, questioncb,
// progresscb, dlcb (one Callbacks impl) and fetchcb (Fetch). the C's
// function pointer + ctx pairs are one trait object per handle; a method
// left at its default is the C's NULL callback, and a question it does
// not answer keeps the C's zeroed answer.
//
// messages are formatted before the call (the C hands fmt + va_list to
// logcb), translated texts are their msgids (gettext without a locale).

use std::ffi::c_int;

use crate::conflict::Conflict;
use crate::db::Db;
use crate::deps::Depend;
use crate::error::Errno;
use crate::package::Package;

// alpm_loglevel_t, bits as in alpm.h
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(i32)]
pub enum LogLevel {
	Error = 1,
	Warning = 1 << 1,
	Debug = 1 << 2,
	Function = 1 << 3,
}

// alpm_package_operation_t
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum PackageOperation {
	Install = 1,
	Upgrade,
	Reinstall,
	Downgrade,
	Remove,
}

// alpm_hook_when_t
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum HookWhen {
	PreTransaction = 1,
	PostTransaction,
}

// alpm_event_t: the type with its alpm_event_*_t data. Event::kind is
// the alpm_event_type_t value
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event<'e> {
	CheckdepsStart,
	CheckdepsDone,
	FileconflictsStart,
	FileconflictsDone,
	ResolvedepsStart,
	ResolvedepsDone,
	InterconflictsStart,
	InterconflictsDone,
	TransactionStart,
	TransactionDone,
	PackageOperationStart(PackageOp<'e>),
	PackageOperationDone(PackageOp<'e>),
	IntegrityStart,
	IntegrityDone,
	LoadStart,
	LoadDone,
	ScriptletInfo {
		line: &'e [u8],
	},
	DbRetrieveStart,
	DbRetrieveDone,
	DbRetrieveFailed,
	// alpm_event_pkg_retrieve_t on all three, like the C's reused struct
	PkgRetrieveStart {
		num: usize,
		total_size: i64,
	},
	PkgRetrieveDone {
		num: usize,
		total_size: i64,
	},
	PkgRetrieveFailed {
		num: usize,
		total_size: i64,
	},
	DiskspaceStart,
	DiskspaceDone,
	OptdepRemoval {
		pkg: &'e Package,
		optdep: &'e Depend,
	},
	DatabaseMissing {
		dbname: &'e [u8],
	},
	KeyringStart,
	KeyringDone,
	KeyDownloadStart,
	KeyDownloadDone,
	PacnewCreated {
		from_noupgrade: bool,
		oldpkg: Option<&'e Package>,
		newpkg: &'e Package,
		file: &'e [u8],
	},
	PacsaveCreated {
		oldpkg: &'e Package,
		file: &'e [u8],
	},
	HookStart {
		when: HookWhen,
	},
	HookDone {
		when: HookWhen,
	},
	HookRunStart(HookRun<'e>),
	HookRunDone(HookRun<'e>),
}

// alpm_event_package_operation_t: no oldpkg on install, no newpkg on
// remove
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackageOp<'e> {
	pub operation: PackageOperation,
	pub oldpkg: Option<&'e Package>,
	pub newpkg: Option<&'e Package>,
}

// alpm_event_hook_run_t
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HookRun<'e> {
	pub name: &'e [u8],
	pub desc: Option<&'e [u8]>,
	pub position: usize,
	pub total: usize,
}

impl Event<'_> {
	// alpm_event_type_t
	pub fn kind(&self) -> c_int {
		match self {
			Event::CheckdepsStart => 1,
			Event::CheckdepsDone => 2,
			Event::FileconflictsStart => 3,
			Event::FileconflictsDone => 4,
			Event::ResolvedepsStart => 5,
			Event::ResolvedepsDone => 6,
			Event::InterconflictsStart => 7,
			Event::InterconflictsDone => 8,
			Event::TransactionStart => 9,
			Event::TransactionDone => 10,
			Event::PackageOperationStart(_) => 11,
			Event::PackageOperationDone(_) => 12,
			Event::IntegrityStart => 13,
			Event::IntegrityDone => 14,
			Event::LoadStart => 15,
			Event::LoadDone => 16,
			Event::ScriptletInfo { .. } => 17,
			Event::DbRetrieveStart => 18,
			Event::DbRetrieveDone => 19,
			Event::DbRetrieveFailed => 20,
			Event::PkgRetrieveStart { .. } => 21,
			Event::PkgRetrieveDone { .. } => 22,
			Event::PkgRetrieveFailed { .. } => 23,
			Event::DiskspaceStart => 24,
			Event::DiskspaceDone => 25,
			Event::OptdepRemoval { .. } => 26,
			Event::DatabaseMissing { .. } => 27,
			Event::KeyringStart => 28,
			Event::KeyringDone => 29,
			Event::KeyDownloadStart => 30,
			Event::KeyDownloadDone => 31,
			Event::PacnewCreated { .. } => 32,
			Event::PacsaveCreated { .. } => 33,
			Event::HookStart { .. } => 34,
			Event::HookDone { .. } => 35,
			Event::HookRunStart(_) => 36,
			Event::HookRunDone(_) => 37,
		}
	}
}

// alpm_question_t. the answer field starts at the C default (0, picks
// none / no): a callback that leaves it acts like no questioncb
#[derive(Debug)]
pub enum Question<'q> {
	// ALPM_QUESTION_INSTALL_IGNOREPKG: nonzero installs pkg anyway
	InstallIgnorepkg {
		install: c_int,
		pkg: &'q Package,
	},
	// ALPM_QUESTION_REPLACE_PKG
	ReplacePkg {
		replace: c_int,
		oldpkg: &'q Package,
		newpkg: &'q Package,
		newdb: &'q Db,
	},
	// ALPM_QUESTION_CONFLICT_PKG: nonzero removes conflict.package2
	ConflictPkg {
		remove: c_int,
		conflict: &'q Conflict,
	},
	// ALPM_QUESTION_CORRUPTED_PKG
	CorruptedPkg {
		remove: c_int,
		filepath: &'q [u8],
		reason: Errno,
	},
	// ALPM_QUESTION_REMOVE_PKGS: nonzero skips the packages
	RemovePkgs {
		skip: c_int,
		packages: &'q [&'q Package],
	},
	// ALPM_QUESTION_SELECT_PROVIDER: position in providers, out of
	// range picks none
	SelectProvider {
		use_index: c_int,
		providers: &'q [&'q Package],
		depend: &'q Depend,
	},
	// ALPM_QUESTION_IMPORT_KEY: nonzero imports
	ImportKey {
		import: c_int,
		uid: Option<&'q [u8]>,
		fingerprint: &'q [u8],
	},
}

impl Question<'_> {
	// alpm_question_type_t
	pub fn kind(&self) -> c_int {
		match self {
			Question::InstallIgnorepkg { .. } => 1,
			Question::ReplacePkg { .. } => 1 << 1,
			Question::ConflictPkg { .. } => 1 << 2,
			Question::CorruptedPkg { .. } => 1 << 3,
			Question::RemovePkgs { .. } => 1 << 4,
			Question::SelectProvider { .. } => 1 << 5,
			Question::ImportKey { .. } => 1 << 6,
		}
	}

	// alpm_question_any_t.answer: the first int after the type in every
	// variant
	pub fn answer(&self) -> c_int {
		match *self {
			Question::InstallIgnorepkg { install: a, .. }
			| Question::ReplacePkg { replace: a, .. }
			| Question::ConflictPkg { remove: a, .. }
			| Question::CorruptedPkg { remove: a, .. }
			| Question::RemovePkgs { skip: a, .. }
			| Question::SelectProvider { use_index: a, .. }
			| Question::ImportKey { import: a, .. } => a,
		}
	}

	pub fn set_answer(&mut self, answer: c_int) {
		match self {
			Question::InstallIgnorepkg { install: a, .. }
			| Question::ReplacePkg { replace: a, .. }
			| Question::ConflictPkg { remove: a, .. }
			| Question::CorruptedPkg { remove: a, .. }
			| Question::RemovePkgs { skip: a, .. }
			| Question::SelectProvider { use_index: a, .. }
			| Question::ImportKey { import: a, .. } => *a = answer,
		}
	}
}

// alpm_progress_t, discriminants as in alpm.h
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Progress {
	AddStart,
	UpgradeStart,
	DowngradeStart,
	ReinstallStart,
	RemoveStart,
	ConflictsStart,
	DiskspaceStart,
	IntegrityStart,
	LoadStart,
	KeyringStart,
}

// alpm_download_event_type_t with its alpm_download_event_*_t data
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DownloadEvent {
	Init { optional: bool },
	Progress { downloaded: i64, total: i64 },
	Retry { resume: bool },
	// result 0 downloaded, 1 up to date, -1 error (optional files too)
	Completed { total: i64, result: c_int },
}

// logcb (_alpm_log), eventcb (EVENT), questioncb (QUESTION), progresscb
// (PROGRESS) and dlcb. () is a handle without callbacks
pub trait Callbacks {
	// one formatted message per _alpm_log call, '\n' included
	fn log(&mut self, _level: LogLevel, _msg: &[u8]) {}
	fn event(&mut self, _event: &Event<'_>) {}
	fn question(&mut self, _question: &mut Question<'_>) {}
	fn progress(
		&mut self,
		_progress: Progress,
		_pkg: &[u8],
		_percent: c_int,
		_howmany: usize,
		_current: usize,
	) {
	}
	fn download(&mut self, _filename: &[u8], _event: DownloadEvent) {}
}

impl Callbacks for () {}

// _alpm_log of a message given in parts, joined before the call
pub fn logv(cb: &mut dyn Callbacks, level: LogLevel, parts: &[&[u8]]) {
	cb.log(level, &parts.concat());
}

// handle->fetchcb (the frontend's XferCommand): 0 downloaded, 1 up to
// date, -1 error. dload uses its own downloader when there is none
pub trait Fetch {
	fn fetch(&mut self, url: &[u8], localpath: &[u8], force: bool)
	-> c_int;
}
