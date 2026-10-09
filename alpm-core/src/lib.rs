//! port of pacman's lib/libalpm, safe rust only.
//!
//! the crate root is the counterpart of `alpm.h`: one flat namespace,
//! the `alpm_` prefix dropped. a front end opens a [`Handle`]
//! ([`Handle::initialize`]), registers sync dbs ([`Handle::register_syncdb`]),
//! installs its [`Callbacks`] ([`Handle::set_callbacks`]), reads packages
//! through [`Db`] and [`Package`], and runs transactions with
//! [`trans_init`], [`add_pkg`]/[`remove_pkg`]/[`sync_sysupgrade`],
//! [`trans_prepare`], [`trans_commit`], [`trans_release`]. errors are
//! [`Errno`], the C's `alpm_errno_t`.
//!
//! strings are bytes (`&[u8]`, `Vec<u8>`), cut at the first nul like the C
//! reads them. flags keep their C values (`c_int` bit sets).
//!
//! the modules [`regex`], [`setlocale`], [`strftime`] and [`tzfile`] are
//! ports of the glibc pieces pacman's output depends on; [`digest`] wraps
//! the checksum crates.
//!
//! the source is one private module per C file (`handle.rs`, `db.rs`,
//! `deps.rs`, ...). the crate's own tests and the equivalence tests reach
//! every module through the `internals` feature, which is not part of the
//! public surface and may change at any time.
mod add;
mod backup;
mod base64;
mod be_local;
mod be_package;
mod be_sync;
mod callbacks;
mod conflict;
mod db;
mod deps;
pub mod digest;
mod diskspace;
mod dload;
mod error;
pub mod filelist;
mod filter;
mod graph;
mod group;
mod handle;
mod hook;
mod log;
mod mtree;
mod package;
mod pkghash;
pub mod regex;
mod remove;
mod sandbox;
mod sandbox_fs;
mod sandbox_syscalls;
pub mod setlocale;
mod signing;
pub mod strftime;
mod sync;
mod tar;
mod trans;
pub mod tzfile;
mod util;
mod version;

#[cfg(feature = "internals")]
pub mod internals;

/// upstream release this port tracks, printed where C uses PACKAGE_VERSION
pub const PACKAGE_VERSION: &str = "7.1.0";
/// alpm_version(): libalpm's meson LIB_VERSION of that release
pub const LIB_VERSION: &str = "16.0.1";

// the public surface, by C file
pub use add::add_pkg;
pub use backup::Backup;
pub use be_local::{
	INFRQ_ALL, INFRQ_BASE, INFRQ_DESC, INFRQ_DSIZE, INFRQ_FILES,
	INFRQ_SCRIPTLET, LocalDb, MtreeEntry, MtreeError, MtreeType,
};
pub use be_package::{
	PkgInvalidReason, PkgLoadError, changelog, pkg_load, pkg_load_level,
};
pub use be_sync::{
	SyncDbError, SyncDbInvalidReason, db_update, get_validation,
};
pub use callbacks::{
	Callbacks, DownloadEvent, Event, Fetch, HookRun, HookWhen, LogLevel,
	PackageOp, PackageOperation, Progress, Question,
};
pub use conflict::{
	Conflict, FileConflict, FileConflictType, FileConflicts, checkconflicts,
};
pub use db::{
	CacheError, DB_USAGE_ALL, DB_USAGE_INSTALL, DB_USAGE_SEARCH,
	DB_USAGE_SYNC, DB_USAGE_UPGRADE, Db,
};
pub use deps::{
	DbPkgs, DepMissing, DepMod, Depend, DepsEnv, DepsOpts, checkdeps,
	dep_compute_string, dep_from_string, depcmp_literal,
	find_dbs_satisfier, find_satisfier,
};
pub use error::Errno;
pub use group::Group;
pub use handle::{DbsMut, Handle, Interrupt};
pub use log::{local_offset, now_secs};
pub use package::{
	DbCaches, PKG_VALIDATION_MD5SUM, PKG_VALIDATION_NONE,
	PKG_VALIDATION_SHA256SUM, PKG_VALIDATION_SIGNATURE,
	PKG_VALIDATION_UNKNOWN, Package, PkgFrom, PkgReason, PkgXData,
	compute_optionalfor, compute_requiredby, pkg_cmp, pkg_find,
	pkg_should_ignore,
};
pub use pkghash::PkgHash;
pub use remove::remove_pkg;
pub use sandbox::{
	ExecError, IgnoreSignals, SandboxExec, helper_entry, quit_default,
	signals_ignored,
};
pub use signing::{
	DecodeError, KeyidError, Keyring, PgpKey, SIG_DATABASE,
	SIG_DATABASE_MARGINAL_OK, SIG_DATABASE_OPTIONAL,
	SIG_DATABASE_UNKNOWN_OK, SIG_PACKAGE, SIG_PACKAGE_MARGINAL_OK,
	SIG_PACKAGE_OPTIONAL, SIG_PACKAGE_UNKNOWN_OK, SIG_USE_DEFAULT,
	SigResult, SigStatus, SigValidity, db_check_pgp_signature,
	decode_signature, extract_keyid, pkg_check_pgp_signature,
};
pub use sync::{
	dbs_satisfier, find_group_pkgs, pkg_download_size,
	sync_get_new_version, sync_sysupgrade,
};
pub use trans::{
	CommitData, CommitError, InitError, PrepareData, PrepareError,
	TRANS_FLAG_ALLDEPS, TRANS_FLAG_ALLEXPLICIT, TRANS_FLAG_CASCADE,
	TRANS_FLAG_DBONLY, TRANS_FLAG_DOWNLOADONLY, TRANS_FLAG_NEEDED,
	TRANS_FLAG_NOCONFLICTS, TRANS_FLAG_NODEPS, TRANS_FLAG_NODEPVERSION,
	TRANS_FLAG_NOHOOKS, TRANS_FLAG_NOLOCK, TRANS_FLAG_NOSAVE,
	TRANS_FLAG_NOSCRIPTLET, TRANS_FLAG_RECURSE, TRANS_FLAG_RECURSEALL,
	TRANS_FLAG_UNNEEDED, Trans, TransPkg, TransState, trans_commit,
	trans_get_add, trans_get_flags, trans_get_remove, trans_init,
	trans_interrupt, trans_prepare, trans_release,
};
pub use util::{compute_md5sum, compute_sha256sum, fnmatch, getuid, strerror};
pub use version::vercmp;
