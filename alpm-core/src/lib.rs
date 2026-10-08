// port of pacman's lib/libalpm, safe rust only
pub mod add;
pub mod backup;
pub mod base64;
pub mod be_local;
pub mod be_package;
pub mod be_sync;
pub mod callbacks;
pub mod conflict;
pub mod db;
pub mod deps;
pub mod diskspace;
pub mod dload;
pub mod error;
pub mod filelist;
pub mod filter;
pub mod graph;
pub mod group;
pub mod handle;
pub mod hook;
pub mod log;
pub mod mtree;
pub mod package;
pub mod pkghash;
pub mod regex;
pub mod remove;
pub mod sandbox;
pub mod sandbox_fs;
pub mod sandbox_syscalls;
pub mod signing;
pub mod sync;
pub mod tar;
pub mod trans;
pub mod util;
pub mod version;

// upstream release this port tracks, printed where C uses PACKAGE_VERSION
pub const PACKAGE_VERSION: &str = "7.1.0";
// alpm_version(): libalpm's meson LIB_VERSION of that release
pub const LIB_VERSION: &str = "16.0.1";
