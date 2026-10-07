// port of pacman's lib/libalpm, safe rust only
pub mod backup;
pub mod base64;
pub mod deps;
pub mod error;
pub mod filelist;
pub mod group;
pub mod package;
pub mod pkghash;
pub mod signing;
pub mod util;
pub mod version;

// upstream release this port tracks, printed where C uses PACKAGE_VERSION
pub const PACKAGE_VERSION: &str = "7.1.0";
