#![doc = include_str!("../README.md")]

mod error;
pub use error::Error;

pub mod desc;
pub mod files;

mod libalpm;

// Initialize i18n support.
fluent_i18n::i18n!("locales");
