//! The library behind the `hush` binary. It exists so the fuzz targets in
//! `fuzz/` can reach the proxy's parsers; nothing else is a public API.

pub mod harden;
#[cfg(target_os = "macos")]
pub mod keychain;
pub mod names;
mod proxy;
pub mod run;
mod tls;
pub mod vault;

#[cfg(fuzzing)]
pub use proxy::fuzzing;
