//! Idiomatic Rust bindings for [`P256-Cortex-M4`][p256-cortex-m4] in the spirit of [`p256`][p256].
//!
//! On platforms other than Cortex-M4 and Cortex-M33, the implementation from `p256` is re-used,
//! with the same (simplified) API.
//!
//! If this fallback is not desired, deactivate the `non-cortex-m4-fallback` feature.
//!
//! [p256-cortex-m4]: https://github.com/Emill/P256-Cortex-M4
//! [p256]: https://docs.rs/p256/

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg), feature(doc_auto_cfg))]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

/// Errors.
#[derive(Copy, Clone, Debug)]
pub struct Error;

/// Result type.
pub type Result<T> = core::result::Result<T, Error>;

// pub mod traits;

/// Convenience function, calculates SHA256 hash digest of a slice of bytes.
#[cfg(feature = "prehash")]
pub fn sha256(message: &[u8]) -> [u8; 32] {
    use sha2::digest::Digest;
    let mut hash = sha2::Sha256::new();
    hash.update(message);
    let data = hash.finalize();
    data.into()
}

#[cfg(cortex_m4)]
mod cortex_m4;
#[cfg(cortex_m4)]
pub use cortex_m4::*;

#[cfg(all(feature = "non-cortex-m4-fallback", not(cortex_m4)))]
mod fallback;
#[cfg(all(feature = "non-cortex-m4-fallback", not(cortex_m4)))]
pub use fallback::*;

#[cfg(feature = "signature")]
pub mod signature;
