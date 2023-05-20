//! ## What is it?
//!
//! Dexios-Core is a library used for managing cryptographic functions and headers that adhere to the Dexios format.
//!
//! ## Security
//!
//! Dexios-Core uses modern, secure and audited<sup>1</sup> AEADs for encryption and decryption.
//!
//! You may find the audits for both AES-256-GCM and XChaCha20-Poly1305 on [the NCC Group's website](https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/).
//!
//! <sup>1</sup> Deoxys-II-256 does not have an official audit, so use it at your own risk
//!
//! ## Who uses Dexios-Core?
//!
//! This library is implemented by [Dexios](https://github.com/brxken128/dexios), a secure command-line file
//! encryption utility.
//!
//! Dexios-Core makes it easy to integrate the Dexios format into your own projects (and if there's a feature that you'd like to see, please don't hesitate to [open a Github issue](https://github.com/brxken128/dexios-core/issues)).
//!
//! ## Donating
//!
//! If you like my work, and want to help support Dexios, or Dexios-Core, feel free to donate! This is not necessary by any means, so please don't feel obliged to do so.
//!
//! ```text
//! XMR: 84zSGS18aHtT3CZjZUnnWpCsz1wmA5f65G6BXisbrvAiH7PxZpP8GorbdjAQYRtfeiANZywwUPjZcHu8eXJeWdafJQFK46G
//! BTC: bc1q8x0r7khrfj40qd0zr5xv3t9nl92rz2387pu48u
//! ETH: 0x9630f95F11dFa8703b71DbF746E5c83A31A3F2DD
//! ```
//!
//! You can read more about Dexios, Dexios-Core and the technical details [in the project's main documentation](https://brxken128.github.io/dexios/)!
//!
//! ## Thank you!
//!
//! Dexios-Core exclusively uses AEADs provided by the [RustCrypto Team](https://github.com/RustCrypto), so I'd like to give them a huge thank you for their hard work (this wouldn't have been possible without them!)
#![forbid(unsafe_code)]
#![warn(clippy::all)]

pub const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod cipher;
pub mod header;
pub mod key;
pub mod primitives;
pub mod protected;
pub mod stream;
pub use aead::Payload;
pub use zeroize::Zeroize;

#[cfg(feature = "visual")]
pub mod visual;
