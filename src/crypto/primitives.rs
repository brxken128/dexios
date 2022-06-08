// this file contains all of the AEAD cryptographic enums/impls
// you can add other ciphers to the mix mainly in here, if you so wish
// they just need to be part of the RustCrypto "family"
// https://github.com/RustCrypto/AEADs

// this file sets constants that are used throughout the codebase
// these can be customised easily by anyone to suit their own needs
pub const BLOCK_SIZE: usize = 1_048_576; // 1024*1024 bytes
pub const SALT_LEN: usize = 16; // bytes

#[derive(Copy, Clone)]
pub enum Algorithm {
    Aes256Gcm,
    XChaCha20Poly1305,
    DeoxysII256,
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Algorithm::Aes256Gcm => write!(f, "AES-256-GCM"),
            Algorithm::XChaCha20Poly1305 => write!(f, "XChaCha20-Poly1305"),
            Algorithm::DeoxysII256 => write!(f, "Deoxys-II-256"),
        }
    }
}

#[derive(PartialEq, Eq)]
pub enum CipherMode {
    // could do with a better name
    MemoryMode,
    StreamMode,
}

pub mod cipher;
pub mod stream;
