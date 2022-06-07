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

#[derive(PartialEq, Eq)]
pub enum CipherMode {
    // could do with a better name
    MemoryMode,
    StreamMode,
}

pub mod cipher;
pub mod stream;
