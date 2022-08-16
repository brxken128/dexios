//! This module contains all cryptographic primitives used by `dexios-core`
use crate::protected::Protected;
use rand::{prelude::ThreadRng, RngCore};

/// This is the streaming block size
///
/// NOTE: Stream mode can be used to encrypt files less than this size, provided the implementation
/// is correct
pub const BLOCK_SIZE: usize = 1_048_576; // 1024*1024 bytes

/// This is the length of the salt used for password hashing
pub const SALT_LEN: usize = 16; // bytes

pub const MASTER_KEY_LEN: usize = 32;
pub const ENCRYPTED_MASTER_KEY_LEN: usize = 48;
pub const ALGORITHMS_LEN: usize = 3;

/// This is an `enum` containing all AEADs supported by `dexios-core`
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Algorithm {
    Aes256Gcm,
    XChaCha20Poly1305,
    DeoxysII256,
}

/// This is an array containing all AEADs supported by `dexios-core`.
///
/// It can be used by and end-user application to show a list of AEADs that they may use
pub static ALGORITHMS: [Algorithm; ALGORITHMS_LEN] = [
    Algorithm::XChaCha20Poly1305,
    Algorithm::Aes256Gcm,
    Algorithm::DeoxysII256,
];

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Algorithm::Aes256Gcm => write!(f, "AES-256-GCM"),
            Algorithm::XChaCha20Poly1305 => write!(f, "XChaCha20-Poly1305"),
            Algorithm::DeoxysII256 => write!(f, "Deoxys-II-256"),
        }
    }
}

/// This defines the possible modes used for encrypting/decrypting
#[derive(PartialEq, Eq)]
pub enum Mode {
    MemoryMode,
    StreamMode,
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Mode::MemoryMode => write!(f, "Memory Mode"),
            Mode::StreamMode => write!(f, "Stream Mode"),
        }
    }
}

/// This can be used to generate a nonce for encryption
/// It requires both the algorithm and the mode, so it can correctly determine the nonce length
/// This nonce can be passed directly to `EncryptionStreams::initialize()`
///
/// # Examples
///
/// ```rust
/// # use dexios_core::primitives::*;
/// let nonce = gen_nonce(&Algorithm::XChaCha20Poly1305, &Mode::StreamMode);
/// ```
///
#[must_use]
pub fn gen_nonce(algorithm: &Algorithm, mode: &Mode) -> Vec<u8> {
    let nonce_len = get_nonce_len(algorithm, mode);
    let mut nonce = vec![0u8; nonce_len];
    ThreadRng::default().fill_bytes(&mut nonce);
    nonce
}

/// This function calculates the length of the nonce, depending on the data provided
///
/// Stream mode nonces are 4 bytes less than their "memory" mode counterparts, due to `aead::StreamLE31`
///
/// `StreamLE31` contains a 31-bit little endian counter, and a 1-bit "last block" flag, stored as the last 4 bytes of the nonce, this is done to prevent nonce-reuse
#[must_use]
pub fn get_nonce_len(algorithm: &Algorithm, mode: &Mode) -> usize {
    let mut nonce_len = match algorithm {
        Algorithm::Aes256Gcm => 12,
        Algorithm::XChaCha20Poly1305 => 24,
        Algorithm::DeoxysII256 => 15,
    };

    if mode == &Mode::StreamMode {
        nonce_len -= 4;
    }

    nonce_len
}

/// Generates a new protected master key of the specified `MASTER_KEY_LEN`.
///
/// This can be used to generate a master key for encryption.
/// It uses `ThreadRng` to securely generate completely random bytes, with extra protection
/// from some side-channel attacks
///
/// # Examples
///
/// ```rust
/// # use dexios_core::primitives::*;
/// let master_key = gen_master_key();
/// ```
///
#[must_use]
pub fn gen_master_key() -> Protected<[u8; MASTER_KEY_LEN]> {
    let mut master_key = [0u8; MASTER_KEY_LEN];
    ThreadRng::default().fill_bytes(&mut master_key);
    Protected::new(master_key)
}

/// Generates a salt, of the specified `SALT_LEN`
///
/// This salt can be directly passed to `argon2id_hash()` or `balloon_hash()`
///
/// # Examples
///
/// ```rust
/// # use dexios_core::primitives::*;
/// let salt = gen_salt();
/// ```
///
#[must_use]
pub fn gen_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    ThreadRng::default().fill_bytes(&mut salt);
    salt
}
