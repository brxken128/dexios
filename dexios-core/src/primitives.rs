//! This module contains all cryptographic primitives used by `dexios-core`

/// This is the streaming block size
///
/// NOTE: Stream mode can be used to encrypt files less than this size, provided the implementation is correct
pub const BLOCK_SIZE: usize = 1_048_576; // 1024*1024 bytes

/// This is the length of the salt used for password hashing
pub const SALT_LEN: usize = 16; // bytes

/// This is an `enum` containing all AEADs supported by `dexios-core`
#[derive(Copy, Clone, PartialEq)]
pub enum Algorithm {
    Aes256Gcm,
    XChaCha20Poly1305,
    #[cfg(feature = "deoxys_v2_256")]
    DeoxysII256,
}

#[cfg(feature = "deoxys_v2_256")]
const ALGORITHMS_LEN: usize = 3;
#[cfg(not(feature = "deoxys_v2_256"))]
const ALGORITHMS_LEN: usize = 2;

/// This is an array containing all AEADs supported by `dexios-core`.
///
/// It can be used by and end-user application to show a list of AEADs that they may use
pub static ALGORITHMS: [Algorithm; ALGORITHMS_LEN] = [
    Algorithm::XChaCha20Poly1305,
    Algorithm::Aes256Gcm,
    #[cfg(feature = "deoxys_v2_256")]
    Algorithm::DeoxysII256,
];

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Algorithm::Aes256Gcm => write!(f, "AES-256-GCM"),
            Algorithm::XChaCha20Poly1305 => write!(f, "XChaCha20-Poly1305"),
            #[cfg(feature = "deoxys_v2_256")]
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
/// ```rust,ignore
/// let nonce = gen_nonce(&Algorithm::XChaCha20Poly1305, &Mode::StreamMode);
/// ```
///
#[must_use]
pub fn gen_nonce(algorithm: &Algorithm, mode: &Mode) -> Vec<u8> {
    use rand::{prelude::StdRng, RngCore, SeedableRng};

    let mut nonce_len = match algorithm {
        Algorithm::Aes256Gcm => 12,
        Algorithm::XChaCha20Poly1305 => 24,
        #[cfg(feature = "deoxys_v2_256")]
        Algorithm::DeoxysII256 => 15,
    };

    if mode == &Mode::StreamMode {
        nonce_len -= 4;
    }

    let mut nonce = vec![0u8; nonce_len];
    StdRng::from_entropy().fill_bytes(&mut nonce);
    nonce
}
