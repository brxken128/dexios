use crate::global::enums::{
    Algorithm, BenchMode, CipherMode, EraseMode, HashMode, HeaderVersion, KeyFile, PasswordMode,
    SkipMode,
};
use crate::global::SALT_LEN;

pub struct CryptoParams {
    pub hash_mode: HashMode,
    pub skip: SkipMode,
    pub bench: BenchMode,
    pub password: PasswordMode,
    pub erase: EraseMode,
    pub keyfile: KeyFile,
}

// the information needed to easily serialize a header
pub struct HeaderType {
    pub header_version: HeaderVersion,
    pub cipher_mode: CipherMode,
    pub algorithm: Algorithm,
}

// the data used returned after reading/deserialising a header
pub struct Header {
    pub header_type: HeaderType,
    pub nonce: Vec<u8>,
    pub salt: [u8; SALT_LEN],
}

pub struct HeaderPrefix {
    pub version_info: [u8; 2],
    pub algorithm_info: [u8; 2],
    pub mode_info: [u8; 2],
}