use std::fs::File;
use std::io::Write;
use std::io::Result;
use aead::{
    stream::{DecryptorLE31, EncryptorLE31},
    Payload,
};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::XChaCha20Poly1305;

// this file sets constants that are used throughout the codebase
// these can be customised easily by anyone to suit their own needs
pub const BLOCK_SIZE: usize = 1_048_576; // 1024*1024 bytes
pub const SALT_LEN: usize = 16; // bytes

pub struct Parameters {
    pub hash_mode: HashMode,
    pub skip: SkipMode,
    pub bench: BenchMode,
    pub password: PasswordMode,
    pub cipher_type: CipherType,
}
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum HashMode {
    CalculateHash,
    NoHash,
}

#[derive(PartialEq, Eq, Copy, Clone)]
pub enum SkipMode {
    ShowPrompts,
    HidePrompts,
}

#[derive(PartialEq, Eq, Copy, Clone)]
pub enum BenchMode {
    WriteToFilesystem,
    BenchmarkInMemory,
}

#[derive(PartialEq, Eq, Copy, Clone)]
pub enum PasswordMode {
    ForceUserProvidedPassword,
    NormalKeySourcePriority,
}

pub enum OutputFile {
    Some(File),
    None,
}

impl OutputFile {
    pub fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        match self {
            OutputFile::Some(file) => file.write_all(buf),
            OutputFile::None => Ok(()),
        }
    }
    pub fn flush(&mut self) -> Result<()> {
        match self {
            OutputFile::Some(file) => file.flush(),
            OutputFile::None => Ok(()),
        }
    }
}

#[derive(Copy, Clone)]
pub enum CipherType {
    AesGcm,
    XChaCha20Poly1305,
}

impl std::fmt::Display for CipherType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            CipherType::AesGcm => write!(f, "AES-256-GCM"),
            CipherType::XChaCha20Poly1305 => write!(f, "XChaCha20-Poly1305"),
        }
    }
}

pub enum EncryptStreamCiphers {
    AesGcm(Box<EncryptorLE31<Aes256Gcm>>),
    XChaCha(Box<EncryptorLE31<XChaCha20Poly1305>>),
}

pub enum DecryptStreamCiphers {
    AesGcm(Box<DecryptorLE31<Aes256Gcm>>),
    XChaCha(Box<DecryptorLE31<XChaCha20Poly1305>>),
}

impl EncryptStreamCiphers {
    pub fn encrypt_next<'msg, 'aad>(
        &mut self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        match self {
            EncryptStreamCiphers::AesGcm(s) => s.encrypt_next(payload),
            EncryptStreamCiphers::XChaCha(s) => s.encrypt_next(payload),
        }
    }

    pub fn encrypt_last<'msg, 'aad>(
        self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        match self {
            EncryptStreamCiphers::AesGcm(s) => s.encrypt_last(payload),
            EncryptStreamCiphers::XChaCha(s) => s.encrypt_last(payload),
        }
    }
}

impl DecryptStreamCiphers {
    pub fn decrypt_next<'msg, 'aad>(
        &mut self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        match self {
            DecryptStreamCiphers::AesGcm(s) => s.decrypt_next(payload),
            DecryptStreamCiphers::XChaCha(s) => s.decrypt_next(payload),
        }
    }

    pub fn decrypt_last<'msg, 'aad>(
        self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        match self {
            DecryptStreamCiphers::AesGcm(s) => s.decrypt_last(payload),
            DecryptStreamCiphers::XChaCha(s) => s.decrypt_last(payload),
        }
    }
}
