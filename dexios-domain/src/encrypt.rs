//! This provides functionality for encryption that adheres to the Dexios format.

use std::cell::RefCell;
use std::io::{Read, Seek, Write};

use core::cipher::Ciphers;
use core::header::{HashingAlgorithm, Header, HeaderType, Keyslot};
use core::primitives::{Mode, ENCRYPTED_MASTER_KEY_LEN};
use core::protected::Protected;
use core::stream::EncryptionStreams;

use crate::utils::{gen_master_key, gen_nonce, gen_salt};

#[derive(Debug)]
pub enum Error {
    ResetCursorPosition,
    HashKey,
    EncryptMasterKey,
    EncryptFile,
    WriteHeader,
    InitializeStreams,
    InitializeChiphers,
    CreateAad,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ResetCursorPosition => f.write_str("Unable to reset cursor position"),
            Error::HashKey => f.write_str("Cannot hash raw key"),
            Error::EncryptMasterKey => f.write_str("Cannot encrypt master key"),
            Error::EncryptFile => f.write_str("Cannot encrypt file"),
            Error::WriteHeader => f.write_str("Cannot write header"),
            Error::InitializeStreams => f.write_str("Cannot initialize streams"),
            Error::InitializeChiphers => f.write_str("Cannot initialize chiphers"),
            Error::CreateAad => f.write_str("Cannot create AAD"),
        }
    }
}

impl std::error::Error for Error {}

pub struct Request<'a, R, W>
where
    R: Read + Seek,
    W: Write + Seek,
{
    pub reader: &'a RefCell<R>,
    pub writer: &'a RefCell<W>,
    pub header_writer: Option<&'a RefCell<W>>,
    pub raw_key: Protected<Vec<u8>>,
    // TODO: don't use external types in logic
    pub header_type: HeaderType,
    pub hashing_algorithm: HashingAlgorithm,
}

pub fn execute<R, W>(req: Request<'_, R, W>) -> Result<(), Error>
where
    R: Read + Seek,
    W: Write + Seek,
{
    // 1. generate salt
    let salt = gen_salt();

    // 2. hash key
    let key = req
        .hashing_algorithm
        .hash(req.raw_key, &salt)
        .map_err(|_| Error::HashKey)?;

    // 3. initialize cipher
    let cipher = Ciphers::initialize(key, &req.header_type.algorithm)
        .map_err(|_| Error::InitializeChiphers)?;

    // 4. generate master key
    let master_key = gen_master_key();

    let master_key_nonce = gen_nonce(&req.header_type.algorithm, &Mode::MemoryMode);

    // 5. encrypt master key
    let master_key_encrypted = {
        let encrypted_key = cipher
            .encrypt(master_key_nonce.as_slice(), master_key.as_slice())
            .map_err(|_| Error::EncryptMasterKey)?;

        let mut encrypted_key_arr = [0u8; ENCRYPTED_MASTER_KEY_LEN];
        let len = ENCRYPTED_MASTER_KEY_LEN.min(encrypted_key.len());
        encrypted_key_arr[..len].copy_from_slice(&encrypted_key[..len]);

        encrypted_key_arr
    };

    let keyslot = Keyslot {
        encrypted_key: master_key_encrypted,
        nonce: master_key_nonce,
        hash_algorithm: req.hashing_algorithm,
        salt,
    };

    let keyslots = vec![keyslot];

    let header_nonce = gen_nonce(&req.header_type.algorithm, &req.header_type.mode);
    let streams =
        EncryptionStreams::initialize(master_key, &header_nonce, &req.header_type.algorithm)
            .map_err(|_| Error::InitializeStreams)?;

    let header = Header {
        header_type: req.header_type,
        nonce: header_nonce,
        salt: None,
        keyslots: Some(keyslots),
    };

    req.writer
        .borrow_mut()
        .rewind()
        .map_err(|_| Error::ResetCursorPosition)?;

    match req.header_writer {
        None => {
            req.writer
                .borrow_mut()
                .write(&header.serialize().map_err(|_| Error::WriteHeader)?)
                .map_err(|_| Error::WriteHeader)?;
        }
        Some(header_writer) => {
            header_writer
                .borrow_mut()
                .rewind()
                .map_err(|_| Error::ResetCursorPosition)?;

            header_writer
                .borrow_mut()
                .write(&header.serialize().map_err(|_| Error::WriteHeader)?)
                .map_err(|_| Error::WriteHeader)?;
        }
    }

    let aad = header.create_aad().map_err(|_| Error::CreateAad)?;

    let mut reader = req.reader.borrow_mut();
    reader.rewind().map_err(|_| Error::ResetCursorPosition)?;

    let mut writer = req.writer.borrow_mut();
    streams
        .encrypt_file(&mut *reader, &mut *writer, &aad)
        .map_err(|_| Error::EncryptFile)?;

    Ok(())
}

// WARNING! Very expensive tests!
// TODO(pleshevskiy): think about optimizations
#[cfg(test)]
pub mod tests {
    use std::io::Cursor;

    use core::header::HeaderVersion;
    use core::primitives::Algorithm;

    use super::*;

    pub const PASSWORD: &[u8; 8] = b"12345678";

    pub const V4_ENCRYPTED_CONTENT: [u8; 155] = [
        222, 4, 14, 1, 12, 1, 58, 206, 16, 183, 233, 128, 23, 223, 81, 30, 214, 132, 32, 104, 51,
        119, 173, 240, 60, 45, 230, 243, 58, 160, 69, 50, 217, 192, 66, 223, 124, 190, 148, 91, 92,
        129, 0, 0, 0, 0, 0, 0, 147, 32, 67, 18, 249, 211, 189, 86, 187, 159, 234, 160, 94, 80, 72,
        68, 231, 114, 132, 105, 164, 177, 26, 217, 46, 168, 97, 110, 34, 27, 13, 16, 14, 111, 3,
        109, 218, 232, 212, 78, 188, 55, 91, 106, 97, 74, 238, 210, 173, 240, 60, 45, 230, 243, 58,
        160, 69, 50, 217, 192, 66, 223, 124, 190, 148, 91, 92, 129, 50, 126, 110, 254, 0, 0, 0, 0,
        0, 0, 0, 0, 14, 110, 105, 217, 74, 171, 173, 103, 11, 136, 119, 98, 145, 17, 70, 84, 144,
        143, 154, 244, 82, 201, 85, 13, 187, 85, 89,
    ];

    pub const V5_ENCRYPTED_CONTENT: [u8; 443] = [
        222, 5, 14, 1, 12, 1, 173, 240, 60, 45, 230, 243, 58, 160, 69, 50, 217, 192, 66, 223, 124,
        190, 148, 91, 92, 129, 0, 0, 0, 0, 0, 0, 223, 181, 71, 240, 140, 106, 41, 36, 82, 150, 105,
        215, 159, 108, 234, 246, 25, 19, 65, 206, 177, 146, 15, 174, 209, 129, 82, 2, 62, 76, 129,
        34, 136, 189, 11, 98, 105, 54, 146, 71, 102, 166, 97, 177, 207, 62, 194, 132, 38, 87, 173,
        240, 60, 45, 230, 243, 58, 160, 69, 50, 217, 192, 66, 223, 124, 190, 148, 91, 92, 129, 50,
        126, 110, 254, 58, 206, 16, 183, 233, 128, 23, 223, 81, 30, 214, 132, 32, 104, 51, 119, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14, 110, 105, 217, 74,
        171, 173, 103, 11, 136, 119, 172, 145, 72, 239, 74, 217, 63, 245, 222, 31, 164, 139, 146,
        71, 165, 91,
    ];

    pub const V5_ENCRYPTED_FULL_DETACHED_CONTENT: [u8; 27] = [
        14, 110, 105, 217, 74, 171, 173, 103, 11, 136, 119, 172, 145, 72, 239, 74, 217, 63, 245,
        222, 31, 164, 139, 146, 71, 165, 91,
    ];
    pub const V5_ENCRYPTED_DETACHED_CONTENT: [u8; 443] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14, 110, 105,
        217, 74, 171, 173, 103, 11, 136, 119, 172, 145, 72, 239, 74, 217, 63, 245, 222, 31, 164,
        139, 146, 71, 165, 91,
    ];
    pub const V5_ENCRYPTED_DETACHED_HEADER: [u8; 416] = [
        222, 5, 14, 1, 12, 1, 173, 240, 60, 45, 230, 243, 58, 160, 69, 50, 217, 192, 66, 223, 124,
        190, 148, 91, 92, 129, 0, 0, 0, 0, 0, 0, 223, 181, 71, 240, 140, 106, 41, 36, 82, 150, 105,
        215, 159, 108, 234, 246, 25, 19, 65, 206, 177, 146, 15, 174, 209, 129, 82, 2, 62, 76, 129,
        34, 136, 189, 11, 98, 105, 54, 146, 71, 102, 166, 97, 177, 207, 62, 194, 132, 38, 87, 173,
        240, 60, 45, 230, 243, 58, 160, 69, 50, 217, 192, 66, 223, 124, 190, 148, 91, 92, 129, 50,
        126, 110, 254, 58, 206, 16, 183, 233, 128, 23, 223, 81, 30, 214, 132, 32, 104, 51, 119, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    #[test]
    fn should_encrypt_content_with_v4_version() {
        let mut input_content = b"Hello world";
        let input_cur = RefCell::new(Cursor::new(&mut input_content));

        let mut output_content = vec![];
        let output_cur = RefCell::new(Cursor::new(&mut output_content));

        let req = Request {
            reader: &input_cur,
            writer: &output_cur,
            header_writer: None,
            raw_key: Protected::new(PASSWORD.to_vec()),
            header_type: HeaderType {
                version: HeaderVersion::V4,
                algorithm: Algorithm::XChaCha20Poly1305,
                mode: Mode::StreamMode,
            },
            hashing_algorithm: HashingAlgorithm::Blake3Balloon(4),
        };

        match execute(req) {
            Ok(_) => {
                assert_eq!(output_content, V4_ENCRYPTED_CONTENT.to_vec());
            }
            Err(e) => {
                println!("{e:?}");
                unreachable!()
            }
        }
    }

    #[test]
    fn should_encrypt_content_with_v5_version() {
        let mut input_content = b"Hello world";
        let input_cur = RefCell::new(Cursor::new(&mut input_content));

        let mut output_content = vec![];
        let output_cur = RefCell::new(Cursor::new(&mut output_content));

        let req = Request {
            reader: &input_cur,
            writer: &output_cur,
            header_writer: None,
            raw_key: Protected::new(PASSWORD.to_vec()),
            header_type: HeaderType {
                version: HeaderVersion::V5,
                algorithm: Algorithm::XChaCha20Poly1305,
                mode: Mode::StreamMode,
            },
            hashing_algorithm: HashingAlgorithm::Blake3Balloon(5),
        };

        match execute(req) {
            Ok(_) => {
                assert_eq!(output_content, V5_ENCRYPTED_CONTENT.to_vec());
            }
            Err(e) => {
                println!("{e:?}");
                unreachable!()
            }
        }
    }

    #[test]
    fn should_save_header_separately() {
        let mut input_content = b"Hello world";
        let input_cur = RefCell::new(Cursor::new(&mut input_content));

        let mut output_content = vec![];
        let output_cur = RefCell::new(Cursor::new(&mut output_content));

        let mut output_header = vec![];
        let output_header_cur = RefCell::new(Cursor::new(&mut output_header));

        let req = Request {
            reader: &input_cur,
            writer: &output_cur,
            header_writer: Some(&output_header_cur),
            raw_key: Protected::new(PASSWORD.to_vec()),
            header_type: HeaderType {
                version: HeaderVersion::V5,
                algorithm: Algorithm::XChaCha20Poly1305,
                mode: Mode::StreamMode,
            },
            hashing_algorithm: HashingAlgorithm::Blake3Balloon(5),
        };

        match execute(req) {
            Ok(_) => {
                assert_eq!(output_content, V5_ENCRYPTED_FULL_DETACHED_CONTENT.to_vec());
                assert_eq!(output_header, V5_ENCRYPTED_DETACHED_HEADER.to_vec());
            }
            Err(e) => {
                println!("{e:?}");
                unreachable!()
            }
        }
    }
}
