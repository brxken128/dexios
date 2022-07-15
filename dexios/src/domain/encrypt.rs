use std::cell::RefCell;
use std::io::{Read, Seek, Write};

use dexios_core::cipher::Ciphers;
use dexios_core::header::{HashingAlgorithm, Header, HeaderType, Keyslot};
use dexios_core::primitives::{Mode, ENCRYPTED_MASTER_KEY_LEN};
use dexios_core::protected::Protected;
use dexios_core::stream::EncryptionStreams;

use crate::utils::{gen_master_key, gen_nonce, gen_salt};

#[derive(Debug)]
pub enum Error {
    HashKey,
    EncryptMasterKey,
    EncryptFile,
    WriteHeader,
    GetHeaderSize,
    InitializeStreams,
    InitializeChiphers,
    CreateAad,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;
        match self {
            HashKey => f.write_str("Cannot hash raw key"),
            EncryptMasterKey => f.write_str("Cannot encrypt master key"),
            EncryptFile => f.write_str("Cannot encrypt file"),
            WriteHeader => f.write_str("Cannot write header"),
            GetHeaderSize => f.write_str("Cannot get header size"),
            InitializeStreams => f.write_str("Cannot initialize streams"),
            InitializeChiphers => f.write_str("Cannot initialize chiphers"),
            CreateAad => f.write_str("Cannot create AAD"),
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

pub fn execute<R, W>(req: Request<R, W>) -> Result<(), Error>
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
            .encrypt(&master_key_nonce, master_key.as_slice())
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
                .write(&header.serialize().map_err(|_| Error::WriteHeader)?)
                .map_err(|_| Error::WriteHeader)?;

            let header_size = header
                .get_size()
                .try_into()
                .map_err(|_| Error::GetHeaderSize)?;

            req.writer
                .borrow_mut()
                .seek(std::io::SeekFrom::Current(header_size))
                .map_err(|_| Error::WriteHeader)?;
        }
    }

    let aad = header.create_aad().map_err(|_| Error::CreateAad)?;

    let mut reader = req.reader.borrow_mut();
    let mut writer = req.writer.borrow_mut();
    streams
        .encrypt_file(&mut *reader, &mut *writer, &aad)
        .map_err(|_| Error::EncryptFile)?;

    Ok(())
}

// WARNING! Very expensive tests!
// TODO(pleshevskiy): think about optimizations
#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use dexios_core::header::HeaderVersion;
    use dexios_core::primitives::Algorithm;

    use super::*;

    const PASSWORD: &str = "12345678";

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
            raw_key: Protected::new(PASSWORD.as_bytes().to_vec()),
            header_type: HeaderType {
                version: HeaderVersion::V4,
                algorithm: Algorithm::XChaCha20Poly1305,
                mode: Mode::StreamMode,
            },
            hashing_algorithm: HashingAlgorithm::Blake3Balloon(4),
        };

        match execute(req) {
            Ok(_) => {
                assert_eq!(
                    output_content,
                    vec![
                        222, 4, 14, 1, 12, 1, 58, 206, 16, 183, 233, 128, 23, 223, 81, 30, 214,
                        132, 32, 104, 51, 119, 58, 206, 16, 183, 233, 128, 23, 223, 81, 30, 214,
                        132, 32, 104, 51, 119, 13, 182, 233, 117, 0, 0, 0, 0, 0, 0, 20, 89, 96, 54,
                        65, 206, 200, 72, 45, 30, 157, 115, 226, 226, 143, 30, 140, 244, 42, 175,
                        25, 165, 64, 205, 157, 164, 48, 169, 65, 245, 58, 23, 152, 176, 182, 127,
                        40, 196, 75, 214, 96, 117, 84, 146, 79, 139, 203, 145, 58, 206, 16, 183,
                        233, 128, 23, 223, 81, 30, 214, 132, 32, 104, 51, 119, 13, 182, 233, 117,
                        195, 199, 31, 7, 0, 0, 0, 0, 0, 0, 0, 0, 250, 200, 57, 180, 83, 36, 137,
                        168, 42, 45, 18, 209, 117, 251, 156, 34, 31, 195, 186, 68, 153, 29, 33, 34,
                        91, 103, 67
                    ]
                );
            }
            Err(e) => {
                println!("{:?}", e);
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
            raw_key: Protected::new(PASSWORD.as_bytes().to_vec()),
            header_type: HeaderType {
                version: HeaderVersion::V5,
                algorithm: Algorithm::XChaCha20Poly1305,
                mode: Mode::StreamMode,
            },
            hashing_algorithm: HashingAlgorithm::Blake3Balloon(5),
        };

        match execute(req) {
            Ok(_) => {
                assert_eq!(
                    output_content,
                    vec![
                        222, 5, 14, 1, 12, 1, 58, 206, 16, 183, 233, 128, 23, 223, 81, 30, 214,
                        132, 32, 104, 51, 119, 13, 182, 233, 117, 0, 0, 0, 0, 0, 0, 223, 181, 195,
                        208, 227, 199, 130, 117, 16, 180, 60, 5, 99, 63, 237, 74, 57, 42, 105, 201,
                        46, 98, 70, 165, 126, 155, 110, 199, 222, 255, 65, 13, 126, 76, 132, 204,
                        12, 255, 179, 16, 220, 242, 171, 187, 124, 115, 188, 27, 252, 253, 58, 206,
                        16, 183, 233, 128, 23, 223, 81, 30, 214, 132, 32, 104, 51, 119, 13, 182,
                        233, 117, 195, 199, 31, 7, 58, 206, 16, 183, 233, 128, 23, 223, 81, 30,
                        214, 132, 32, 104, 51, 119, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 250, 200, 57, 180, 83, 36, 137, 168, 42, 45, 18, 74, 46, 70, 96,
                        86, 65, 27, 121, 4, 55, 33, 220, 149, 241, 61, 180
                    ]
                );
            }
            Err(e) => {
                println!("{:?}", e);
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
            raw_key: Protected::new(PASSWORD.as_bytes().to_vec()),
            header_type: HeaderType {
                version: HeaderVersion::V5,
                algorithm: Algorithm::XChaCha20Poly1305,
                mode: Mode::StreamMode,
            },
            hashing_algorithm: HashingAlgorithm::Blake3Balloon(5),
        };

        match execute(req) {
            Ok(_) => {
                assert_eq!(
                    output_content,
                    vec![
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 250, 200, 57, 180, 83, 36,
                        137, 168, 42, 45, 18, 74, 46, 70, 96, 86, 65, 27, 121, 4, 55, 33, 220, 149,
                        241, 61, 180
                    ]
                );
                assert_eq!(
                    output_header,
                    vec![
                        222, 5, 14, 1, 12, 1, 58, 206, 16, 183, 233, 128, 23, 223, 81, 30, 214,
                        132, 32, 104, 51, 119, 13, 182, 233, 117, 0, 0, 0, 0, 0, 0, 223, 181, 195,
                        208, 227, 199, 130, 117, 16, 180, 60, 5, 99, 63, 237, 74, 57, 42, 105, 201,
                        46, 98, 70, 165, 126, 155, 110, 199, 222, 255, 65, 13, 126, 76, 132, 204,
                        12, 255, 179, 16, 220, 242, 171, 187, 124, 115, 188, 27, 252, 253, 58, 206,
                        16, 183, 233, 128, 23, 223, 81, 30, 214, 132, 32, 104, 51, 119, 13, 182,
                        233, 117, 195, 199, 31, 7, 58, 206, 16, 183, 233, 128, 23, 223, 81, 30,
                        214, 132, 32, 104, 51, 119, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0
                    ]
                );
            }
            Err(e) => {
                println!("{:?}", e);
                unreachable!()
            }
        }
    }
}
