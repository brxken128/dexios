use std::cell::RefCell;
use std::io::{Read, Seek, Write};

use core::cipher::Ciphers;
use core::header::{Header, HeaderType};
use core::key::decrypt_master_key;
use core::primitives::Mode;
use core::protected::Protected;
use core::stream::DecryptionStreams;

#[derive(Debug)]
pub enum Error {
    InitializeChiphers,
    InitializeStreams,
    DeserializeHeader,
    ReadEncryptedData,
    DecryptMasterKey,
    DecryptData,
    WriteData,
    RewindDataReader,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InitializeChiphers => f.write_str("Cannot initialize chiphers"),
            Error::InitializeStreams => f.write_str("Cannot initialize streams"),
            Error::DeserializeHeader => f.write_str("Cannot deserialize header"),
            Error::ReadEncryptedData => f.write_str("Unable to read encrypted data"),
            Error::DecryptMasterKey => f.write_str("Cannot decrypt master key"),
            Error::DecryptData => f.write_str("Unable to decrypt data"),
            Error::WriteData => f.write_str("Unable to write data"),
            Error::RewindDataReader => f.write_str("Unable to rewind the reader"),
        }
    }
}

impl std::error::Error for Error {}

pub type OnDecryptedHeaderFn = Box<dyn FnOnce(&HeaderType)>;

pub struct Request<'a, R, W>
where
    R: Read + Seek,
    W: Write + Seek,
{
    pub header_reader: Option<&'a RefCell<R>>,
    pub reader: &'a RefCell<R>,
    pub writer: &'a RefCell<W>,
    pub raw_key: Protected<Vec<u8>>,
    pub on_decrypted_header: Option<OnDecryptedHeaderFn>,
}

pub fn execute<R, W>(req: Request<'_, R, W>) -> Result<(), Error>
where
    R: Read + Seek,
    W: Write + Seek,
{
    let (header, aad) = match req.header_reader {
        Some(header_reader) => {
            let (header, aad) = Header::deserialize(&mut *header_reader.borrow_mut())
                .map_err(|_| Error::DeserializeHeader)?;

            // Try reading an empty header from the content.
            #[allow(clippy::cast_possible_truncation)]
            let mut header_bytes = vec![0u8; header.get_size() as usize];

            req.reader
                .borrow_mut()
                .read_exact(&mut header_bytes)
                .or_else(|e| {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        Ok(())
                    } else {
                        Err(e)
                    }
                })
                .map_err(|_| Error::ReadEncryptedData)?;

            if !header_bytes.into_iter().all(|b| b == 0) {
                // And return the cursor position to the start if it wasn't found
                req.reader
                    .borrow_mut()
                    .rewind()
                    .map_err(|_| Error::RewindDataReader)?;
            }

            (header, aad)
        }
        None => Header::deserialize(&mut *req.reader.borrow_mut())
            .map_err(|_| Error::DeserializeHeader)?,
    };

    if let Some(cb) = req.on_decrypted_header {
        cb(&header.header_type);
    }

    match header.header_type.mode {
        Mode::MemoryMode => {
            let mut encrypted_data = Vec::new();
            req.reader
                .borrow_mut()
                .read_to_end(&mut encrypted_data)
                .map_err(|_| Error::ReadEncryptedData)?;

            let master_key =
                decrypt_master_key(req.raw_key, &header).map_err(|_| Error::DecryptMasterKey)?;

            let ciphers = Ciphers::initialize(master_key, &header.header_type.algorithm)
                .map_err(|_| Error::InitializeChiphers)?;

            let payload = core::Payload {
                aad: &aad,
                msg: &encrypted_data,
            };

            let decrypted_bytes = ciphers
                .decrypt(&header.nonce, payload)
                .map_err(|_| Error::DecryptData)?;

            req.writer
                .borrow_mut()
                .write_all(&decrypted_bytes)
                .map_err(|_| Error::WriteData)?;
        }
        Mode::StreamMode => {
            let master_key =
                decrypt_master_key(req.raw_key, &header).map_err(|_| Error::DecryptMasterKey)?;

            let streams = DecryptionStreams::initialize(
                master_key,
                &header.nonce,
                &header.header_type.algorithm,
            )
            .map_err(|_| Error::InitializeStreams)?;

            streams
                .decrypt_file(
                    &mut *req.reader.borrow_mut(),
                    &mut *req.writer.borrow_mut(),
                    &aad,
                )
                .map_err(|_| Error::DecryptData)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    use crate::encrypt::tests::{
        PASSWORD, V4_ENCRYPTED_CONTENT, V5_ENCRYPTED_CONTENT, V5_ENCRYPTED_DETACHED_CONTENT,
        V5_ENCRYPTED_DETACHED_HEADER, V5_ENCRYPTED_FULL_DETACHED_CONTENT,
    };

    #[test]
    fn should_decrypt_encrypted_content_with_v4_version() {
        let mut input_content = V4_ENCRYPTED_CONTENT.to_vec();
        let input_cur = RefCell::new(Cursor::new(&mut input_content));

        let mut output_content = vec![];
        let output_cur = RefCell::new(Cursor::new(&mut output_content));

        let req = Request {
            header_reader: None,
            reader: &input_cur,
            writer: &output_cur,
            raw_key: Protected::new(PASSWORD.to_vec()),
            on_decrypted_header: None,
        };

        match execute(req) {
            Ok(_) => {
                assert_eq!(output_content, "Hello world".as_bytes().to_vec());
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_decrypt_encrypted_content_with_v5_version() {
        let mut input_content = V5_ENCRYPTED_CONTENT.to_vec();
        let input_cur = RefCell::new(Cursor::new(&mut input_content));

        let mut output_content = vec![];
        let output_cur = RefCell::new(Cursor::new(&mut output_content));

        let req = Request {
            header_reader: None,
            reader: &input_cur,
            writer: &output_cur,
            raw_key: Protected::new(PASSWORD.to_vec()),
            on_decrypted_header: None,
        };

        match execute(req) {
            Ok(_) => {
                assert_eq!(output_content, "Hello world".as_bytes().to_vec());
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_decrypt_encrypted_detached_header_and_content_with_v5_version() {
        let mut input_content = V5_ENCRYPTED_DETACHED_CONTENT.to_vec();
        let input_cur = RefCell::new(Cursor::new(&mut input_content));

        let mut input_header = V5_ENCRYPTED_DETACHED_HEADER.to_vec();
        let header_cur = RefCell::new(Cursor::new(&mut input_header));

        let mut output_content = vec![];
        let output_cur = RefCell::new(Cursor::new(&mut output_content));

        let req = Request {
            header_reader: Some(&header_cur),
            reader: &input_cur,
            writer: &output_cur,
            raw_key: Protected::new(PASSWORD.to_vec()),
            on_decrypted_header: None,
        };

        match execute(req) {
            Ok(_) => {
                assert_eq!(output_content, "Hello world".as_bytes().to_vec());
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_decrypt_encrypted_full_detached_header_and_content_with_v5_version() {
        let mut input_content = V5_ENCRYPTED_FULL_DETACHED_CONTENT.to_vec();
        let input_cur = RefCell::new(Cursor::new(&mut input_content));

        let mut input_header = V5_ENCRYPTED_DETACHED_HEADER.to_vec();
        let header_cur = RefCell::new(Cursor::new(&mut input_header));

        let mut output_content = vec![];
        let output_cur = RefCell::new(Cursor::new(&mut output_content));

        let req = Request {
            header_reader: Some(&header_cur),
            reader: &input_cur,
            writer: &output_cur,
            raw_key: Protected::new(PASSWORD.to_vec()),
            on_decrypted_header: None,
        };

        match execute(req) {
            Ok(_) => {
                assert_eq!(output_content, "Hello world".as_bytes().to_vec());
            }
            _ => unreachable!(),
        }
    }
}
