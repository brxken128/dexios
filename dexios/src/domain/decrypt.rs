use std::cell::RefCell;
use std::io::{Read, Seek, Write};

use dexios_core::cipher::Ciphers;
use dexios_core::header::Header;
use dexios_core::key::decrypt_master_key;
use dexios_core::primitives::Mode;
use dexios_core::protected::Protected;

#[derive(Debug)]
pub enum Error {
    InitializeChiphers,
    DeserializeHeader,
    ReadEncryptedData,
    DecryptMasterKey,
    DecryptData,
    WriteData,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;
        match self {
            InitializeChiphers => f.write_str("Cannot initialize chiphers"),
            DeserializeHeader => f.write_str("Cannot deserialize header"),
            ReadEncryptedData => f.write_str("Unable to read encrypted data"),
            DecryptMasterKey => f.write_str("Cannot decrypt master key"),
            DecryptData => f.write_str("Unable to decrypt data"),
            WriteData => f.write_str("Unable to write data"),
        }
    }
}

impl std::error::Error for Error {}

pub struct Request<'a, R, W>
where
    R: Read + Seek,
    W: Write + Seek,
{
    pub header_reader: Option<&'a RefCell<R>>,
    pub reader: &'a RefCell<R>,
    pub writer: &'a RefCell<W>,
    pub raw_key: Protected<Vec<u8>>,
}

pub fn execute<R, W>(req: Request<R, W>) -> Result<(), Error>
where
    R: Read + Seek,
    W: Write + Seek,
{
    let (header, aad) = match req.header_reader {
        Some(header_reader) => {
            let (header, aad) = Header::deserialize(&mut *header_reader.borrow_mut())
                .map_err(|_| Error::DeserializeHeader)?;
            req.reader
                .borrow_mut()
                .seek(std::io::SeekFrom::Start(header.get_size()))
                .map_err(|_| Error::DeserializeHeader)?;
            (header, aad)
        }
        None => Header::deserialize(&mut *req.reader.borrow_mut())
            .map_err(|_| Error::DeserializeHeader)?,
    };

    match header.header_type.mode {
        Mode::MemoryMode => {
            let mut encrypted_data = Vec::new();
            req.reader
                .borrow_mut()
                .read_to_end(&mut encrypted_data)
                .map_err(|_| Error::ReadEncryptedData)?;

            let key =
                decrypt_master_key(req.raw_key, &header).map_err(|_| Error::DecryptMasterKey)?;

            let ciphers = Ciphers::initialize(key, &header.header_type.algorithm)
                .map_err(|_| Error::InitializeChiphers)?;

            let payload = dexios_core::Payload {
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
        _ => unimplemented!(),
    }

    Ok(())
}
