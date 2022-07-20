use std::cell::RefCell;
use std::io::{BufReader, BufWriter, Cursor, Read, Seek, Write};

use dexios_core::header::{HashingAlgorithm, HeaderType};
use dexios_core::primitives::BLOCK_SIZE;
use dexios_core::protected::Protected;
use zip::write::FileOptions;

use crate::domain;

#[derive(Debug)]
pub enum Error {
    AddDirToArchive,
    AddFileToArchive,
    FinishArchive,
    ReadData,
    WriteData,
    Encrypt(domain::encrypt::Error),
    Overwrite(domain::overwrite::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;
        match self {
            AddDirToArchive => f.write_str("Unable to add directory to archive"),
            AddFileToArchive => f.write_str("Unable to add file to archive"),
            FinishArchive => f.write_str("Unable to finish archive"),
            ReadData => f.write_str("Unable to read data"),
            WriteData => f.write_str("Unable to write data"),
            Encrypt(inner) => write!(f, "Unable to encrypt archive: {}", inner),
            Overwrite(inner) => write!(f, "Unable to overwrite archive: {}", inner),
        }
    }
}

impl std::error::Error for Error {}

pub struct Request<'a, RW>
where
    RW: Read + Write + Seek,
{
    pub writer: &'a RefCell<RW>,
    pub compress_files: Vec<domain::storage::File<RW>>,
    pub compression_method: zip::CompressionMethod,
    pub header_writer: Option<&'a RefCell<RW>>,
    pub raw_key: Protected<Vec<u8>>,
    // TODO: don't use external types in logic
    pub header_type: HeaderType,
    pub hashing_algorithm: HashingAlgorithm,
}

pub fn execute<RW>(req: Request<RW>) -> Result<(), Error>
where
    RW: Read + Write + Seek,
{
    // 1. Create in memory zip archive.
    let mut zip_content = vec![];
    let file = Cursor::new(&mut zip_content);
    let mut zip_writer = zip::ZipWriter::new(BufWriter::new(file));

    let options = FileOptions::default()
        .compression_method(req.compression_method)
        .large_file(true)
        .unix_permissions(0o755);

    // 2. Add files to the archive.
    req.compress_files.into_iter().try_for_each(|f| {
        let file_path = f.path().to_str().ok_or(Error::ReadData)?;
        if f.is_dir() {
            zip_writer
                .add_directory(file_path, options)
                .map_err(|_| Error::AddDirToArchive)?;
        } else {
            zip_writer
                .start_file(file_path, options)
                .map_err(|_| Error::AddFileToArchive)?;

            let mut reader = f.try_reader().map_err(|_| Error::ReadData)?.borrow_mut();
            let mut buffer = [0u8; BLOCK_SIZE];
            loop {
                let read_count = reader.read(&mut buffer).map_err(|_| Error::ReadData)?;
                zip_writer
                    .write_all(&buffer[..read_count])
                    .map_err(|_| Error::WriteData)?;
                if read_count != BLOCK_SIZE {
                    break;
                }
            }
        }

        Ok(())
    })?;

    // 3. Close archive and switch writer to reader.
    let (zip_reader_capacity, zip_reader) = zip_writer
        .finish()
        .map_err(|_| Error::FinishArchive)?
        .into_inner()
        .map(|r| (r.get_ref().capacity(), RefCell::new(BufReader::new(r))))
        .map_err(|_| Error::FinishArchive)?;

    // 4. Encrypt zip archive
    let encrypt_res = domain::encrypt::execute(domain::encrypt::Request {
        reader: &zip_reader,
        writer: req.writer,
        header_writer: req.header_writer,
        raw_key: req.raw_key,
        header_type: req.header_type,
        hashing_algorithm: req.hashing_algorithm,
    })
    .map_err(Error::Encrypt);

    // 5. Finally overwrite zip archive with zeros.
    domain::overwrite::execute(domain::overwrite::Request {
        buf_capacity: zip_reader_capacity,
        writer: &RefCell::new(zip_reader.into_inner().into_inner()),
        passes: 2,
    })
    .map_err(Error::Overwrite)?;

    encrypt_res
}
