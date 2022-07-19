use std::io::{BufReader, BufWriter, Read, Seek, Write};

use dexios_core::primitives::BLOCK_SIZE;
use zip::write::FileOptions;

use crate::domain;

#[derive(Debug)]
pub enum Error {
    AddFileToArchive,
    FinishArchive,
    WriteData,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;
        match self {
            AddFileToArchive => f.write_str("Unable to add file to archive"),
            FinishArchive => f.write_str("Unable to finish archive"),
            WriteData => f.write_str("Unable to write data"),
        }
    }
}

impl std::error::Error for Error {}

pub struct Request<RW>
where
    RW: Read + Write + Seek,
{
    //writer: RefCell<W>,
    pub compress_files: Vec<domain::storage::File<RW>>,
    pub compression_method: zip::CompressionMethod,
}

pub fn execute<RW>(req: Request<RW>) -> Result<(), Error>
where
    RW: Read + Write + Seek,
{
    let file = std::fs::File::create("pack.test").unwrap();

    //let mut zip_content = vec![];
    //let file = Cursor::new(&mut zip_content)
    let mut zip_writer = zip::ZipWriter::new(BufWriter::new(file));

    let options = FileOptions::default()
        .compression_method(req.compression_method)
        .large_file(true)
        .unix_permissions(0o755);

    // TODO(pleshevskiy): magic with content here
    req.compress_files.into_iter().try_for_each(|f| {
        // TODO(pleshevskiy): handle all errors!
        zip_writer
            .start_file(f.path().to_str().unwrap(), options)
            .map_err(|_| Error::AddFileToArchive)?;

        let mut reader = f.try_reader().unwrap().borrow_mut();
        let mut buffer = [0u8; BLOCK_SIZE];
        loop {
            let read_count = reader.read(&mut buffer).unwrap();
            zip_writer
                .write_all(&buffer[..read_count])
                .map_err(|_| Error::WriteData)?;
            if read_count != BLOCK_SIZE {
                break;
            }
        }

        Ok(())
    })?;

    let mut zip_reader = zip_writer
        .finish()
        .map_err(|_| Error::FinishArchive)?
        .into_inner()
        .map(BufReader::new)
        .map_err(|_| Error::FinishArchive)?;

    /*
    let mut content = vec![];
    zip_reader.rewind().map_err(|_| Error::FinishArchive)?;
    zip_reader.read_to_end(&mut content).unwrap();
    */

    std::process::exit(0);

    Ok(())
}
