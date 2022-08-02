use std::cell::RefCell;
use std::io::{Read, Seek, Write};
use std::path::PathBuf;
use std::sync::Arc;

use crate::storage::{self, Storage};
use crate::{decrypt, overwrite};
use dexios_core::protected::Protected;

#[derive(Debug)]
pub enum Error {
    WriteData,
    OpenArchive,
    ResetCursorPosition,
    Storage(storage::Error),
    Decrypt(decrypt::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::WriteData => f.write_str("Unable to write data"),
            Error::OpenArchive => f.write_str("Unable to open archive"),
            Error::ResetCursorPosition => f.write_str("Unable to reset cursor position"),
            Error::Storage(inner) => write!(f, "Storage error: {}", inner),
            Error::Decrypt(inner) => write!(f, "Decrypt error: {}", inner),
        }
    }
}

impl std::error::Error for Error {}

type OnArchiveInfo = Box<dyn FnOnce(usize)>;
type OnZipFileFn = Box<dyn Fn(PathBuf) -> bool>;

pub struct Request<'a, R>
where
    R: Read,
{
    pub reader: &'a RefCell<R>,
    pub header_reader: Option<&'a RefCell<R>>,
    pub raw_key: Protected<Vec<u8>>,
    pub output_dir_path: PathBuf,
    pub on_decrypted_header: Option<decrypt::OnDecryptedHeaderFn>,
    pub on_archive_info: Option<OnArchiveInfo>,
    pub on_zip_file: Option<OnZipFileFn>,
}

pub fn execute<RW: Read + Write + Seek>(
    stor: Arc<impl Storage<RW>>,
    req: Request<RW>,
) -> Result<(), Error> {
    // 1. Create temp zip archive.
    let tmp_file = stor.create_temp_file().map_err(Error::Storage)?;

    // 2. Decrypt input file to temp zip archive.
    decrypt::execute(decrypt::Request {
        header_reader: req.header_reader,
        reader: req.reader,
        writer: tmp_file
            .try_writer()
            .expect("We sure that file in write mode"),
        raw_key: req.raw_key,
        on_decrypted_header: req.on_decrypted_header,
    })
    .map_err(Error::Decrypt)?;

    let buf_capacity = stor.file_len(&tmp_file).map_err(Error::Storage)?;

    // 3. Recover files from temp archive.
    {
        let mut reader = tmp_file
            .try_reader()
            .expect("We sure that file in read mode")
            .borrow_mut();

        reader.rewind().map_err(|_| Error::ResetCursorPosition)?;

        let mut archive = zip::ZipArchive::new(&mut *reader).map_err(|_| Error::OpenArchive)?;

        stor.create_dir_all(&req.output_dir_path)
            .map_err(Error::Storage)?;

        for i in 0..archive.len() {
            let mut full_path = req.output_dir_path.clone();

            let mut zip_file = archive.by_index(i).map_err(|_| todo!())?;
            match zip_file.enclosed_name() {
                Some(path) => full_path.push(path),
                None => continue,
            }

            // TODO(pleshevskiy): check slip prevention

            if zip_file.is_dir() {
                stor.create_dir_all(full_path).map_err(Error::Storage)?;
            } else {
                // TODO(pleshevskiy): handle the file's existence
                if let Some(on_zip_file) = req.on_zip_file.as_ref() {
                    if !on_zip_file(full_path.clone()) {
                        continue;
                    }
                }

                let file = stor.create_file(full_path).map_err(Error::Storage)?;
                std::io::copy(
                    &mut zip_file,
                    &mut *file.try_writer().map_err(Error::Storage)?.borrow_mut(),
                )
                .map_err(|_| Error::WriteData)?;
            }
        }
    }

    // 4. Finally eraze temp zip archive with zeros.
    overwrite::execute(crate::overwrite::Request {
        buf_capacity,
        writer: tmp_file
            .try_writer()
            .expect("We sure that file in write mode"),
        passes: 2,
    })
    .ok();

    stor.remove_file(tmp_file).ok();

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore = "not yet implemented"]
    fn should_unpack_encrypted_archive() {
        todo!()
    }
}
