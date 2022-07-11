use crate::domain;
use std::io::{Read, Seek, Write};

use domain::storage::Storage;

#[derive(Debug)]
pub enum Error {
    InvalidFileType,
    EraseFile(domain::erase::Error),
    ReadDirEntries,
    RemoveDir,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;
        match self {
            InvalidFileType => f.write_str("Invalid file type"),
            EraseFile(inner) => write!(f, "Unable to erase file: {}", inner),
            ReadDirEntries => f.write_str("Unable to get all dir entries"),
            RemoveDir => f.write_str("Unable to remove directory recursively"),
        }
    }
}

impl std::error::Error for Error {}

pub struct Request<RW>
where
    RW: Read + Write + Seek,
{
    pub file: domain::storage::File<RW>,
    pub passes: i32,
}

pub fn execute<RW>(stor: &impl Storage<RW>, req: Request<RW>) -> Result<(), Error>
where
    RW: Read + Write + Seek,
{
    if req.file.is_dir() {
        return Err(Error::InvalidFileType);
    }

    // TODO: move the directory reading to the domain because we cannot test it :(
    let (file_paths, _) = crate::file::get_paths_in_dir(
        req.file
            .path()
            .to_str()
            .expect("We sure that it's valid unicode"),
        crate::global::states::DirectoryMode::Recursive,
        &Vec::<String>::new(),
        &crate::global::states::HiddenFilesMode::Include,
        &crate::global::states::PrintMode::Quiet,
    )
    .map_err(|_| Error::ReadDirEntries)?;

    for file_path in file_paths {
        domain::erase::execute(
            stor,
            domain::erase::Request {
                path: file_path,
                passes: req.passes,
            },
        )
        .map_err(Error::EraseFile)?;
    }

    stor.remove_dir_all(req.file).map_err(|_| Error::RemoveDir)
}
