//! This provides functionality for "shredding" a directory. It first traverses the directory, and then calls `shred` on all files.
//!
//! This will not be effective on flash storage, and if you are planning to release a program that uses this function, I'd recommend putting the default number of passes to 1.

use std::io::{Read, Seek, Write};
use std::sync::Arc;

use crate::storage::Storage;

#[derive(Debug)]
pub enum Error {
    InvalidFileType,
    EraseFile(crate::erase::Error),
    ReadDirEntries,
    RemoveDir,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidFileType => f.write_str("Invalid file type"),
            Error::EraseFile(inner) => write!(f, "Unable to erase file: {inner}"),
            Error::ReadDirEntries => f.write_str("Unable to get all dir entries"),
            Error::RemoveDir => f.write_str("Unable to remove directory recursively"),
        }
    }
}

impl std::error::Error for Error {}

pub struct Request<RW>
where
    RW: Read + Write + Seek,
{
    pub entry: crate::storage::Entry<RW>,
    pub passes: i32,
}

pub fn execute<RW>(stor: Arc<impl Storage<RW> + 'static>, req: Request<RW>) -> Result<(), Error>
where
    RW: Read + Write + Seek,
{
    if !req.entry.is_dir() {
        return Err(Error::InvalidFileType);
    }

    let files = stor
        .read_dir(&req.entry)
        .map_err(|_| Error::ReadDirEntries)?;

    #[allow(clippy::needless_collect)] // 🚫 we have to collect in order to propertly join threads!
    let handlers = files
        .into_iter()
        .filter(|f| !f.is_dir())
        .map(|f| {
            let file_path = f.path().to_path_buf();
            let stor = stor.clone();
            std::thread::spawn(move || -> Result<(), Error> {
                crate::erase::execute(
                    stor,
                    crate::erase::Request {
                        path: file_path,
                        passes: req.passes,
                    },
                )
                .map_err(Error::EraseFile)?;
                Ok(())
            })
        })
        .collect::<Vec<_>>();

    handlers.into_iter().try_for_each(|h| h.join().unwrap())?;

    stor.remove_dir_all(req.entry).map_err(|_| Error::RemoveDir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemoryStorage;

    use std::path::PathBuf;

    #[test]
    fn should_erase_dir_recursively_with_subfiles() {
        let stor = Arc::new(InMemoryStorage::default());
        stor.add_hello_txt();
        stor.add_bar_foo_folder();

        let file = stor.read_file("bar/").unwrap();
        let file_path = file.path().to_path_buf();

        let req = Request {
            entry: file,
            passes: 2,
        };

        match execute(stor.clone(), req) {
            Ok(()) => {
                assert_eq!(stor.files().get(&file_path).cloned(), None);
                let files = stor.files();
                let mut keys = files.keys();
                assert_eq!(keys.next(), Some(&PathBuf::from("hello.txt")));
                assert_eq!(keys.next(), None);
            }
            _ => unreachable!(),
        }
    }
}
