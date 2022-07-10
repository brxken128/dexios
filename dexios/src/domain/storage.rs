use std::cell::RefCell;
use std::fs;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::io;

#[derive(Debug)]
pub enum Error {
    OpenFile,
    RemoveFile,
    WriteFile,
    FlushFile,
    FileAccess,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;
        match self {
            OpenFile => f.write_str("Unable to read file"),
            WriteFile => f.write_str("Unable to write file"),
            FlushFile => f.write_str("Unable to flush file"),
            RemoveFile => f.write_str("Unable to remove file"),
            FileAccess => f.write_str("Permission denied"),
        }
    }
}

impl std::error::Error for Error {}

pub trait Storage<RW>
where
    RW: Read + Write + Seek,
{
    fn open_file<P: AsRef<Path>>(&self, path: P) -> Result<File<RW>, Error>;
    fn write_file<P: AsRef<Path>>(&self, path: P) -> Result<File<RW>, Error>;
    fn flush_file(&self, file: File<RW>) -> Result<(), Error>;
    fn remove_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Error>;
}

pub struct FileStorage {}

impl Storage<fs::File> for FileStorage {
    fn open_file<P: AsRef<Path>>(&self, path: P) -> Result<File<fs::File>, Error> {
        let path = path.as_ref().to_path_buf();
        let file = fs::File::open(&path).map_err(|_| Error::OpenFile)?;

        Ok(File::Read(ReadFile {
            path,
            reader: RefCell::new(file),
        }))
    }

    fn write_file<P: AsRef<Path>>(&self, path: P) -> Result<File<fs::File>, Error> {
        let path = path.as_ref().to_path_buf();
        let file = fs::File::create(&path).map_err(|_| Error::WriteFile)?;

        Ok(File::Write(WriteFile {
            path,
            writer: RefCell::new(file),
        }))
    }

    fn flush_file(&self, file: File<fs::File>) -> Result<(), Error> {
        file.try_writer()?
            .borrow_mut()
            .flush()
            .map_err(|_| Error::FlushFile)
    }

    fn remove_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        fs::remove_file(path).map_err(|_| Error::RemoveFile)
    }
}

#[cfg(test)]
#[derive(Default)]
pub struct InMemoryStorage {
    pub files: RefCell<HashMap<PathBuf, InMemoryFile>>,
}

#[cfg(test)]
impl InMemoryStorage {
    fn save_file(&self, path: PathBuf, file: InMemoryFile) -> Result<(), Error> {
        self.files
            .borrow_mut()
            .insert(path, file)
            .ok_or(Error::WriteFile)?;
        Ok(())
    }
}

#[cfg(test)]
impl Storage<io::Cursor<Vec<u8>>> for InMemoryStorage {
    fn open_file<P: AsRef<Path>>(&self, path: P) -> Result<File<io::Cursor<Vec<u8>>>, Error> {
        let files = self.files.borrow();
        let file = files.get(path.as_ref()).ok_or(Error::OpenFile)?;
        let cursor = io::Cursor::new(file.buf.clone());

        Ok(File::Read(ReadFile {
            path: path.as_ref().to_path_buf(),
            reader: RefCell::new(cursor),
        }))
    }

    fn write_file<P: AsRef<Path>>(&self, path: P) -> Result<File<io::Cursor<Vec<u8>>>, Error> {
        let file_path = path.as_ref().to_path_buf();
        let file = InMemoryFile {
            buf: vec![],
            len: 0,
        };
        let cursor = io::Cursor::new(file.buf.clone());

        self.save_file(file_path, file)?;

        Ok(File::Read(ReadFile {
            path: path.as_ref().to_path_buf(),
            reader: RefCell::new(cursor),
        }))
    }

    fn flush_file(&self, file: File<io::Cursor<Vec<u8>>>) -> Result<(), Error> {
        let file_path = file.file_path();
        let writer = file.try_writer()?;

        let vec = writer.clone().into_inner().into_inner();
        let len = vec.len();
        let new_file = InMemoryFile { buf: vec, len };

        self.save_file(file_path.to_path_buf(), new_file)?;

        Ok(())
    }

    fn remove_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        self.files
            .borrow_mut()
            .remove(path.as_ref())
            .ok_or(Error::RemoveFile)?;
        Ok(())
    }
}

#[cfg(test)]
#[derive(Clone)]
pub struct InMemoryFile {
    pub buf: Vec<u8>,
    pub len: usize,
}

pub struct ReadFile<R>
where
    R: Read + Seek,
{
    path: PathBuf,
    reader: RefCell<R>,
}

pub struct WriteFile<W>
where
    W: Write + Seek,
{
    path: PathBuf,
    writer: RefCell<W>,
}

pub enum File<RW>
where
    RW: Read + Write + Seek,
{
    Read(ReadFile<RW>),
    Write(WriteFile<RW>),
    // TODO: Dir and Symlink?
}

impl<RW> File<RW>
where
    RW: Read + Write + Seek,
{
    pub fn file_path(&self) -> &Path {
        match self {
            File::Read(ReadFile { path, .. }) => path,
            File::Write(WriteFile { path, .. }) => path,
        }
    }

    pub fn try_reader(&self) -> Result<&RefCell<RW>, Error> {
        match self {
            File::Read(file) => Ok(&file.reader),
            _ => Err(Error::FileAccess),
        }
    }

    pub fn try_writer(&self) -> Result<&RefCell<RW>, Error> {
        match self {
            File::Write(file) => Ok(&file.writer),
            _ => Err(Error::FileAccess),
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn should_create_file() {}
}
