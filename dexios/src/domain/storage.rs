use std::cell::RefCell;
use std::fs;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::io;
#[cfg(test)]
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
#[cfg(test)]
use std::thread;

#[derive(Debug)]
pub enum FileMode {
    Read,
    Write,
}

#[derive(Debug)]
pub enum Error {
    CreateFile,
    OpenFile(FileMode),
    RemoveFile,
    RemoveDir,
    FlushFile,
    FileAccess,
    FileLen,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;
        match self {
            CreateFile => f.write_str("Unable to create a new file"),
            OpenFile(mode) => write!(f, "Unable to read the file in {:?} mode", mode),
            FlushFile => f.write_str("Unable to flush the file"),
            RemoveFile => f.write_str("Unable to remove the file"),
            RemoveDir => f.write_str("Unable to remove dir"),
            FileAccess => f.write_str("Permission denied"),
            FileLen => f.write_str("Unable to get file length"),
        }
    }
}

impl std::error::Error for Error {}

pub trait Storage<RW>: Send + Sync
where
    RW: Read + Write + Seek,
{
    fn create_file<P: AsRef<Path>>(&self, path: P) -> Result<File<RW>, Error>;
    fn read_file<P: AsRef<Path>>(&self, path: P) -> Result<File<RW>, Error>;
    fn write_file<P: AsRef<Path>>(&self, path: P) -> Result<File<RW>, Error>;
    fn flush_file(&self, file: &File<RW>) -> Result<(), Error>;
    fn file_len(&self, file: &File<RW>) -> Result<usize, Error>;
    fn remove_file(&self, file: &File<RW>) -> Result<(), Error>;
    fn remove_dir_all(&self, file: File<RW>) -> Result<(), Error>;
}

pub struct FileStorage;

impl Storage<fs::File> for FileStorage {
    fn create_file<P: AsRef<Path>>(&self, path: P) -> Result<File<fs::File>, Error> {
        let path = path.as_ref().to_path_buf();
        let file = fs::File::options()
            .create_new(true)
            .write(true)
            .open(&path)
            .map_err(|_| Error::CreateFile)?;
        Ok(File::Write(WriteFile {
            path,
            // TODO: Should we add the BufWriter?
            writer: RefCell::new(file),
        }))
    }

    fn read_file<P: AsRef<Path>>(&self, path: P) -> Result<File<fs::File>, Error> {
        let path = path.as_ref().to_path_buf();
        let file = fs::File::open(&path).map_err(|_| Error::OpenFile(FileMode::Read))?;
        let file_meta = file
            .metadata()
            .map_err(|_| Error::OpenFile(FileMode::Read))?;

        if file_meta.is_dir() {
            Ok(File::Dir(path))
        } else {
            Ok(File::Read(ReadFile {
                path,
                reader: RefCell::new(file),
            }))
        }
    }

    fn write_file<P: AsRef<Path>>(&self, path: P) -> Result<File<fs::File>, Error> {
        let path = path.as_ref().to_path_buf();
        let file = fs::File::options()
            .write(true)
            .open(&path)
            .map_err(|_| Error::OpenFile(FileMode::Write))?;

        Ok(File::Write(WriteFile {
            path,
            // TODO: Should we add the BufWriter?
            writer: RefCell::new(file),
        }))
    }

    fn flush_file(&self, file: &File<fs::File>) -> Result<(), Error> {
        file.try_writer()?
            .borrow_mut()
            .flush()
            .map_err(|_| Error::FlushFile)
    }

    fn file_len(&self, file: &File<fs::File>) -> Result<usize, Error> {
        let fs_file = match file {
            File::Read(ReadFile { reader, .. }) => reader.borrow(),
            File::Write(WriteFile { writer, .. }) => writer.borrow(),
            _ => return Err(Error::FileAccess),
        };
        let file_meta = fs::File::metadata(&fs_file).map_err(|_| Error::FileLen)?;
        file_meta.len().try_into().map_err(|_| Error::FileLen)
    }

    fn remove_file(&self, file: &File<fs::File>) -> Result<(), Error> {
        if let File::Write(WriteFile { writer, .. }) = &file {
            let mut writer = writer.borrow_mut();
            writer.set_len(0).map_err(|_| Error::RemoveFile)?;
            writer.flush().map_err(|_| Error::FlushFile)?;
        }

        fs::remove_file(file.path()).map_err(|_| Error::RemoveFile)
    }

    fn remove_dir_all(&self, file: File<fs::File>) -> Result<(), Error> {
        if !file.is_dir() {
            return Err(Error::RemoveDir);
        }

        fs::remove_dir_all(file.path()).map_err(|_| Error::RemoveDir)
    }
}

#[cfg(test)]
#[derive(Default)]
pub struct InMemoryStorage {
    pub files: RwLock<HashMap<PathBuf, IMFile>>,
}

#[cfg(test)]
impl InMemoryStorage {
    pub(crate) fn files(&self) -> RwLockReadGuard<HashMap<PathBuf, IMFile>> {
        loop {
            match self.files.try_read() {
                Ok(files) => break files,
                _ => thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
    }

    pub(crate) fn mut_files(&self) -> RwLockWriteGuard<HashMap<PathBuf, IMFile>> {
        loop {
            match self.files.try_write() {
                Ok(files) => break files,
                _ => thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
    }

    fn save_file(&self, path: PathBuf, im_file: IMFile) -> Result<(), Error> {
        self.mut_files().insert(path, im_file);
        Ok(())
    }

    // --------------------------------
    // TEST DATA
    // -------------------------------

    pub(crate) fn add_hello_txt(&self) -> Result<(), Error> {
        let buf = b"hello world".to_vec();
        self.save_file(
            PathBuf::from("hello.txt"),
            IMFile::File(InMemoryFile {
                len: buf.len(),
                buf,
            }),
        )
    }
}

#[cfg(test)]
impl Storage<io::Cursor<Vec<u8>>> for InMemoryStorage {
    fn create_file<P: AsRef<Path>>(&self, path: P) -> Result<File<io::Cursor<Vec<u8>>>, Error> {
        let file_path = path.as_ref().to_path_buf();

        let im_file = match self.files().get(&file_path) {
            Some(_) => Err(Error::CreateFile),
            None => Ok(IMFile::File(InMemoryFile::default())),
        }?;

        let cursor = io::Cursor::new(im_file.inner().buf.clone());

        self.save_file(file_path.clone(), im_file)?;

        Ok(File::Write(WriteFile {
            path: file_path,
            writer: RefCell::new(cursor),
        }))
    }

    fn read_file<P: AsRef<Path>>(&self, path: P) -> Result<File<io::Cursor<Vec<u8>>>, Error> {
        let in_file = self
            .files()
            .get(path.as_ref())
            .cloned()
            .ok_or(Error::OpenFile(FileMode::Read))?;

        let file_path = path.as_ref().to_path_buf();

        match in_file {
            IMFile::Dir => Ok(File::Dir(file_path)),
            IMFile::File(f) => {
                let cursor = io::Cursor::new(f.buf);
                Ok(File::Read(ReadFile {
                    path: file_path,
                    reader: RefCell::new(cursor),
                }))
            }
        }
    }

    fn write_file<P: AsRef<Path>>(&self, path: P) -> Result<File<io::Cursor<Vec<u8>>>, Error> {
        let file_path = path.as_ref().to_path_buf();

        let file = self
            .files()
            .get(&file_path)
            .cloned()
            .ok_or(Error::OpenFile(FileMode::Write))?;
        if matches!(file, IMFile::Dir) {
            return Err(Error::FileAccess);
        }

        let cursor = io::Cursor::new(file.inner().buf.clone());

        Ok(File::Write(WriteFile {
            path: file_path,
            writer: RefCell::new(cursor),
        }))
    }

    fn flush_file(&self, file: &File<io::Cursor<Vec<u8>>>) -> Result<(), Error> {
        if file.is_dir() {
            return Err(Error::FileAccess);
        }

        let file_path = file.path();
        let writer = file.try_writer()?;
        writer.borrow_mut().flush().map_err(|_| Error::FlushFile)?;

        let vec = writer.borrow().get_ref().clone();
        let len = vec.len();
        let new_file = IMFile::File(InMemoryFile { buf: vec, len });

        self.save_file(file_path.to_owned(), new_file)?;

        Ok(())
    }

    fn file_len(&self, file: &File<io::Cursor<Vec<u8>>>) -> Result<usize, Error> {
        let cur = match file {
            File::Read(ReadFile { reader, .. }) => reader.borrow(),
            File::Write(WriteFile { writer, .. }) => writer.borrow(),
            _ => return Err(Error::FileAccess),
        };

        Ok(cur.get_ref().len())
    }

    fn remove_file(&self, file: &File<io::Cursor<Vec<u8>>>) -> Result<(), Error> {
        self.mut_files()
            .remove(file.path())
            .ok_or(Error::RemoveFile)?;
        Ok(())
    }

    fn remove_dir_all(&self, file: File<io::Cursor<Vec<u8>>>) -> Result<(), Error> {
        if !file.is_dir() {
            return Err(Error::FileAccess);
        }

        let files = self.files();

        let file_path = file.path();
        files
            .keys()
            .filter(|k| k.starts_with(file_path))
            .try_for_each(|k| {
                self.mut_files()
                    .remove(k)
                    .map(|_| ())
                    .ok_or(Error::RemoveDir)?;
                Ok(())
            })
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InMemoryFile {
    pub buf: Vec<u8>,
    pub len: usize,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IMFile {
    File(InMemoryFile),
    Dir,
}

#[cfg(test)]
impl IMFile {
    fn inner(&self) -> &InMemoryFile {
        match self {
            IMFile::File(inner) => inner,
            IMFile::Dir => unreachable!(),
        }
    }
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
    Dir(PathBuf),
    // TODO: Dir and Symlink?
}

impl<RW> File<RW>
where
    RW: Read + Write + Seek,
{
    pub fn path(&self) -> &Path {
        match self {
            File::Read(ReadFile { path, .. })
            | File::Write(WriteFile { path, .. })
            | File::Dir(path) => path,
        }
    }

    pub fn is_dir(&self) -> bool {
        matches!(self, File::Dir(_))
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
    use super::*;

    #[test]
    fn should_create_a_new_file() {
        let stor = InMemoryStorage::default();

        match stor.create_file("hello.txt") {
            Ok(file) => {
                let im_file = stor.files().get(file.path()).cloned();
                assert_eq!(im_file, Some(IMFile::File(InMemoryFile::default())));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_throw_an_error_if_file_already_exist() {
        let stor = InMemoryStorage::default();
        stor.add_hello_txt().unwrap();

        match stor.create_file("hello.txt") {
            Err(Error::CreateFile) => {}
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_not_open_file_to_read() {
        let stor = InMemoryStorage::default();

        match stor.read_file("hello.txt") {
            Err(Error::OpenFile(FileMode::Read)) => {}
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_not_open_file_to_write() {
        let stor = InMemoryStorage::default();

        match stor.write_file("hello.txt") {
            Err(Error::OpenFile(FileMode::Write)) => {}
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_open_exist_file_in_read_mode() {
        let stor = InMemoryStorage::default();
        stor.add_hello_txt().unwrap();

        match stor.read_file("hello.txt") {
            Ok(file) => {
                if let Some(IMFile::File(InMemoryFile { buf, len })) = stor.files().get(file.path())
                {
                    let content = b"hello world".to_vec();
                    assert_eq!(len, &content.len());
                    assert_eq!(buf, &content);
                } else {
                    unreachable!();
                }
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_open_exist_file_in_write_mode() {
        let stor = InMemoryStorage::default();
        stor.add_hello_txt().unwrap();

        match stor.write_file("hello.txt") {
            Ok(file) => {
                if let Some(IMFile::File(InMemoryFile { buf, len })) = stor.files().get(file.path())
                {
                    let content = b"hello world".to_vec();
                    assert_eq!(len, &content.len());
                    assert_eq!(buf, &content);
                } else {
                    unreachable!();
                }
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_write_content_to_file() {
        let stor = InMemoryStorage::default();
        let content = "hello world";

        let file = stor.create_file("hello.txt").unwrap();
        file.try_writer()
            .unwrap()
            .borrow_mut()
            .write_all(content.as_bytes())
            .unwrap();

        match stor.flush_file(&file) {
            Ok(_) => {
                let im_file = stor.files().get(file.path()).cloned();
                assert_eq!(
                    im_file,
                    Some(IMFile::File(InMemoryFile {
                        buf: content.as_bytes().to_vec(),
                        len: content.len()
                    }))
                );
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_remove_a_file_in_read_mode() {
        let stor = InMemoryStorage::default();
        stor.add_hello_txt().unwrap();

        let file = stor.write_file("hello.txt").unwrap();

        match stor.remove_file(&file) {
            Ok(_) => {
                let im_file = stor.files().get(file.path()).cloned();
                assert_eq!(im_file, None);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_remove_a_file_in_write_mode() {
        let stor = InMemoryStorage::default();
        stor.add_hello_txt().unwrap();

        let file = stor.write_file("hello.txt").unwrap();

        match stor.remove_file(&file) {
            Ok(_) => {
                let im_file = stor.files().get(file.path()).cloned();
                assert_eq!(im_file, None);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_get_file_length() {
        let stor = InMemoryStorage::default();
        stor.add_hello_txt().unwrap();

        let file = stor.read_file("hello.txt").unwrap();

        match stor.file_len(&file) {
            Ok(len) => {
                let content = b"hello world".to_vec();
                assert_eq!(len, content.len());
            }
            _ => unreachable!(),
        }
    }
}
