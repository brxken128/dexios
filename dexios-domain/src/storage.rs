use rand::distributions::{Alphanumeric, DistString};
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
    CreateDir,
    CreateFile,
    OpenFile(FileMode),
    RemoveFile,
    RemoveDir,
    DirEntries,
    FlushFile,
    FileAccess,
    FileLen,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::CreateDir => f.write_str("Unable to create a new directory"),
            Error::CreateFile => f.write_str("Unable to create a new file"),
            Error::OpenFile(mode) => write!(f, "Unable to read the file in {mode:?} mode"),
            Error::FlushFile => f.write_str("Unable to flush the file"),
            Error::RemoveFile => f.write_str("Unable to remove the file"),
            Error::RemoveDir => f.write_str("Unable to remove dir"),
            Error::DirEntries => f.write_str("Unable to read directory"),
            Error::FileAccess => f.write_str("Permission denied"),
            Error::FileLen => f.write_str("Unable to get file length"),
        }
    }
}

impl std::error::Error for Error {}

pub trait Storage<RW>: Send + Sync
where
    RW: Read + Write + Seek,
{
    // TODO(pleshevskiy): return a new struct that will be removed on drop.
    fn create_temp_file(&self) -> Result<Entry<RW>, Error> {
        let mut path = std::env::temp_dir();
        let file_name = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);
        path.push(file_name);

        self.create_file(path)
    }

    fn create_dir_all<P: AsRef<Path>>(&self, path: P) -> Result<(), Error>;
    fn create_file<P: AsRef<Path>>(&self, path: P) -> Result<Entry<RW>, Error>;
    fn read_file<P: AsRef<Path>>(&self, path: P) -> Result<Entry<RW>, Error>;
    fn write_file<P: AsRef<Path>>(&self, path: P) -> Result<Entry<RW>, Error>;
    fn flush_file(&self, file: &Entry<RW>) -> Result<(), Error>;
    fn file_len(&self, file: &Entry<RW>) -> Result<usize, Error>;
    fn remove_file(&self, file: Entry<RW>) -> Result<(), Error>;
    fn remove_dir_all(&self, file: Entry<RW>) -> Result<(), Error>;
    // TODO(pleshevskiy): return iterator instead of Vector
    fn read_dir(&self, file: &Entry<RW>) -> Result<Vec<Entry<RW>>, Error>;
}

pub struct FileStorage;

impl Storage<fs::File> for FileStorage {
    fn create_dir_all<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        fs::create_dir_all(&path).map_err(|_| Error::CreateDir)
    }

    fn create_file<P: AsRef<Path>>(&self, path: P) -> Result<Entry<fs::File>, Error> {
        let path = path.as_ref().to_path_buf();
        let file = fs::File::options()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|_| Error::CreateFile)?;
        Ok(Entry::File(FileData {
            path,
            stream: RefCell::new(file),
        }))
    }

    fn read_file<P: AsRef<Path>>(&self, path: P) -> Result<Entry<fs::File>, Error> {
        let path = path.as_ref().to_path_buf();
        if path.is_dir() {
            Ok(Entry::Dir(path))
        } else {
            let file = fs::File::open(&path).map_err(|_| Error::OpenFile(FileMode::Read))?;
            Ok(Entry::File(FileData {
                path,
                stream: RefCell::new(file),
            }))
        }
    }

    fn write_file<P: AsRef<Path>>(&self, path: P) -> Result<Entry<fs::File>, Error> {
        let path = path.as_ref().to_path_buf();
        let file = fs::File::options()
            .write(true)
            .read(true)
            .truncate(true)
            .open(&path)
            .map_err(|_| Error::OpenFile(FileMode::Write))?;

        Ok(Entry::File(FileData {
            path,
            stream: RefCell::new(file),
        }))
    }

    fn flush_file(&self, file: &Entry<fs::File>) -> Result<(), Error> {
        file.try_writer()?
            .borrow_mut()
            .flush()
            .map_err(|_| Error::FlushFile)
    }

    fn file_len(&self, file: &Entry<fs::File>) -> Result<usize, Error> {
        let fs_file = match file {
            Entry::File(FileData { stream, .. }) => stream.borrow(),
            Entry::Dir(_) => return Err(Error::FileAccess),
        };
        let file_meta = fs::File::metadata(&fs_file).map_err(|_| Error::FileLen)?;
        file_meta.len().try_into().map_err(|_| Error::FileLen)
    }

    fn remove_file(&self, file: Entry<fs::File>) -> Result<(), Error> {
        if let Entry::File(FileData { stream, .. }) = &file {
            let mut stream = stream.borrow_mut();
            stream.set_len(0).map_err(|_| Error::RemoveFile)?;
            stream.flush().map_err(|_| Error::FlushFile)?;
        }

        fs::remove_file(file.path()).map_err(|_| Error::RemoveFile)
    }

    fn remove_dir_all(&self, file: Entry<fs::File>) -> Result<(), Error> {
        if !file.is_dir() {
            return Err(Error::RemoveDir);
        }

        fs::remove_dir_all(file.path()).map_err(|_| Error::RemoveDir)
    }

    fn read_dir(&self, file: &Entry<fs::File>) -> Result<Vec<Entry<fs::File>>, Error> {
        if !file.is_dir() {
            return Err(Error::FileAccess);
        }

        walkdir::WalkDir::new(file.path())
            .into_iter()
            .map(|res| {
                res.map(|e| e.path().to_owned())
                    .map_err(|_| Error::DirEntries)
            })
            .map(|path| path.and_then(|path| self.read_file(path)))
            .collect()
    }
}

#[cfg(test)]
#[derive(Default)]
pub struct InMemoryStorage {
    pub files: RwLock<HashMap<PathBuf, IMFile>>,
}

#[cfg(test)]
impl InMemoryStorage {
    fn save_text_file<P: AsRef<Path>>(&self, path: P, content: &str) {
        let buf = content.bytes().collect::<Vec<_>>();
        self.save_file(
            path,
            IMFile::File(InMemoryFile {
                len: buf.len(),
                buf,
            }),
        );
    }

    fn save_file<P: AsRef<Path>>(&self, path: P, im_file: IMFile) {
        self.mut_files().insert(path.as_ref().to_owned(), im_file);
    }

    pub(crate) fn files(&self) -> RwLockReadGuard<'_, HashMap<PathBuf, IMFile>> {
        loop {
            match self.files.try_read() {
                Ok(files) => break files,
                _ => thread::sleep(std::time::Duration::from_micros(100)),
            }
        }
    }

    pub(crate) fn mut_files(&self) -> RwLockWriteGuard<'_, HashMap<PathBuf, IMFile>> {
        loop {
            match self.files.try_write() {
                Ok(files) => break files,
                _ => thread::sleep(std::time::Duration::from_micros(100)),
            }
        }
    }

    // --------------------------------
    // TEST DATA
    // -------------------------------

    pub(crate) fn add_hello_txt(&self) {
        self.save_text_file("hello.txt", "hello world");
    }

    pub(crate) fn add_bar_foo_folder(&self) {
        self.save_file("bar/", IMFile::Dir);
        self.save_text_file("bar/hello.txt", "hello");
        self.save_text_file("bar/world.txt", "world");
        self.save_file("bar/foo/", IMFile::Dir);
        self.save_text_file("bar/foo/hello.txt", "hello");
        self.save_text_file("bar/foo/world.txt", "world");
    }

    pub(crate) fn add_bar_foo_folder_with_hidden(&self) {
        self.save_file("bar/", IMFile::Dir);
        self.save_text_file("bar/.hello.txt", "hello");
        self.save_text_file("bar/world.txt", "world");
        self.save_file("bar/.foo/", IMFile::Dir);
        self.save_text_file("bar/.foo/hello.txt", "hello");
        self.save_text_file("bar/.foo/world.txt", "world");
    }
}

#[cfg(test)]
impl Storage<io::Cursor<Vec<u8>>> for InMemoryStorage {
    fn create_dir_all<P: AsRef<Path>>(&self, _path: P) -> Result<(), Error> {
        todo!();
    }

    fn create_file<P: AsRef<Path>>(&self, path: P) -> Result<Entry<io::Cursor<Vec<u8>>>, Error> {
        let file_path = path.as_ref().to_path_buf();

        #[allow(clippy::significant_drop_in_scrutinee)]
        let im_file = match self.files().get(&file_path) {
            Some(_) => Err(Error::CreateFile),
            None => Ok(IMFile::File(InMemoryFile::default())),
        }?;

        let cursor = io::Cursor::new(im_file.inner().buf.clone());

        self.save_file(file_path.clone(), im_file);

        Ok(Entry::File(FileData {
            path: file_path,
            stream: RefCell::new(cursor),
        }))
    }

    fn read_file<P: AsRef<Path>>(&self, path: P) -> Result<Entry<io::Cursor<Vec<u8>>>, Error> {
        let in_file = self
            .files()
            .get(path.as_ref())
            .cloned()
            .ok_or(Error::OpenFile(FileMode::Read))?;

        let file_path = path.as_ref().to_path_buf();

        match in_file {
            IMFile::Dir => Ok(Entry::Dir(file_path)),
            IMFile::File(f) => {
                let cursor = io::Cursor::new(f.buf);
                Ok(Entry::File(FileData {
                    path: file_path,
                    stream: RefCell::new(cursor),
                }))
            }
        }
    }

    fn write_file<P: AsRef<Path>>(&self, path: P) -> Result<Entry<io::Cursor<Vec<u8>>>, Error> {
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

        Ok(Entry::File(FileData {
            path: file_path,
            stream: RefCell::new(cursor),
        }))
    }

    fn flush_file(&self, file: &Entry<io::Cursor<Vec<u8>>>) -> Result<(), Error> {
        if file.is_dir() {
            return Err(Error::FileAccess);
        }

        let file_path = file.path();
        let writer = file.try_writer()?;
        writer.borrow_mut().flush().map_err(|_| Error::FlushFile)?;

        let vec = writer.borrow().get_ref().clone();
        let len = vec.len();
        let new_file = IMFile::File(InMemoryFile { buf: vec, len });

        self.save_file(file_path, new_file);

        Ok(())
    }

    fn file_len(&self, file: &Entry<io::Cursor<Vec<u8>>>) -> Result<usize, Error> {
        let cur = match file {
            Entry::File(FileData { stream, .. }) => stream.borrow(),
            Entry::Dir(_) => return Err(Error::FileAccess),
        };

        Ok(cur.get_ref().len())
    }

    fn remove_file(&self, file: Entry<io::Cursor<Vec<u8>>>) -> Result<(), Error> {
        self.mut_files()
            .remove(file.path())
            .ok_or(Error::RemoveFile)?;
        Ok(())
    }

    fn remove_dir_all(&self, file: Entry<io::Cursor<Vec<u8>>>) -> Result<(), Error> {
        if !file.is_dir() {
            return Err(Error::FileAccess);
        }

        let file_path = file.path();

        #[allow(clippy::needless_collect)] // 🚫 we have to collect to close read lock guard!
        let file_paths = self
            .files()
            .keys()
            .filter(|k| k.starts_with(file_path))
            .cloned()
            .collect::<Vec<_>>();

        file_paths.into_iter().try_for_each(|k| {
            self.mut_files()
                .remove(&k)
                .map(|_| ())
                .ok_or(Error::RemoveDir)?;
            Ok(())
        })
    }

    fn read_dir(
        &self,
        file: &Entry<io::Cursor<Vec<u8>>>,
    ) -> Result<Vec<Entry<io::Cursor<Vec<u8>>>>, Error> {
        if !file.is_dir() {
            return Err(Error::FileAccess);
        }

        let file_path = file.path();

        self.files()
            .iter()
            .filter(|(k, _)| k.starts_with(file_path))
            .map(|(k, _)| self.read_file(k))
            .collect()
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

pub struct FileData<RW>
where
    RW: Read + Write + Seek,
{
    path: PathBuf,
    stream: RefCell<RW>,
}

pub enum Entry<RW>
where
    RW: Read + Write + Seek,
{
    File(FileData<RW>),
    Dir(PathBuf),
}

impl<RW> Entry<RW>
where
    RW: Read + Write + Seek,
{
    pub fn path(&self) -> &Path {
        match self {
            Entry::File(FileData { path, .. }) | Entry::Dir(path) => path,
        }
    }

    pub fn is_dir(&self) -> bool {
        matches!(self, Entry::Dir(_))
    }

    pub fn try_reader(&self) -> Result<&RefCell<RW>, Error> {
        match self {
            Entry::File(file) => Ok(&file.stream),
            Entry::Dir(_) => Err(Error::FileAccess),
        }
    }

    pub fn try_writer(&self) -> Result<&RefCell<RW>, Error> {
        match self {
            Entry::File(file) => Ok(&file.stream),
            Entry::Dir(_) => Err(Error::FileAccess),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sorted_file_names(file_names: &[PathBuf]) -> Vec<&str> {
        let mut keys = file_names
            .iter()
            .map(|k| k.to_str().unwrap())
            .collect::<Vec<_>>();
        keys.sort_unstable();
        keys
    }

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
        stor.add_hello_txt();

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
        stor.add_hello_txt();

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
        stor.add_hello_txt();

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
        stor.add_hello_txt();

        let file = stor.write_file("hello.txt").unwrap();
        let file_path = file.path().to_path_buf();

        match stor.remove_file(file) {
            Ok(_) => {
                let im_file = stor.files().get(&file_path).cloned();
                assert_eq!(im_file, None);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_remove_a_file_in_write_mode() {
        let stor = InMemoryStorage::default();
        stor.add_hello_txt();

        let file = stor.write_file("hello.txt").unwrap();
        let file_path = file.path().to_path_buf();

        match stor.remove_file(file) {
            Ok(_) => {
                let im_file = stor.files().get(&file_path).cloned();
                assert_eq!(im_file, None);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_get_file_length() {
        let stor = InMemoryStorage::default();
        stor.add_hello_txt();

        let file = stor.read_file("hello.txt").unwrap();

        match stor.file_len(&file) {
            Ok(len) => {
                let content = b"hello world".to_vec();
                assert_eq!(len, content.len());
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_open_dir() {
        let stor = InMemoryStorage::default();
        stor.add_bar_foo_folder();

        match stor.read_file("bar/foo/") {
            Ok(Entry::Dir(path)) => assert_eq!(path, PathBuf::from("bar/foo/")),
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_remove_dir_with_subfiles() {
        let stor = InMemoryStorage::default();
        stor.add_hello_txt();
        stor.add_bar_foo_folder();

        let file = stor.read_file("bar/foo/").unwrap();
        let file_path = file.path().to_path_buf();

        match stor.remove_dir_all(file) {
            Ok(()) => {
                assert_eq!(stor.files().get(&file_path).cloned(), None);
                let files = stor.files();
                let keys = files.keys().cloned().collect::<Vec<_>>();
                assert_eq!(
                    sorted_file_names(&keys),
                    vec!["bar/", "bar/hello.txt", "bar/world.txt", "hello.txt"]
                );
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_remove_dir_recursively_with_subfiles() {
        let stor = InMemoryStorage::default();
        stor.add_hello_txt();
        stor.add_bar_foo_folder();

        let file = stor.read_file("bar/").unwrap();
        let file_path = file.path().to_path_buf();

        match stor.remove_dir_all(file) {
            Ok(()) => {
                assert_eq!(stor.files().get(&file_path).cloned(), None);
                let files = stor.files();
                let keys = files.keys().cloned().collect::<Vec<PathBuf>>();
                assert_eq!(sorted_file_names(&keys), vec!["hello.txt"]);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_return_file_names_of_dir_subfiles() {
        let stor = InMemoryStorage::default();
        stor.add_hello_txt();
        stor.add_bar_foo_folder();

        let file = stor.read_file("bar/").unwrap();

        match stor.read_dir(&file) {
            Ok(files) => {
                let file_names = files
                    .iter()
                    .map(|f| f.path().to_path_buf())
                    .collect::<Vec<_>>();
                assert_eq!(
                    sorted_file_names(&file_names),
                    vec![
                        "bar/",
                        "bar/foo/",
                        "bar/foo/hello.txt",
                        "bar/foo/world.txt",
                        "bar/hello.txt",
                        "bar/world.txt",
                    ]
                );
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_include_hidden_files_names() {
        let stor = InMemoryStorage::default();
        stor.add_hello_txt();
        stor.add_bar_foo_folder_with_hidden();

        let file = stor.read_file("bar/").unwrap();

        match stor.read_dir(&file) {
            Ok(files) => {
                let file_names = files
                    .into_iter()
                    .map(|f| f.path().to_path_buf())
                    .collect::<Vec<_>>();
                assert_eq!(
                    sorted_file_names(&file_names),
                    vec![
                        "bar/",
                        "bar/.foo/",
                        "bar/.foo/hello.txt",
                        "bar/.foo/world.txt",
                        "bar/.hello.txt",
                        "bar/world.txt",
                    ]
                );
            }
            _ => unreachable!(),
        }
    }
}
