use dexios::storage::{Error, FileStorage, Storage};
use std::fs;
use std::io::Write;
use std::ops::Deref;
use std::path::{Path, PathBuf};

pub struct TestFileStorage {
    inner: FileStorage,
    test_case_n: u32,
}

impl TestFileStorage {
    pub fn new(test_case_n: u32) -> Self {
        Self {
            inner: FileStorage,
            test_case_n,
        }
    }
}

impl Deref for TestFileStorage {
    type Target = FileStorage;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Drop for TestFileStorage {
    fn drop(&mut self) {
        fs::remove_file(format!("hello_{}.txt", self.test_case_n)).ok();
        fs::remove_dir_all(format!("bar_{}", self.test_case_n)).ok();
    }
}

pub fn save_text_file<P>(stor: &TestFileStorage, path: P, content: &str) -> Result<(), Error>
where
    P: AsRef<Path>,
{
    let file = stor.create_file(path)?;
    file.try_writer()?
        .borrow_mut()
        .write_all(content.as_bytes())
        .map_err(|_| Error::CreateFile)?;
    stor.flush_file(&file)
}

// --------------------------------
// TEST DATA
// -------------------------------

pub fn add_hello_txt(stor: &TestFileStorage) -> Result<(), Error> {
    save_text_file(
        stor,
        format!("hello_{}.txt", stor.test_case_n),
        "hello world",
    )
}

pub fn add_bar_foo_folder(stor: &TestFileStorage) -> Result<(), Error> {
    let bar = PathBuf::from(format!("bar_{}", stor.test_case_n));
    let mut foo_bar = bar.clone();
    foo_bar.push("foo");

    for folder in [bar, foo_bar] {
        fs::create_dir(&folder).map_err(|_| Error::CreateFile)?;

        for file in ["hello", "world"] {
            let mut file_path = folder.clone();
            file_path.push(format!("{}.txt", file));

            save_text_file(stor, file_path, file)?;
        }
    }

    Ok(())
}

pub fn add_bar_foo_folder_with_hidden(stor: &TestFileStorage) -> Result<(), Error> {
    let bar = PathBuf::from(format!("bar_{}", stor.test_case_n));
    let mut foo_bar = bar.clone();
    foo_bar.push(".foo");

    for (i, folder) in [bar, foo_bar].into_iter().enumerate() {
        fs::create_dir(&folder).map_err(|_| Error::CreateFile)?;

        for (j, file) in ["hello", "world"].into_iter().enumerate() {
            let mut file_path = folder.clone();
            file_path.push(format!(
                "{}{}.txt",
                if i == 0 && j == 0 { "." } else { "" },
                file
            ));

            save_text_file(stor, file_path, file)?;
        }
    }

    Ok(())
}

pub fn sorted_file_names(file_names: Vec<&PathBuf>) -> Vec<&PathBuf> {
    let mut keys = file_names;
    keys.sort_unstable();
    keys
}
