use dexios_domain::storage::{Error, FileStorage, Storage};
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
        fs::remove_dir_all(format!("bar_{}/", self.test_case_n)).ok();
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
    let bar_dir = format!("bar_{}", stor.test_case_n);
    fs::create_dir(&bar_dir).map_err(|_| Error::CreateFile)?;
    save_text_file(stor, format!("{}/hello.txt", &bar_dir), "hello")?;
    save_text_file(stor, format!("{}/world.txt", &bar_dir), "world")?;
    fs::create_dir(format!("{}/foo/", &bar_dir)).map_err(|_| Error::CreateFile)?;
    save_text_file(stor, format!("{}/foo/hello.txt", &bar_dir), "hello")?;
    save_text_file(stor, format!("{}/foo/world.txt", &bar_dir), "world")?;
    Ok(())
}

pub fn add_bar_foo_folder_with_hidden(stor: &TestFileStorage) -> Result<(), Error> {
    let bar_dir = format!("bar_{}", stor.test_case_n);
    fs::create_dir(&bar_dir).map_err(|_| Error::CreateFile)?;
    save_text_file(stor, format!("{}/.hello.txt", &bar_dir), "hello")?;
    save_text_file(stor, format!("{}/world.txt", &bar_dir), "world")?;
    fs::create_dir(format!("{}/.foo/", &bar_dir)).map_err(|_| Error::CreateFile)?;
    save_text_file(stor, format!("{}/.foo/hello.txt", &bar_dir), "hello")?;
    save_text_file(stor, format!("{}/.foo/world.txt", &bar_dir), "world")?;
    Ok(())
}

pub fn sorted_file_names(file_names: Vec<&PathBuf>) -> Vec<&str> {
    let mut keys = file_names
        .iter()
        .map(|k| k.to_str().unwrap())
        .collect::<Vec<_>>();
    keys.sort_unstable();
    keys
}
