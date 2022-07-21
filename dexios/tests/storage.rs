mod common;
use common::*;
use dexios::storage::*;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

#[test]
fn should_create_a_new_file() {
    let stor = TestFileStorage::new(1);

    match stor.create_file("hello_1.txt") {
        Ok(_) => match fs::File::open("hello_1.txt") {
            Ok(_) => {}
            _ => unreachable!(),
        },
        _ => unreachable!(),
    }
}

#[test]
fn should_throw_an_error_if_file_already_exist() {
    let stor = TestFileStorage::new(2);
    add_hello_txt(&stor).unwrap();

    match stor.create_file("hello_2.txt") {
        Err(Error::CreateFile) => {}
        _ => unreachable!(),
    }
}

#[test]
fn should_not_open_file_to_read() {
    let stor = TestFileStorage::new(3);

    match stor.read_file("hello_3.txt") {
        Err(Error::OpenFile(FileMode::Read)) => {}
        _ => unreachable!(),
    }
}

#[test]
fn should_not_open_file_to_write() {
    let stor = TestFileStorage::new(4);

    match stor.write_file("hello_4.txt") {
        Err(Error::OpenFile(FileMode::Write)) => {}
        _ => unreachable!(),
    }
}

#[test]
fn should_open_exist_file_in_read_mode() {
    let stor = TestFileStorage::new(5);
    add_hello_txt(&stor).unwrap();

    match stor.read_file("hello_5.txt") {
        Ok(file) => {
            let mut file_buf = vec![];
            file.try_reader()
                .unwrap()
                .borrow_mut()
                .read_to_end(&mut file_buf)
                .unwrap();
            let content = b"hello world".to_vec();
            assert_eq!(file_buf, content);
            assert_eq!(file_buf.len(), content.len());
        }
        _ => unreachable!(),
    }
}

#[test]
fn should_open_exist_file_in_write_mode() {
    let stor = TestFileStorage::new(6);
    add_hello_txt(&stor).unwrap();

    match stor.write_file("hello_6.txt") {
        Ok(file) => {
            file.try_writer()
                .unwrap()
                .borrow_mut()
                .write_all(b"hello")
                .unwrap();
            stor.flush_file(&file).unwrap();
            let mut file_buf = vec![];
            fs::File::open("hello_6.txt")
                .unwrap()
                .read_to_end(&mut file_buf)
                .unwrap();
            let content = b"hello".to_vec();
            //assert_eq!(file_buf.len(), content.len());
            assert_eq!(file_buf, content);
        }
        _ => unreachable!(),
    }
}

#[test]
fn should_write_content_to_file() {
    let stor = TestFileStorage::new(7);
    let content = "hello world";

    let file = stor.create_file("hello_7.txt").unwrap();
    file.try_writer()
        .unwrap()
        .borrow_mut()
        .write_all(content.as_bytes())
        .unwrap();

    match stor.flush_file(&file) {
        Ok(_) => {
            let mut file_buf = vec![];
            fs::File::open("hello_7.txt")
                .unwrap()
                .read_to_end(&mut file_buf)
                .unwrap();
            let content = b"hello world".to_vec();
            assert_eq!(file_buf, content);
            assert_eq!(file_buf.len(), content.len());
        }
        _ => unreachable!(),
    }
}

#[test]
fn should_remove_a_file_in_read_mode() {
    let stor = TestFileStorage::new(8);
    add_hello_txt(&stor).unwrap();

    let file = stor.write_file("hello_8.txt").unwrap();

    match stor.remove_file(file) {
        Ok(_) => match fs::File::open("hello_8.txt") {
            Err(_) => {}
            _ => unreachable!(),
        },
        _ => unreachable!(),
    }
}

#[test]
fn should_remove_a_file_in_write_mode() {
    let stor = TestFileStorage::new(9);
    add_hello_txt(&stor).unwrap();

    let file = stor.write_file("hello_9.txt").unwrap();

    match stor.remove_file(file) {
        Ok(_) => match fs::File::open("hello_9.txt") {
            Err(_) => {}
            _ => unreachable!(),
        },
        _ => unreachable!(),
    }
}

#[test]
fn should_get_file_length() {
    let stor = TestFileStorage::new(10);
    add_hello_txt(&stor).unwrap();

    let file = stor.read_file("hello_10.txt").unwrap();

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
    let stor = TestFileStorage::new(11);
    add_bar_foo_folder(&stor).unwrap();

    let foo_bar = ["bar_11", "foo"].iter().collect::<PathBuf>();

    match stor.read_file(&foo_bar) {
        Ok(Entry::Dir(path)) => assert_eq!(path, foo_bar),
        _ => unreachable!(),
    }
}

#[test]
fn should_remove_dir_with_subfiles() {
    let stor = TestFileStorage::new(12);
    add_hello_txt(&stor).unwrap();
    add_bar_foo_folder(&stor).unwrap();

    let bar = PathBuf::from("bar_12");
    let foo_bar = ["bar_12", "foo"].iter().collect::<PathBuf>();
    let file = stor.read_file(&foo_bar).unwrap();

    match stor.remove_dir_all(file) {
        Ok(()) => match (fs::read_dir(&bar), fs::read_dir(&foo_bar)) {
            (Ok(_), Err(_)) => {}
            _ => unreachable!(),
        },
        _ => unreachable!(),
    }
}

#[test]
fn should_remove_dir_recursively_with_subfiles() {
    let stor = TestFileStorage::new(13);
    add_hello_txt(&stor).unwrap();
    add_bar_foo_folder(&stor).unwrap();

    let bar = PathBuf::from("bar_13");
    let foo_bar = ["bar_13", "foo"].iter().collect::<PathBuf>();
    let file = stor.read_file(&bar).unwrap();

    match stor.remove_dir_all(file) {
        Ok(()) => match (fs::read_dir(&bar), fs::read_dir(&foo_bar)) {
            (Err(_), Err(_)) => {}
            _ => unreachable!(),
        },
        _ => unreachable!(),
    }
}

#[test]
fn should_return_file_names_of_dir_subfiles() {
    let stor = TestFileStorage::new(14);
    add_hello_txt(&stor).unwrap();
    add_bar_foo_folder(&stor).unwrap();

    let file = stor.read_file(PathBuf::from("bar_14")).unwrap();

    match stor.read_dir(&file) {
        Ok(files) => {
            let file_names = files
                .iter()
                .map(|f| f.path().to_path_buf())
                .collect::<Vec<_>>();
            assert_eq!(
                sorted_file_names(file_names.iter().collect()),
                vec![
                    &PathBuf::from("bar_14"),
                    &["bar_14", "foo"].iter().collect(),
                    &["bar_14", "foo", "hello.txt"].iter().collect(),
                    &["bar_14", "foo", "world.txt"].iter().collect(),
                    &["bar_14", "hello.txt"].iter().collect(),
                    &["bar_14", "world.txt"].iter().collect(),
                ]
            )
        }
        _ => unreachable!(),
    }
}

#[test]
fn should_include_hidden_files_names() {
    let stor = TestFileStorage::new(15);
    add_hello_txt(&stor).unwrap();
    add_bar_foo_folder_with_hidden(&stor).unwrap();

    let file = stor.read_file(PathBuf::from("bar_15")).unwrap();

    match stor.read_dir(&file) {
        Ok(files) => {
            let file_names = files
                .iter()
                .map(|f| f.path().to_path_buf())
                .collect::<Vec<_>>();
            assert_eq!(
                sorted_file_names(file_names.iter().collect()),
                vec![
                    &PathBuf::from("bar_15"),
                    &["bar_15", ".foo"].iter().collect(),
                    &["bar_15", ".foo", "hello.txt"].iter().collect(),
                    &["bar_15", ".foo", "world.txt"].iter().collect(),
                    &["bar_15", ".hello.txt"].iter().collect(),
                    &["bar_15", "world.txt"].iter().collect(),
                ]
            )
        }
        _ => unreachable!(),
    }
}
