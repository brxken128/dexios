use crate::global::parameters::DirectoryMode;
use crate::global::parameters::HiddenFilesMode;
use crate::global::parameters::PrintMode;
use anyhow::{Context, Ok, Result};
use secrecy::Secret;
use secrecy::SecretVec;
use std::fs::read_dir;
use std::path::PathBuf;
use std::{
    fs::File,
    io::Read,
};

// this takes the name/relative path of a file, and returns the bytes wrapped in a secret
pub fn get_bytes(name: &str) -> Result<Secret<Vec<u8>>> {
    let mut file = File::open(name).with_context(|| format!("Unable to open file: {}", name))?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .with_context(|| format!("Unable to read file: {}", name))?;
    Ok(SecretVec::new(data))
}


pub fn get_paths_in_dir(
    name: &str,
    mode: DirectoryMode,
    exclude: &[String],
    hidden: &HiddenFilesMode,
    print_mode: &PrintMode,
) -> Result<(Vec<PathBuf>, Option<Vec<PathBuf>>)> {
    let mut file_list = Vec::new(); // so we know what files to encrypt
    let mut dir_list = Vec::new(); // so we can recreate the structure inside of the zip file

    let paths =
        read_dir(name).with_context(|| format!("Unable to open the directory: {}", name))?;

    'dirs: for item in paths {
        let path = item
            .with_context(|| format!("Unable to get the item's path: {}", name))?
            .path(); // not great error message

        let file_name = path
            .file_name()
            .context("Unable to get file name from path")?
            .to_str()
            .context("Unable to convert OsStr into str")?;
        let first_char = file_name
            .chars()
            .next()
            .context("Unable to get first character of the file/folder's name")?;

        if hidden == &HiddenFilesMode::Exclude && first_char == '.' {
            continue;
        }

        for pattern in exclude {
            if file_name == *pattern {
                continue 'dirs;
            }
        }

        if path.is_dir() && mode == DirectoryMode::Recursive {
            let (files, dirs) =
                get_paths_in_dir(path.to_str().unwrap(), mode, exclude, hidden, print_mode)?;
            dir_list.push(path);

            file_list.extend(files);
            dir_list.extend(dirs.unwrap()); // this should never error and it should be there, at least empty - should still add context
        } else if path.is_dir() {
            if print_mode == &PrintMode::Verbose {
                println!(
                    "Skipping {} as it's a directory and -r was not specified",
                    path.display()
                );
            }
        } else if path.is_symlink() {
            if print_mode == &PrintMode::Verbose {
                println!("Skipping {} as it's a symlink", path.display());
            }
        } else {
            file_list.push(path);
        }
    }

    if mode == DirectoryMode::Recursive {
        Ok((file_list, Some(dir_list)))
    } else {
        Ok((file_list, None))
    }
}
