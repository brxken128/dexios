use std::{path::Path, fs::File};

use anyhow::Result;
use zip::write::FileOptions;

use crate::{global::{Parameters, DirectoryMode}, file::get_paths_in_dir};

pub fn encrypt_directory(input: &str, output: &str, exclude: Vec<&str>, keyfile: &str, mode: DirectoryMode, params: Parameters) -> Result<()> {
    let (files, dirs) = get_paths_in_dir(input, mode)?;

    let file = File::create(output)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Bzip2)
        .compression_level(Some(6)) // this is the default anyway
        .unix_permissions(0o755);

    if mode == DirectoryMode::Recursive {
        let directories = match dirs { // could probably just unwrap
            Some(directories) => directories,
            None => Vec::new(),
        };
        for dir in directories {
            zip.add_directory(dir.to_str().unwrap(), options)?;
        }
    }



    Ok(())
}