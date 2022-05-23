use std::{path::Path, fs::File, io::{Read, Write}};

use anyhow::{Result, Context};
use zip::write::FileOptions;

use crate::{global::{Parameters, DirectoryMode, BLOCK_SIZE}, file::get_paths_in_dir};

pub fn encrypt_directory(input: &str, output: &str, exclude: Vec<&str>, keyfile: &str, mode: DirectoryMode, params: Parameters) -> Result<()> {
    let (files, dirs) = get_paths_in_dir(input, mode)?;

    let file = File::create(output)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Bzip2)
        .compression_level(Some(6)) // this is the default anyway
        .unix_permissions(0o755);

    if mode == DirectoryMode::Recursive {
        let directories = dirs.context("Error unwrapping directory vec")?; // this should always be *something* anyway
        for dir in directories {
            zip.add_directory(dir.to_str().unwrap(), options)?;
        }
    }

    for file in files {
        zip.start_file(file.to_str().unwrap(), options)?;

        let zip_writer = zip.by_ref();
        let mut file_reader = File::open(file)?;
        let file_size = file_reader.metadata().unwrap().len();

        if file_size <= BLOCK_SIZE.try_into().unwrap() {
            let mut data = Vec::new();
            file_reader.read_to_end(&mut data)?;
            zip_writer.write_all(&mut data)?;
        } else {
            // stream read/write here
            let mut buffer = [0u8; BLOCK_SIZE];

            loop {
                let read_count = file_reader.read(&mut buffer)?;
                zip_writer
                    .write_all(&buffer[..read_count])
                    .context("Unable to write to the output file")?;
            }
        }
    }

    zip.finish()?;

    Ok(())
}