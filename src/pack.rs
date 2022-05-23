use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
    str::FromStr,
};

use anyhow::{Context, Result};
use rand::distributions::{Alphanumeric, DistString};
use zip::write::FileOptions;

use crate::{
    file::get_paths_in_dir,
    global::{DirectoryMode, Parameters, SkipMode, BLOCK_SIZE},
    prompt::get_answer,
};

pub fn encrypt_directory(
    input: &str,
    output: &str,
    exclude: Vec<&str>,
    keyfile: &str,
    mode: DirectoryMode,
    memory: bool,
    params: Parameters,
) -> Result<()> {
    let (files, dirs) = get_paths_in_dir(input, mode)?;
    let random_extension: String = Alphanumeric.sample_string(&mut rand::thread_rng(), 8);

    let tmp_name = format!("{}.{}", output, random_extension); // e.g. "output.kjHSD93l"

    let file = File::create(&tmp_name).context("Unable to create the output file")?;
    let mut zip = zip::ZipWriter::new(file);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Bzip2)
        .compression_level(Some(6)) // this is the default anyway
        .unix_permissions(0o755);

    zip.add_directory(input, options)?;

    if mode == DirectoryMode::Recursive {
        let directories = dirs.context("Error unwrapping directory vec")?; // this should always be *something* anyway
        for dir in directories {
            zip.add_directory(dir.to_str().unwrap(), options)?;
        }
    }

    for file in files {
        zip.start_file(file.to_str().unwrap(), options)
            .context("Unable to add file to zip")?;
        println!("Compressing {} into {}", file.to_str().unwrap(), tmp_name);
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
                if read_count == BLOCK_SIZE {
                    zip_writer
                        .write_all(&buffer[..read_count])
                        .context("Unable to write to the output file")?;
                } else {
                    zip_writer
                        .write_all(&buffer[..read_count])
                        .context("Unable to write to the output file")?;
                    break;
                }
            }
        }
    }
    zip.finish()?;

    if memory {
        crate::encrypt::memory_mode(&tmp_name, output, keyfile, &params)?;
    } else {
        crate::encrypt::stream_mode(&tmp_name, output, keyfile, &params)?;
    };

    crate::erase::secure_erase(&tmp_name, 8)?; // cleanup our tmp file

    println!("Your output file is: {}", output);

    Ok(())
}

pub fn decrypt_directory(
    input: &str,        // encrypted zip file
    output: &str,       // directory
    keyfile: &str,      // for decrypt function
    memory: bool,       // memory or stream mode
    params: Parameters, // params for decrypt function
) -> Result<()> {
    let random_extension: String = Alphanumeric.sample_string(&mut rand::thread_rng(), 8);

    // this is the name of the decrypted zip file
    let tmp_name = format!("{}.{}", input, random_extension); // e.g. "input.kjHSD93l"

    if memory {
        crate::decrypt::memory_mode(input, &tmp_name, keyfile, &params)?;
    } else {
        crate::decrypt::stream_mode(input, &tmp_name, keyfile, &params)?;
    }

    let file = File::open(&tmp_name).context("Unable to open temporary archive")?;
    let mut archive = zip::ZipArchive::new(file)
        .context("Temporary archive can't be opened, is it a zip file?")?;

    match std::fs::create_dir(output) {
        Ok(_) => println!("Created output directory: {}", output),
        Err(_) => println!("Output directory ({}) already exists!", output),
    }

    for i in 0..archive.len() {
        let mut full_path = PathBuf::from_str(output)
            .context("Unable to create a PathBuf from your output directory")?;

        let mut file = archive.by_index(i).context("Unable to index the archive")?;
        match file.enclosed_name() {
            Some(path) => full_path.push(path.to_owned()),
            None => continue,
        };

        if file.name().ends_with('/') {
            // if it's a directory, recreate the structure
            std::fs::create_dir_all(full_path)?;
        } else {
            // this must be a file
            let file_name: String = full_path
                .clone()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            if std::fs::metadata(full_path.clone()).is_ok() {
                let answer = get_answer(
                    &format!("{} already exists, would you like to overwrite?", file_name),
                    true,
                    params.skip == SkipMode::HidePrompts,
                )?;
                if !answer {
                    println!("Skipping {}", file_name);
                    continue;
                }
            }
            println!("Extracting {}", file_name);
            let mut output_file = File::create(full_path)?;
            std::io::copy(&mut file, &mut output_file)?;
        }
    }

    crate::erase::secure_erase(&tmp_name, 8)?; // cleanup the tmp file
    Ok(())
}
