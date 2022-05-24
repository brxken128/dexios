use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
    str::FromStr,
    time::Instant,
};

use anyhow::{Context, Result};
use rand::distributions::{Alphanumeric, DistString};
use zip::write::FileOptions;

use crate::{
    file::get_paths_in_dir,
    global::{DirectoryMode, HiddenFilesMode, Parameters, PrintMode, SkipMode, BLOCK_SIZE},
    prompt::get_answer,
};

pub fn encrypt_directory(
    input: &str,
    output: &str,
    exclude: &[&str],
    keyfile: &str,
    mode: DirectoryMode,
    hidden: &HiddenFilesMode,
    memory: bool,
    compression_level: i32,
    print_mode: &PrintMode,
    params: &Parameters,
) -> Result<()> {
    if mode == DirectoryMode::Recursive {
        println!("Traversing {} recursively", input);
    } else {
        println!("Traversing {}", input);
    }

    let index_start_time = Instant::now();
    let (files, dirs) = get_paths_in_dir(input, mode, exclude, hidden, print_mode)?;
    let index_duration = index_start_time.elapsed();
    let file_count = files.len();
    println!(
        "Indexed {} files [took {:.2}s]",
        file_count,
        index_duration.as_secs_f32()
    );

    let random_extension: String = Alphanumeric.sample_string(&mut rand::thread_rng(), 8);
    let tmp_name = format!("{}.{}", output, random_extension); // e.g. "output.kjHSD93l"

    let file = std::io::BufWriter::new(
        File::create(&tmp_name)
            .with_context(|| format!("Unable to create the output file: {}", output))?,
    );

    println!(
        "Creating and compressing files into {} with a compression level of {}",
        tmp_name, compression_level
    );

    let zip_start_time = Instant::now();

    let mut zip = zip::ZipWriter::new(file);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .compression_level(Some(compression_level)) // this is the default anyway
        .large_file(true)
        .unix_permissions(0o755);

    zip.add_directory(input, options)
        .context("Unable to add directory to zip")?;

    if mode == DirectoryMode::Recursive {
        let directories = dirs.context("Error unwrapping Vec containing list of directories.")?; // this should always be *something* anyway
        for dir in directories {
            zip.add_directory(
                dir.to_str()
                    .context("Error converting directory path to string")?,
                options,
            )
            .context("Unable to add directory to zip")?;
        }
    }

    for file in files {
        zip.start_file(
            file.to_str()
                .context("Error converting file path to string")?,
            options,
        )
        .context("Unable to add file to zip")?;

        if print_mode == &PrintMode::Verbose {
            println!("Compressing {} into {}", file.to_str().unwrap(), tmp_name);
        }

        let zip_writer = zip.by_ref();
        let mut file_reader = File::open(file)?;
        let file_size = file_reader.metadata().unwrap().len();

        if file_size <= BLOCK_SIZE.try_into().unwrap() {
            let mut data = Vec::new();
            file_reader.read_to_end(&mut data)?;
            zip_writer.write_all(&data)?;
        } else {
            // stream read/write here
            let mut buffer = [0u8; BLOCK_SIZE];

            loop {
                let read_count = file_reader.read(&mut buffer)?;
                if read_count == BLOCK_SIZE {
                    zip_writer
                        .write_all(&buffer[..read_count])
                        .with_context(|| {
                            format!("Unable to write to the output file: {}", output)
                        })?;
                } else {
                    zip_writer
                        .write_all(&buffer[..read_count])
                        .with_context(|| {
                            format!("Unable to write to the output file: {}", output)
                        })?;
                    break;
                }
            }
        }
    }
    zip.finish()?;
    drop(zip);

    let zip_duration = zip_start_time.elapsed();
    println!(
        "Compressed {} files into {}! [took {:.2}s]",
        file_count,
        tmp_name,
        zip_duration.as_secs_f32()
    );

    if memory {
        crate::encrypt::memory_mode(&tmp_name, output, keyfile, params)?;
    } else {
        crate::encrypt::stream_mode(&tmp_name, output, keyfile, params)?;
    };

    crate::erase::secure_erase(&tmp_name, 16)?; // cleanup our tmp file

    println!("Your output file is: {}", output);

    Ok(())
}

pub fn decrypt_directory(
    input: &str,   // encrypted zip file
    output: &str,  // directory
    keyfile: &str, // for decrypt function
    memory: bool,  // memory or stream mode
    print_mode: &PrintMode,
    params: &Parameters, // params for decrypt function
) -> Result<()> {
    let random_extension: String = Alphanumeric.sample_string(&mut rand::thread_rng(), 8);

    // this is the name of the decrypted zip file
    let tmp_name = format!("{}.{}", input, random_extension); // e.g. "input.kjHSD93l"

    if memory {
        crate::decrypt::memory_mode(input, &tmp_name, keyfile, params)?;
    } else {
        crate::decrypt::stream_mode(input, &tmp_name, keyfile, params)?;
    }

    let zip_start_time = Instant::now();
    let file = File::open(&tmp_name).context("Unable to open temporary archive")?;
    let mut archive = zip::ZipArchive::new(file)
        .context("Temporary archive can't be opened, is it a zip file?")?;

    match std::fs::create_dir(output) {
        Ok(_) => println!("Created output directory: {}", output),
        Err(_) => println!("Output directory ({}) already exists!", output),
    }

    let file_count = archive.len();

    println!("Decompressing {} items into {}", file_count, output);

    for i in 0..file_count {
        let mut full_path = PathBuf::from_str(output)
            .context("Unable to create a PathBuf from your output directory")?;

        let mut file = archive.by_index(i).context("Unable to index the archive")?;
        match file.enclosed_name() {
            Some(path) => full_path.push(path),
            None => continue,
        };

        if file.name().ends_with('/') {
            // if it's a directory, recreate the structure
            std::fs::create_dir_all(full_path).context("Unable to create an output directory")?;
        } else {
            // this must be a file
            let file_name: String = full_path
                .clone()
                .file_name()
                .context("Unable to convert file name to OsStr")?
                .to_str()
                .context("Unable to convert file name's OsStr to &str")?
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
            if print_mode == &PrintMode::Verbose {
                println!("Extracting {}", file_name);
            }
            let mut output_file =
                File::create(full_path).context("Error creating an output file")?;
            std::io::copy(&mut file, &mut output_file)
                .context("Error copying data out of archive to the target file")?;
        }
    }

    let zip_duration = zip_start_time.elapsed();
    println!(
        "Extracted {} items to {} [took {:.2}s]",
        file_count,
        output,
        zip_duration.as_secs_f32()
    );

    crate::erase::secure_erase(&tmp_name, 16)?; // cleanup the tmp file

    println!(
        "Unpacking Successful! You will find your files in {}",
        output
    );

    Ok(())
}
