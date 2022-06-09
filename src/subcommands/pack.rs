use std::{
    fs::File,
    io::{Read, Write},
    time::Instant,
};

use anyhow::{Context, Result};
use dexios_core::primitives::{Algorithm, BLOCK_SIZE};
use paris::Logger;
use rand::distributions::{Alphanumeric, DistString};
use zip::write::FileOptions;

use crate::{
    file::get_paths_in_dir,
    global::states::{DirectoryMode, PrintMode, DeleteSourceDir},
    global::structs::{CryptoParams, PackParams},
};

// this first indexes the input directory
// once it has the total number of files/folders, it creates a temporary zip file
// it compresses all of the files into the temporary archive
// once compressed, it encrypts the zip file
// it erases the temporary archive afterwards, to stop any residual data from remaining
#[allow(clippy::module_name_repetitions)]
#[allow(clippy::too_many_lines)]
pub fn pack(
    input: &str,
    output: &str,
    pack_params: &PackParams,
    params: &CryptoParams,
    algorithm: Algorithm,
) -> Result<()> {
    let mut logger = Logger::new();

    if pack_params.dir_mode == DirectoryMode::Recursive {
        logger.info(format!("Traversing {} recursively", input));
    } else {
        logger.info(format!("Traversing {}", input));
    }

    let index_start_time = Instant::now();
    let (files, dirs) = get_paths_in_dir(
        input,
        pack_params.dir_mode,
        &pack_params.exclude,
        &pack_params.hidden,
        &pack_params.print_mode,
    )?;
    let index_duration = index_start_time.elapsed();
    let file_count = files.len();
    logger.success(format!(
        "Indexed {} files [took {:.2}s]",
        file_count,
        index_duration.as_secs_f32()
    ));

    let random_extension: String = Alphanumeric.sample_string(&mut rand::thread_rng(), 8);
    let tmp_name = format!("{}.{}", output, random_extension); // e.g. "output.kjHSD93l"

    let file = std::io::BufWriter::new(
        File::create(&tmp_name)
            .with_context(|| format!("Unable to create the output file: {}", output))?,
    );

    logger.info(format!("Creating and compressing files into {}", tmp_name));

    let zip_start_time = Instant::now();

    let mut zip = zip::ZipWriter::new(file);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .large_file(true)
        .unix_permissions(0o755);

    zip.add_directory(input, options)
        .context("Unable to add directory to zip")?;

    if pack_params.dir_mode == DirectoryMode::Recursive {
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

        if pack_params.print_mode == PrintMode::Verbose {
            logger.info(format!(
                "Compressing {} into {}",
                file.to_str().unwrap(),
                tmp_name
            ));
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
            let mut buffer = vec![0u8; BLOCK_SIZE].into_boxed_slice();

            loop {
                let read_count = file_reader.read(&mut buffer)?;
                zip_writer
                    .write_all(&buffer[..read_count])
                    .with_context(|| format!("Unable to write to the output file: {}", output))?;
                if read_count != BLOCK_SIZE {
                    break;
                }
            }
        }
    }
    zip.finish()?;
    drop(zip);

    let zip_duration = zip_start_time.elapsed();
    logger.success(format!(
        "Compressed {} files into {}! [took {:.2}s]",
        file_count,
        tmp_name,
        zip_duration.as_secs_f32()
    ));

    super::encrypt::stream_mode(&tmp_name, output, params, algorithm)?;

    super::erase::secure_erase(&tmp_name, 2)?; // cleanup our tmp file

    if pack_params.delete_source == DeleteSourceDir::Delete {
        std::fs::remove_dir_all(input).context("Unable to delete source directory")?;
    }

    logger.success(format!("Your output file is: {}", output));

    Ok(())
}
