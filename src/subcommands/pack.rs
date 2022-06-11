use std::{
    fs::File,
    io::{Read, Write},
    time::Instant,
};

use anyhow::{Context, Result};
use dexios_core::primitives::{Algorithm, BLOCK_SIZE};
use paris::Logger;
use rand::distributions::{Alphanumeric, DistString};
use walkdir::WalkDir;
use zip::write::FileOptions;

use crate::{
    global::states::{DirectoryMode, EraseSourceDir, PrintMode},
    global::{structs::{CryptoParams, PackParams}},
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

    let mut item_count = 0;

    if pack_params.dir_mode == DirectoryMode::Recursive {
        logger.info(format!("Traversing {} recursively", input));
    } else {
        logger.info(format!("Traversing {}", input));
    }

    let walker = if pack_params.dir_mode == DirectoryMode::Recursive {
        WalkDir::new(input)
    } else {
        WalkDir::new(input).max_depth(1)
    };

    for item in walker {
        item_count += 1;

        let item_data = item.context("Unable to get path of item, skipping")?;
        let item = item_data.path();

        if item.is_dir() {
            zip.add_directory(
                item.to_str()
                    .context("Error converting directory path to string")?,
                options,
            )
            .context("Unable to add directory to zip")?;

            continue;
        }

        zip.start_file(
            item.to_str()
                .context("Error converting file path to string")?,
            options,
        )
        .context("Unable to add file to zip")?;

        if pack_params.print_mode == PrintMode::Verbose {
            logger.info(format!(
                "Compressing {} into {}",
                item.to_str().unwrap(),
                tmp_name
            ));
        }

        let zip_writer = zip.by_ref();
        let mut file_reader = File::open(item)?;
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
        item_count,
        tmp_name,
        zip_duration.as_secs_f32()
    ));

    super::encrypt::stream_mode(&tmp_name, output, params, algorithm)?;

    super::erase::secure_erase(&tmp_name, 2)?; // cleanup our tmp file

    if pack_params.erase_source == EraseSourceDir::Erase {
        super::erase::secure_erase(input, 2)?;
    }

    logger.success(format!("Your output file is: {}", output));

    Ok(())
}
