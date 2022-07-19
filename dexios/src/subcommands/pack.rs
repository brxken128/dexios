use std::sync::Arc;
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

use crate::domain::{self, storage::Storage};

use crate::{
    global::states::{DirectoryMode, EraseSourceDir, PrintMode},
    global::{
        states::Compression,
        structs::{CryptoParams, PackParams},
    },
};

pub struct Request<'a> {
    pub input_file: &'a str,
    pub output_file: &'a str,
    pub pack_params: PackParams,
    pub crypto_params: CryptoParams,
    pub algorithm: Algorithm,
}

// this first indexes the input directory
// once it has the total number of files/folders, it creates a temporary zip file
// it compresses all of the files into the temporary archive
// once compressed, it encrypts the zip file
// it erases the temporary archive afterwards, to stop any residual data from remaining
#[allow(clippy::too_many_lines)]
pub fn execute(req: Request) -> Result<()> {
    // TODO: It is necessary to raise it to a higher level
    let stor = Arc::new(domain::storage::FileStorage);

    let mut logger = Logger::new();

    let input_file = stor.read_file(req.input_file)?;

    let compress_files = if input_file.is_dir() {
        // TODO(pleshevskiy): use iterator instead of vec!
        stor.read_dir(&input_file)?
            .into_iter()
            .map(|pb| stor.read_file(pb))
            .collect::<Result<Vec<_>, _>>()?
    } else {
        vec![input_file]
    };

    domain::pack::execute(domain::pack::Request {
        compress_files,
        compression_method: zip::CompressionMethod::Stored,
    })?;

    // 1. Initialize walker
    let walker = if req.pack_params.dir_mode == DirectoryMode::Recursive {
        logger.info(format!("Traversing {} recursively", req.input_file));
        WalkDir::new(req.input_file)
    } else {
        logger.info(format!("Traversing {}", req.input_file));
        WalkDir::new(req.input_file).max_depth(1)
    };

    // 2. Skip failed dir entries
    let walker = walker
        .into_iter()
        .filter_map(|res| res.ok())
        .collect::<Vec<walkdir::DirEntry>>();

    // 3. create temp file
    let random_extension: String = Alphanumeric.sample_string(&mut rand::thread_rng(), 8);
    let tmp_name = format!("{}.{}", req.output_file, random_extension); // e.g. "output.kjHSD93l"

    let file = std::io::BufWriter::new(
        File::create(&tmp_name)
            .with_context(|| format!("Unable to create the output file: {}", req.output_file))?,
    );

    logger.info(format!("Creating and compressing files into {}", tmp_name));

    // 4. Pipe to zip writer
    let zip_start_time = Instant::now();

    let mut zip = zip::ZipWriter::new(file);

    // 5. Add options for zip file
    let options = match req.pack_params.compression {
        Compression::None => FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .large_file(true)
            .unix_permissions(0o755),
        Compression::Zstd => FileOptions::default()
            .compression_method(zip::CompressionMethod::Zstd)
            .large_file(true)
            .unix_permissions(0o755),
    };

    // 6. iterate all entries and zip them
    let item_count = walker.len();
    for dir_entry in walker {
        let entry_path = dir_entry.path();

        let item_str = entry_path
            .to_str()
            .context("Error converting directory path to string")?
            .replace('\\', "/");

        if entry_path.is_dir() {
            zip.add_directory(item_str, options)
                .context("Unable to add directory to zip")?;

            continue;
        }

        zip.start_file(item_str, options)
            .context("Unable to add file to zip")?;

        if req.pack_params.print_mode == PrintMode::Verbose {
            logger.info(format!(
                "Compressing {} into {}",
                entry_path.to_str().unwrap(),
                tmp_name
            ));
        }

        let zip_writer = zip.by_ref();
        let mut file_reader = File::open(entry_path)?;
        // stream read/write here
        let mut buffer = vec![0u8; BLOCK_SIZE].into_boxed_slice();

        loop {
            let read_count = file_reader.read(&mut buffer)?;
            zip_writer
                .write_all(&buffer[..read_count])
                .with_context(|| {
                    format!("Unable to write to the output file: {}", req.output_file)
                })?;
            if read_count != BLOCK_SIZE {
                break;
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

    // 7. Encrypt the compressed file
    // TODO: need to extract getting password from encrypt command.
    super::encrypt::stream_mode(
        &tmp_name,
        req.output_file,
        &req.crypto_params,
        req.algorithm,
    )
    .or_else(|err| super::erase::secure_erase(&tmp_name, 2).and(Err(err)))?;

    // 8. Erase files
    super::erase::secure_erase(&tmp_name, 2)?; // cleanup our tmp file

    if req.pack_params.erase_source == EraseSourceDir::Erase {
        super::erase::secure_erase(req.input_file, 2)?;
    }

    logger.success(format!("Your output file is: {}", req.output_file));

    Ok(())
}
