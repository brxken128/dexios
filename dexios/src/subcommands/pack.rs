use std::path::PathBuf;
use std::process::exit;
use std::sync::Arc;

use anyhow::Result;
use core::header::{HeaderType, HEADER_VERSION};
use core::primitives::{Algorithm, Mode};

use crate::global::states::{HashMode, HeaderLocation, PasswordState};
use crate::{
    global::states::EraseSourceDir,
    global::{
        states::Compression,
        structs::{CryptoParams, PackParams},
    },
};
use domain::storage::Storage;

use crate::cli::prompt::overwrite_check;

pub struct Request<'a> {
    pub input_file: &'a Vec<String>,
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
pub fn execute(req: &Request) -> Result<()> {
    // TODO: It is necessary to raise it to a higher level
    let stor = Arc::new(domain::storage::FileStorage);

    // 1. validate and prepare options
    if req.input_file.iter().any(|f| f == req.output_file) {
        return Err(anyhow::anyhow!(
            "Input and output files cannot have the same name."
        ));
    }

    if req.input_file.iter().any(|f| PathBuf::from(f).is_file()) {
        return Err(anyhow::anyhow!("Input path cannot be a file."));
    }

    if !overwrite_check(req.output_file, req.crypto_params.force)? {
        exit(0);
    }

    let input_files = req
        .input_file
        .iter()
        .map(|file_name| stor.read_file(file_name))
        .collect::<Result<Vec<_>, _>>()?;
    let raw_key = req.crypto_params.key.get_secret(&PasswordState::Validate)?;
    let output_file = stor
        .create_file(req.output_file)
        .or_else(|_| stor.write_file(req.output_file))?;

    let header_file = match &req.crypto_params.header_location {
        HeaderLocation::Embedded => None,
        HeaderLocation::Detached(path) => {
            if !overwrite_check(path, req.crypto_params.force)? {
                exit(0);
            }

            Some(stor.create_file(path).or_else(|_| stor.write_file(path))?)
        }
    };

    let compress_files = input_files
        .into_iter()
        .flat_map(|file| {
            if file.is_dir() {
                // TODO(pleshevskiy): use iterator instead of vec!
                match stor.read_dir(&file) {
                    Ok(files) => files.into_iter().map(Ok).collect(),
                    Err(err) => vec![Err(err)],
                }
            } else {
                vec![Ok(file)]
            }
        })
        .collect::<Result<Vec<_>, _>>()?;

    let compression_method = match req.pack_params.compression {
        Compression::None => zip::CompressionMethod::Stored,
        Compression::Zstd => zip::CompressionMethod::Zstd,
    };

    // 2. compress and encrypt files
    domain::pack::execute(
        stor.clone(),
        domain::pack::Request {
            compress_files,
            compression_method,
            writer: output_file.try_writer()?,
            header_writer: header_file.as_ref().and_then(|f| f.try_writer().ok()),
            raw_key,
            header_type: HeaderType {
                version: HEADER_VERSION,
                mode: Mode::StreamMode,
                algorithm: req.algorithm,
            },
            hashing_algorithm: req.crypto_params.hashing_algorithm,
        },
    )?;

    // 3. flush result
    if let Some(header_file) = header_file {
        stor.flush_file(&header_file)?;
    }
    stor.flush_file(&output_file)?;

    if req.crypto_params.hash_mode == HashMode::CalculateHash {
        super::hashing::hash_stream(&[req.output_file.to_string()])?;
    }

    if req.pack_params.erase_source == EraseSourceDir::Erase {
        req.input_file.iter().try_for_each(|file_name| {
            super::erase::secure_erase(file_name, 1, req.crypto_params.force)
        })?;
    }

    Ok(())
}
