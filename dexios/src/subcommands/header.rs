use std::{
    cell::RefCell,
    fs::{File, OpenOptions},
};

use crate::cli::prompt::overwrite_check;
use crate::global::states::ForceMode;
use anyhow::{Context, Result};
use dcore::header::HashingAlgorithm;
use dcore::header::{Header, HeaderVersion};
use ddomain::storage::Storage;
use ddomain::utils::hex_encode;

pub fn details(input: &str) -> Result<()> {
    let mut input_file =
        File::open(input).with_context(|| format!("Unable to open input file: {}", input))?;

    let header_result = Header::deserialize(&mut input_file);

    if header_result.is_err() {
        return Err(anyhow::anyhow!(
            "This does not seem like a valid Dexios header"
        ));
    }

    let (header, aad) = header_result.unwrap();

    println!("Header version: {}", header.header_type.version);
    println!("Encryption algorithm: {}", header.header_type.algorithm);
    println!("Encryption mode: {}", header.header_type.mode);
    println!("Encryption nonce: {} (hex)", hex_encode(&header.nonce));
    println!("AAD: {} (hex)", hex_encode(&aad));

    match header.header_type.version {
        HeaderVersion::V1 => {
            println!("Salt: {} (hex)", hex_encode(&header.salt.unwrap()));
            println!("Hashing Algorithm: {}", HashingAlgorithm::Argon2id(1));
        }
        HeaderVersion::V2 => {
            println!("Salt: {} (hex)", hex_encode(&header.salt.unwrap()));
            println!("Hashing Algorithm: {}", HashingAlgorithm::Argon2id(2));
        }
        HeaderVersion::V3 => {
            println!("Salt: {} (hex)", hex_encode(&header.salt.unwrap()));
            println!("Hashing Algorithm: {}", HashingAlgorithm::Argon2id(3));
        }
        HeaderVersion::V4 | HeaderVersion::V5 => {
            for (i, keyslot) in header.keyslots.unwrap().iter().enumerate() {
                println!("Keyslot {}:", i);
                println!("  Hashing Algorithm: {}", keyslot.hash_algorithm);
                println!("  Salt: {} (hex)", hex_encode(&keyslot.salt));
                println!(
                    "  Master Key: {} (hex, encrypted)",
                    hex_encode(&keyslot.encrypted_key)
                );
                println!("  Master Key Nonce: {} (hex)", hex_encode(&keyslot.nonce));
            }
        }
    }

    Ok(())
}

// this function reads the header fromthe input file and writes it to the output file
// it's used for extracting an encrypted file's header for backups and such
// it implements a check to ensure the header is valid
pub fn dump(input: &str, output: &str, force: ForceMode) -> Result<()> {
    let stor = std::sync::Arc::new(ddomain::storage::FileStorage);
    let input_file = stor.read_file(input)?;

    if !overwrite_check(output, force)? {
        std::process::exit(0);
    }

    let output_file = stor
        .create_file(output)
        .or_else(|_| stor.write_file(output))?;

    let req = ddomain::header::dump::Request {
        reader: input_file.try_reader()?,
        writer: output_file.try_writer()?,
    };

    ddomain::header::dump::execute(req)?;

    stor.flush_file(&output_file)?;

    Ok(())
}

// this function reads the header from the input file
// it then writes the header to the start of the ouput file
// this can be used for restoring a dumped header to a file that had it's header stripped
// this does not work for files encrypted *with* a detached header
// it implements a check to ensure the header is valid before restoring to a file
pub fn restore(input: &str, output: &str) -> Result<()> {
    let stor = std::sync::Arc::new(ddomain::storage::FileStorage);

    let input_file = stor.read_file(input)?;

    let output_file = RefCell::new(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(output)
            .with_context(|| format!("Unable to open output file: {}", output))?,
    );

    let req = ddomain::header::restore::Request {
        reader: input_file.try_reader()?,
        writer: &output_file,
    };

    ddomain::header::restore::execute(req)?;

    Ok(())
}

// this wipes the length of the header from the provided file
// the header must be intact for this to work, as the length varies between the versions
// it can be useful for storing the header separate from the file, to make an attacker's life that little bit harder
// it implements a check to ensure the header is valid before stripping
pub fn strip(input: &str) -> Result<()> {
    let input_file = RefCell::new(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(input)
            .with_context(|| format!("Unable to open input file: {}", input))?,
    );

    let req = ddomain::header::strip::Request {
        handle: &input_file,
    };

    ddomain::header::strip::execute(req)?;

    Ok(())
}
