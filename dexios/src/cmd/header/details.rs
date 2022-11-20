use std::{fs::File, path::PathBuf};

use anyhow::{Context, Result};
use core::header::HashingAlgorithm;
use core::header::{Header, HeaderVersion};
use domain::utils::hex_encode;

#[derive(clap::Args)]
pub struct Args {
    #[clap(help = "The encrypted header file")]
    input: PathBuf,
}

pub fn details(args: Args) -> Result<()> {
    let mut input_file = File::open(args.input).with_context(|| {
        format!(
            "Unable to open input file: {}",
            args.input.to_str().unwrap()
        )
    })?;

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
