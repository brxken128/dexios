use crate::{
    global::parameters::{
        Algorithm, BenchMode, CipherMode, DexiosVersion, HeaderData, HeaderType, OutputFile,
        SkipMode,
    },
    global::SALT_LEN,
    prompt::{get_answer, overwrite_check},
};
use anyhow::{Context, Result};
use blake3::Hasher;
use std::{fs::File, io::Write};
use std::{fs::OpenOptions, io::Read, process::exit};

fn calc_nonce_len(header_info: &HeaderType) -> usize {
    let mut nonce_len = match header_info.algorithm {
        Algorithm::XChaCha20Poly1305 => 24,
        Algorithm::AesGcm => 12,
    };

    if header_info.cipher_mode == CipherMode::StreamMode {
        nonce_len -= 4; // the last 4 bytes are dynamic in stream mode
    }

    nonce_len
}

fn serialise(header_info: &HeaderType) -> ([u8; 2], [u8; 2], [u8; 2]) {
    let version_info = match header_info.dexios_version {
        DexiosVersion::V8 => {
            let info: [u8; 2] = [0xDE, 0x08];
            info
        }
    };
    let algorithm_info = match header_info.algorithm {
        Algorithm::XChaCha20Poly1305 => {
            let info: [u8; 2] = [0x0E, 0x01];
            info
        }
        Algorithm::AesGcm => {
            let info: [u8; 2] = [0x0E, 0x02];
            info
        }
    };

    let mode_info = match header_info.cipher_mode {
        CipherMode::StreamMode => {
            let info: [u8; 2] = [0x0C, 0x01];
            info
        }
        CipherMode::MemoryMode => {
            let info: [u8; 2] = [0x0C, 0x02];
            info
        }
    };

    (version_info, algorithm_info, mode_info)
}

pub fn write_to_file(
    file: &mut OutputFile,
    salt: &[u8; SALT_LEN],
    nonce: &[u8],
    header_info: &HeaderType,
) -> Result<()> {
    let nonce_len = calc_nonce_len(header_info);

    match header_info.dexios_version {
        DexiosVersion::V8 => {
            let padding = vec![0u8; 26 - nonce_len];
            let (version_info, algorithm_info, mode_info) = serialise(header_info);

            file.write_all(&version_info).context("Unable to write version to header")?;
            file.write_all(&algorithm_info).context("Unable to write algorithm to header")?;
            file.write_all(&mode_info).context("Unable to write encryption mode to header")?; // 6 bytes total
            file.write_all(salt).context("Unable to write salt to header")?; // 22 bytes total
            file.write_all(&[0; 16]).context("Unable to write empty bytes to header")?; // 38 bytes total (26 remaining)
            file.write_all(nonce).context("Unable to write nonce to header")?; // (26 - nonce_len remaining)
            file.write_all(&padding).context("Unable to write final padding to header")?; // this has reached the 64 bytes
        }
    }

    Ok(())
}

pub fn hash(hasher: &mut Hasher, salt: &[u8; SALT_LEN], nonce: &[u8], header_info: &HeaderType) {
    match header_info.dexios_version {
        DexiosVersion::V8 => {
            let nonce_len = calc_nonce_len(header_info);
            let padding = vec![0u8; 26 - nonce_len];
            let (version_info, algorithm_info, mode_info) = serialise(header_info);

            hasher.update(&version_info);
            hasher.update(&algorithm_info);
            hasher.update(&mode_info);
            hasher.update(salt);
            hasher.update(&[0; 16]);
            hasher.update(nonce);
            hasher.update(&padding);
        }
    }
}

fn deserialise(
    version_info: [u8; 2],
    algorithm_info: [u8; 2],
    mode_info: [u8; 2],
) -> Result<HeaderType> {
    let dexios_version = match version_info {
        [0xDE, 0x08] => DexiosVersion::V8,
        _ => return Err(anyhow::anyhow!("Error getting cipher mode from header")),
    };

    let algorithm = match algorithm_info {
        [0x0E, 0x01] => Algorithm::XChaCha20Poly1305,
        [0x0E, 0x02] => Algorithm::AesGcm,
        _ => return Err(anyhow::anyhow!("Error getting encryption mode from header")),
    };

    let cipher_mode = match mode_info {
        [0x0C, 0x01] => CipherMode::StreamMode,
        [0x0C, 0x02] => CipherMode::MemoryMode,
        _ => return Err(anyhow::anyhow!("Error getting cipher mode from header")),
    };

    Ok(HeaderType {
        dexios_version,
        cipher_mode,
        algorithm,
    })
}

pub fn read_from_file(file: &mut File) -> Result<HeaderData> {
    let mut version_info = [0u8; 2];
    let mut algorithm_info = [0u8; 2];
    let mut mode_info = [0u8; 2];
    let mut salt = [0u8; SALT_LEN];

    file.read_exact(&mut version_info).context("Unable to read version from header")?;
    file.read_exact(&mut algorithm_info).context("Unable to read algorithm from header")?;
    file.read_exact(&mut mode_info).context("Unable to read encryption mode from header")?;

    let header_info = deserialise(version_info, algorithm_info, mode_info)?;
    match header_info.dexios_version {
        DexiosVersion::V8 => {
            let nonce_len = calc_nonce_len(&header_info);
            let mut nonce = vec![0u8; nonce_len];

            file.read_exact(&mut salt).context("Unable to read salt from header")?;
            file.read_exact(&mut [0; 16]).context("Unable to empty bytes from header")?; // read and subsequently discard the next 16 bytes
            file.read_exact(&mut nonce).context("Unable to read nonce from header")?;
            file.read_exact(&mut vec![0u8; 26 - nonce_len]).context("Unable to read final padding from header")?; // read and discard the final padding

            Ok(HeaderData {
                header_type: header_info,
                nonce,
                salt,
            })
        }
    }
}

pub fn dump(input: &str, output: &str, skip: SkipMode) -> Result<()> {
    println!("THIS FEATURE IS FOR ADVANCED USERS ONLY AND MAY RESULT IN A LOSS OF DATA - PROCEED WITH CAUTION");

    let mut header = [0u8; 64];

    let mut file =
        File::open(input).with_context(|| format!("Unable to open input file: {}", input))?;
    file.read_exact(&mut header).with_context(|| format!("Unable to read header from file: {}", input))?;

    if !overwrite_check(output, skip, BenchMode::WriteToFilesystem)? {
        std::process::exit(0);
    }

    let mut output_file =
        File::create(output).with_context(|| format!("Unable to open output file: {}", output))?;
    output_file
        .write_all(&header)
        .with_context(|| format!("Unable to write header to output file: {}", output))?;

    println!("Header dumped to {} successfully.", output);
    Ok(())
}

pub fn restore(input: &str, output: &str, skip: SkipMode) -> Result<()> {
    println!("THIS FEATURE IS FOR ADVANCED USERS ONLY AND MAY RESULT IN A LOSS OF DATA - PROCEED WITH CAUTION");
    let prompt = format!(
        "Are you sure you'd like to restore the header in {} to {}?",
        input, output
    );
    if !get_answer(&prompt, false, skip == SkipMode::HidePrompts)? {
        exit(0);
    }

    let mut header = vec![0u8; 64];
    let mut input_file =
        File::open(input).with_context(|| format!("Unable to open header file: {}", input))?;
    input_file
        .read(&mut header)
        .with_context(|| format!("Unable to read header from file: {}", input))?;

    let mut output_file = OpenOptions::new()
        .write(true)
        .open(output)
        .with_context(|| format!("Unable to open output file: {}", output))?;

    output_file
        .write_all(&header)
        .with_context(|| format!("Unable to write header to file: {}", output))?;

    println!("Header restored to {} from {} successfully.", output, input);
    Ok(())
}

pub fn strip(input: &str, skip: SkipMode) -> Result<()> {
    println!("THIS FEATURE IS FOR ADVANCED USERS ONLY AND MAY RESULT IN A LOSS OF DATA - PROCEED WITH CAUTION");
    let prompt = format!("Are you sure you'd like to wipe the header for {}?", input);
    if !get_answer(&prompt, false, skip == SkipMode::HidePrompts)? {
        exit(0);
    }

    let buffer = vec![0u8; 64];

    let mut file = OpenOptions::new()
        .write(true)
        .open(input)
        .with_context(|| format!("Unable to open input file: {}", input))?;

    file.write_all(&buffer)
        .with_context(|| format!("Unable to wipe header for file: {}", input))?;

    println!("Header stripped from {} successfully.", input);
    Ok(())
}
