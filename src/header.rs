use crate::{
    global::enums::{Algorithm, BenchMode, CipherMode, HeaderVersion, OutputFile, SkipMode},
    global::structs::{Header, HeaderType},
    global::SALT_LEN,
    prompt::{get_answer, overwrite_check},
};
use anyhow::{Context, Result};
use blake3::Hasher;
use paris::Logger;
use std::{fs::File, io::Write};
use std::{fs::OpenOptions, io::Read, process::exit};

// this calculates how long the nonce will be, based on the provided input
fn calc_nonce_len(header_info: &HeaderType) -> usize {
    let mut nonce_len = match header_info.algorithm {
        Algorithm::XChaCha20Poly1305 => 24,
        Algorithm::Aes256Gcm => 12,
        Algorithm::DeoxysII256 => 15,
    };

    if header_info.cipher_mode == CipherMode::StreamMode {
        nonce_len -= 4; // the last 4 bytes are dynamic in stream mode
    }

    nonce_len
}

// this takes information about the header, and serializes it into raw bytes
// this is the inverse of the deserialize function
fn serialize(header_info: &HeaderType) -> ([u8; 2], [u8; 2], [u8; 2]) {
    let version_info = match header_info.header_version {
        HeaderVersion::V1 => {
            let info: [u8; 2] = [0xDE, 0x01];
            info
        }
    };
    let algorithm_info = match header_info.algorithm {
        Algorithm::XChaCha20Poly1305 => {
            let info: [u8; 2] = [0x0E, 0x01];
            info
        }
        Algorithm::Aes256Gcm => {
            let info: [u8; 2] = [0x0E, 0x02];
            info
        }
        Algorithm::DeoxysII256 => {
            let info: [u8; 2] = [0x0E, 0x03];
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

// this writes a header to a file
// it handles padding and serialising the specific information
// it ensures the buffer is left at 64 bytes, so other functions can write the data without further hassle
pub fn write_to_file(file: &mut OutputFile, header: &Header) -> Result<()> {
    let nonce_len = calc_nonce_len(&header.header_type);

    match &header.header_type.header_version {
        HeaderVersion::V1 => {
            let padding = vec![0u8; 26 - nonce_len];
            let (version_info, algorithm_info, mode_info) = serialize(&header.header_type);

            file.write_all(&version_info)
                .context("Unable to write version to header")?;
            file.write_all(&algorithm_info)
                .context("Unable to write algorithm to header")?;
            file.write_all(&mode_info)
                .context("Unable to write encryption mode to header")?; // 6 bytes total
            file.write_all(&header.salt)
                .context("Unable to write salt to header")?; // 22 bytes total
            file.write_all(&[0; 16])
                .context("Unable to write empty bytes to header")?; // 38 bytes total (26 remaining)
            file.write_all(&header.nonce)
                .context("Unable to write nonce to header")?; // (26 - nonce_len remaining)
            file.write_all(&padding)
                .context("Unable to write final padding to header")?; // this has reached the 64 bytes
        }
    }

    Ok(())
}

// this hashes a header with the salt, nonce, and info provided
pub fn hash(hasher: &mut Hasher, header: &Header) {
    match &header.header_type.header_version {
        HeaderVersion::V1 => {
            let nonce_len = calc_nonce_len(&header.header_type);
            let padding = vec![0u8; 26 - nonce_len];
            let (version_info, algorithm_info, mode_info) = serialize(&header.header_type);

            hasher.update(&version_info);
            hasher.update(&algorithm_info);
            hasher.update(&mode_info);
            hasher.update(&header.salt);
            hasher.update(&[0; 16]);
            hasher.update(&header.nonce);
            hasher.update(&padding);
        }
    }
}

// this is used for converting raw bytes from the header to enums that dexios can understand
// this involves the header version, encryption algorithm/mode, and possibly more in the future
fn deserialize(
    version_info: [u8; 2],
    algorithm_info: [u8; 2],
    mode_info: [u8; 2],
) -> Result<HeaderType> {
    let header_version = match version_info {
        [0xDE, 0x01] => HeaderVersion::V1,
        _ => return Err(anyhow::anyhow!("Error getting cipher mode from header")),
    };

    let algorithm = match algorithm_info {
        [0x0E, 0x01] => Algorithm::XChaCha20Poly1305,
        [0x0E, 0x02] => Algorithm::Aes256Gcm,
        [0x0E, 0x03] => Algorithm::DeoxysII256,
        _ => return Err(anyhow::anyhow!("Error getting encryption mode from header")),
    };

    let cipher_mode = match mode_info {
        [0x0C, 0x01] => CipherMode::StreamMode,
        [0x0C, 0x02] => CipherMode::MemoryMode,
        _ => return Err(anyhow::anyhow!("Error getting cipher mode from header")),
    };

    Ok(HeaderType {
        header_version,
        cipher_mode,
        algorithm,
    })
}

// this takes an input file, and gets all of the data necessary from the header of the file
// it ensures that the buffer starts at 64 bytes, so that other functions can just read encrypted data immediately
pub fn read_from_file(file: &mut File) -> Result<Header> {
    let mut version_info = [0u8; 2];
    let mut algorithm_info = [0u8; 2];
    let mut mode_info = [0u8; 2];
    let mut salt = [0u8; SALT_LEN];

    file.read_exact(&mut version_info)
        .context("Unable to read version from header")?;
    file.read_exact(&mut algorithm_info)
        .context("Unable to read algorithm from header")?;
    file.read_exact(&mut mode_info)
        .context("Unable to read encryption mode from header")?;

    let header_info = deserialize(version_info, algorithm_info, mode_info)?;
    match header_info.header_version {
        HeaderVersion::V1 => {
            let nonce_len = calc_nonce_len(&header_info);
            let mut nonce = vec![0u8; nonce_len];

            file.read_exact(&mut salt)
                .context("Unable to read salt from header")?;
            file.read_exact(&mut [0; 16])
                .context("Unable to empty bytes from header")?; // read and subsequently discard the next 16 bytes
            file.read_exact(&mut nonce)
                .context("Unable to read nonce from header")?;
            file.read_exact(&mut vec![0u8; 26 - nonce_len])
                .context("Unable to read final padding from header")?; // read and discard the final padding

            Ok(Header {
                header_type: header_info,
                nonce,
                salt,
            })
        }
    }
}

// this function dumps the first 64 bytes of
// the input file into the output file
// it's used for extracting an encrypted file's header for backups and such
pub fn dump(input: &str, output: &str, skip: SkipMode) -> Result<()> {
    let mut logger = Logger::new();
    logger.warn("THIS FEATURE IS FOR ADVANCED USERS ONLY AND MAY RESULT IN A LOSS OF DATA - PROCEED WITH CAUTION");

    let mut header = [0u8; 64];

    let mut file =
        File::open(input).with_context(|| format!("Unable to open input file: {}", input))?;
    file.read_exact(&mut header)
        .with_context(|| format!("Unable to read header from file: {}", input))?;

    if !overwrite_check(output, skip, BenchMode::WriteToFilesystem)? {
        std::process::exit(0);
    }

    let mut output_file =
        File::create(output).with_context(|| format!("Unable to open output file: {}", output))?;
    output_file
        .write_all(&header)
        .with_context(|| format!("Unable to write header to output file: {}", output))?;

    logger.success(format!("Header dumped to {} successfully.", output));
    Ok(())
}

// this function reads the first 64 bytes (header) from the input file
// and then overwrites the first 64 bytes of the output file with it
// this can be used for restoring a dumped header to a file that had it's header stripped
pub fn restore(input: &str, output: &str, skip: SkipMode) -> Result<()> {
    let mut logger = Logger::new();
    logger.warn("THIS FEATURE IS FOR ADVANCED USERS ONLY AND MAY RESULT IN A LOSS OF DATA - PROCEED WITH CAUTION");
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
        .read_exact(&mut header)
        .with_context(|| format!("Unable to read header from file: {}", input))?;

    if header[..1] != [0xDE] {
        let prompt =
            "This doesn't seem to be a Dexios header file, are you sure you'd like to continue?";
        if !get_answer(prompt, false, skip == SkipMode::HidePrompts)? {
            exit(0);
        }
    }

    let mut output_file = OpenOptions::new()
        .write(true)
        .open(output)
        .with_context(|| format!("Unable to open output file: {}", output))?;

    output_file
        .write_all(&header)
        .with_context(|| format!("Unable to write header to file: {}", output))?;

    logger.success(format!(
        "Header restored to {} from {} successfully.",
        output, input
    ));
    Ok(())
}

// this wipes the first 64 bytes (header) from the provided file
// it can be useful for storing the header separate from the file, to make an attacker's life that little bit harder
pub fn strip(input: &str, skip: SkipMode) -> Result<()> {
    let mut logger = Logger::new();
    logger.warn("THIS FEATURE IS FOR ADVANCED USERS ONLY AND MAY RESULT IN A LOSS OF DATA - PROCEED WITH CAUTION");

    let prompt = format!("Are you sure you'd like to wipe the header for {}?", input);
    if !get_answer(&prompt, false, skip == SkipMode::HidePrompts)? {
        exit(0);
    }

    let prompt = "This can be destructive! Make sure you dumped the header first. Would you like to continue?";
    if !get_answer(prompt, false, skip == SkipMode::HidePrompts)? {
        exit(0);
    }

    let buffer = vec![0u8; 64];

    let mut file = OpenOptions::new()
        .write(true)
        .open(input)
        .with_context(|| format!("Unable to open input file: {}", input))?;

    file.write_all(&buffer)
        .with_context(|| format!("Unable to wipe header for file: {}", input))?;

    logger.success(format!("Header stripped from {} successfully.", input));
    Ok(())
}
