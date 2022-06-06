use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    process::exit,
};

use anyhow::{Context, Result};
use paris::Logger;

use crate::global::states::{BenchMode, SkipMode};

use super::prompt::{get_answer, overwrite_check};

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
