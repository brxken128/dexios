//! This module contains all Dexios header-related functions, such as dumping the header, restoring a dumped header, or stripping it entirely.

pub mod dump;
pub mod restore;
pub mod strip;

#[derive(Debug)]
pub enum Error {
    UnsupportedRestore,
    InvalidFile,
    Write,
    Read,
    HeaderSizeParse,
    Rewind,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::{HeaderSizeParse, InvalidFile, Read, Rewind, UnsupportedRestore, Write};
        match self {
            UnsupportedRestore => f.write_str("The provided request is unsupported with this file. It maybe isn't an encrypted file, or it was encrypted in detached mode."),
            InvalidFile => f.write_str("The file does not contain a valid Dexios header."),
            Write => f.write_str("Unable to write the data."),
            Read => f.write_str("Unable to read the data."),
            Rewind => f.write_str("Unable to rewind the stream."),
            HeaderSizeParse => f.write_str("Unable to parse the size of the header."),
        }
    }
}

impl std::error::Error for Error {}
