use dexios_core::primitives::BLOCK_SIZE;
use std::fmt;
use std::{
    cell::RefCell,
    io::{Read, Seek},
};

#[derive(Debug)]
pub enum Error {
    ResetCursorPosition,
    ReadData,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;
        match self {
            ResetCursorPosition => f.write_str("Unable to reset cursor position"),
            ReadData => f.write_str("Unable to read data"),
        }
    }
}

impl std::error::Error for Error {}

pub struct Request<R: Read + Seek> {
    pub reader: RefCell<R>,
}

pub fn execute<R: Read + Seek>(req: Request<R>) -> Result<String, Error> {
    req.reader
        .borrow_mut()
        .rewind()
        .map_err(|_| Error::ResetCursorPosition)?;

    // TODO: move out blake3 hasher to input parameters
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; BLOCK_SIZE];

    loop {
        let read_count = req
            .reader
            .borrow_mut()
            .read(&mut buffer)
            .map_err(|_| Error::ReadData)?;
        hasher.update(&buffer[..read_count]);
        if read_count != BLOCK_SIZE {
            break;
        }
    }

    Ok(hasher.finalize().to_hex().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use std::io::Cursor;

    #[test]
    fn should_hash_string() {
        let text = "Hello world";
        let mut bytes = text.as_bytes();
        let reader = Cursor::new(&mut bytes);

        let req = Request {
            reader: RefCell::new(reader),
        };

        match execute(req) {
            Err(_) => unreachable!(),
            Ok(hash) => {
                assert_eq!(hash, blake3::hash(text.as_bytes()).to_hex().to_string());
            }
        }
    }

    #[test]
    fn should_hash_big_string() {
        let capacity = (BLOCK_SIZE as f32 * 1.5) as usize;
        let mut buf = Vec::with_capacity(capacity);
        rand::thread_rng().fill_bytes(&mut buf);

        let orig_buf = buf.clone();
        let reader = Cursor::new(&mut buf);

        let req = Request {
            reader: RefCell::new(reader),
        };

        match execute(req) {
            Err(_) => unreachable!(),
            Ok(hash) => {
                assert_eq!(hash, blake3::hash(&orig_buf).to_hex().to_string());
            }
        }
    }
}
