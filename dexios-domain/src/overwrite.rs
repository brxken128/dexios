use rand::RngCore;
use std::cell::RefCell;
use std::fmt;
use std::io::{Seek, Write};

const BLOCK_SIZE: usize = 512;

#[derive(Debug)]
pub enum Error {
    ResetCursorPosition,
    OverwriteWithRandomBytes,
    OverwriteWithZeros,
    FlushFile,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ResetCursorPosition => f.write_str("Unable to reset cursor position"),
            Error::OverwriteWithRandomBytes => f.write_str("Unable to overwrite with random bytes"),
            Error::OverwriteWithZeros => f.write_str("Unable to overwrite with zeros"),
            Error::FlushFile => f.write_str("Unable to flush"),
        }
    }
}

impl std::error::Error for Error {}

pub struct Request<'a, W: Write + Seek> {
    pub writer: &'a RefCell<W>,
    pub buf_capacity: usize,
    pub passes: i32,
}

pub fn execute<W: Write + Seek>(req: Request<W>) -> Result<(), Error> {
    let mut writer = req.writer.borrow_mut();
    for _ in 0..req.passes {
        writer.rewind().map_err(|_| Error::ResetCursorPosition)?;

        let mut blocks = vec![BLOCK_SIZE].repeat(req.buf_capacity / BLOCK_SIZE);
        blocks.push(req.buf_capacity % BLOCK_SIZE);

        for block_size in blocks.into_iter().take_while(|bs| *bs > 0) {
            let mut block_buf = Vec::with_capacity(block_size);
            rand::thread_rng().fill_bytes(&mut block_buf);
            writer
                .write_all(&block_buf)
                .map_err(|_| Error::OverwriteWithRandomBytes)?;
        }

        writer.flush().map_err(|_| Error::FlushFile)?;
    }

    writer.rewind().map_err(|_| Error::ResetCursorPosition)?;
    writer
        .write_all(&[0].repeat(req.buf_capacity))
        .map_err(|_| Error::OverwriteWithZeros)?;
    writer.flush().map_err(|_| Error::FlushFile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn make_test(capacity: usize, passes: i32) {
        let mut buf = Vec::with_capacity(capacity);
        rand::thread_rng().fill_bytes(&mut buf);

        let writer = Cursor::new(&mut buf);

        let req = Request {
            writer: &RefCell::new(writer),
            buf_capacity: capacity,
            passes,
        };

        match execute(req) {
            Ok(_) => {
                assert_eq!(buf.len(), capacity);
                assert_eq!(buf, vec![0].repeat(capacity));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_overwrite_empty_content() {
        make_test(0, 1);
    }

    #[test]
    fn should_overwrite_small_content() {
        make_test(100, 1);
    }

    #[test]
    fn should_overwrite_perfectly_divisible_content() {
        make_test(BLOCK_SIZE, 1);
    }

    #[test]
    fn should_overwrite_not_perfectly_divisible_content() {
        make_test(515, 1);
    }

    #[test]
    fn should_overwrite_large_content() {
        make_test(BLOCK_SIZE * 100, 1);
    }

    #[test]
    fn should_erase_fill_random_bytes_one_hundred_times() {
        make_test(515, 100);
    }

    #[test]
    fn should_erase_fill_random_bytes_zero_times() {
        make_test(515, 0);
    }
}
