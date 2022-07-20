use std::cell::RefCell;
use std::io::{BufReader, BufWriter, Cursor, Read, Seek, Write};

use dexios_core::header::{HashingAlgorithm, HeaderType};
use dexios_core::primitives::BLOCK_SIZE;
use dexios_core::protected::Protected;
use zip::write::FileOptions;

use crate::domain;

#[derive(Debug)]
pub enum Error {
    AddDirToArchive,
    AddFileToArchive,
    FinishArchive,
    ReadData,
    WriteData,
    Encrypt(domain::encrypt::Error),
    Overwrite(domain::overwrite::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;
        match self {
            AddDirToArchive => f.write_str("Unable to add directory to archive"),
            AddFileToArchive => f.write_str("Unable to add file to archive"),
            FinishArchive => f.write_str("Unable to finish archive"),
            ReadData => f.write_str("Unable to read data"),
            WriteData => f.write_str("Unable to write data"),
            Encrypt(inner) => write!(f, "Unable to encrypt archive: {}", inner),
            Overwrite(inner) => write!(f, "Unable to overwrite archive: {}", inner),
        }
    }
}

impl std::error::Error for Error {}

pub struct Request<'a, RW>
where
    RW: Read + Write + Seek,
{
    pub writer: &'a RefCell<RW>,
    pub compress_files: Vec<domain::storage::File<RW>>,
    pub compression_method: zip::CompressionMethod,
    pub header_writer: Option<&'a RefCell<RW>>,
    pub raw_key: Protected<Vec<u8>>,
    // TODO: don't use external types in logic
    pub header_type: HeaderType,
    pub hashing_algorithm: HashingAlgorithm,
}

pub fn execute<RW>(req: Request<RW>) -> Result<(), Error>
where
    RW: Read + Write + Seek,
{
    // 1. Create in memory zip archive.
    let mut zip_content = vec![];
    let file = Cursor::new(&mut zip_content);
    let mut zip_writer = zip::ZipWriter::new(BufWriter::new(file));

    let options = FileOptions::default()
        .compression_method(req.compression_method)
        .large_file(true)
        .unix_permissions(0o755);

    // 2. Add files to the archive.
    req.compress_files.into_iter().try_for_each(|f| {
        let file_path = f.path().to_str().ok_or(Error::ReadData)?;
        if f.is_dir() {
            zip_writer
                .add_directory(file_path, options)
                .map_err(|_| Error::AddDirToArchive)?;
        } else {
            zip_writer
                .start_file(file_path, options)
                .map_err(|_| Error::AddFileToArchive)?;

            let mut reader = f.try_reader().map_err(|_| Error::ReadData)?.borrow_mut();
            let mut buffer = [0u8; BLOCK_SIZE];
            loop {
                let read_count = reader.read(&mut buffer).map_err(|_| Error::ReadData)?;
                zip_writer
                    .write_all(&buffer[..read_count])
                    .map_err(|_| Error::WriteData)?;
                if read_count != BLOCK_SIZE {
                    break;
                }
            }
        }

        Ok(())
    })?;

    // 3. Close archive and switch writer to reader.
    let (zip_reader_capacity, zip_reader) = zip_writer
        .finish()
        .map_err(|_| Error::FinishArchive)?
        .into_inner()
        .map(|r| (r.get_ref().capacity(), RefCell::new(BufReader::new(r))))
        .map_err(|_| Error::FinishArchive)?;

    // 4. Encrypt zip archive
    let encrypt_res = domain::encrypt::execute(domain::encrypt::Request {
        reader: &zip_reader,
        writer: req.writer,
        header_writer: req.header_writer,
        raw_key: req.raw_key,
        header_type: req.header_type,
        hashing_algorithm: req.hashing_algorithm,
    })
    .map_err(Error::Encrypt);

    // 5. Finally overwrite zip archive with zeros.
    domain::overwrite::execute(domain::overwrite::Request {
        buf_capacity: zip_reader_capacity,
        writer: &RefCell::new(zip_reader.into_inner().into_inner()),
        passes: 2,
    })
    .map_err(Error::Overwrite)?;

    encrypt_res
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    use dexios_core::header::{HeaderType, HeaderVersion};
    use dexios_core::primitives::{Algorithm, Mode};

    use crate::domain::encrypt::tests::PASSWORD;
    use crate::domain::storage::{InMemoryStorage, Storage};

    #[test]
    fn should_pack_bar_directory() {
        let stor = InMemoryStorage::default();
        stor.add_hello_txt().unwrap();
        stor.add_bar_foo_folder_with_hidden().unwrap();

        let file = stor.read_file("bar/").unwrap();
        let compress_files = stor.read_dir(&file).unwrap();
        let output_file = stor.create_file("bar.zip.enc").unwrap();

        let req = Request {
            compress_files,
            compression_method: zip::CompressionMethod::Stored,
            writer: output_file.try_writer().unwrap(),
            header_writer: None,
            raw_key: Protected::new(PASSWORD.to_vec()),
            header_type: HeaderType {
                version: HeaderVersion::V5,
                algorithm: Algorithm::XChaCha20Poly1305,
                mode: Mode::StreamMode,
            },
            hashing_algorithm: HashingAlgorithm::Blake3Balloon(5),
        };

        match execute(req) {
            Ok(()) => {
                let reader = &mut *output_file.try_writer().unwrap().borrow_mut();
                reader.rewind().unwrap();

                let mut content = vec![];
                reader.read_to_end(&mut content).unwrap();

                assert_eq!(
                    content,
                    vec![
                        222, 5, 14, 1, 12, 1, 173, 240, 60, 45, 230, 243, 58, 160, 69, 50, 217,
                        192, 66, 223, 124, 190, 148, 91, 92, 129, 0, 0, 0, 0, 0, 0, 223, 181, 71,
                        240, 140, 106, 41, 36, 82, 150, 105, 215, 159, 108, 234, 246, 25, 19, 65,
                        206, 177, 146, 15, 174, 209, 129, 82, 2, 62, 76, 129, 34, 136, 189, 11, 98,
                        105, 54, 146, 71, 102, 166, 97, 177, 207, 62, 194, 132, 38, 87, 173, 240,
                        60, 45, 230, 243, 58, 160, 69, 50, 217, 192, 66, 223, 124, 190, 148, 91,
                        92, 129, 50, 126, 110, 254, 58, 206, 16, 183, 233, 128, 23, 223, 81, 30,
                        214, 132, 32, 104, 51, 119, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 22, 64, 6, 177, 49, 139, 218, 8, 121, 228, 19, 5, 8, 117, 33, 131,
                        131, 70, 76, 147, 108, 49, 191, 191, 127, 223, 77, 127, 248, 65, 201, 130,
                        166, 129, 236, 147, 142, 211, 160, 149, 191, 70, 7, 102, 124, 253, 12, 44,
                        172, 79, 236, 207, 68, 229, 37, 122, 249, 51, 18, 96, 29, 51, 240, 169,
                        137, 27, 175, 241, 44, 118, 35, 36, 117, 148, 118, 23, 165, 30, 224, 42,
                        173, 239, 51, 241, 118, 235, 83, 64, 125, 184, 202, 208, 18, 104, 240, 146,
                        139, 19, 217, 51, 232, 229, 191, 179, 178, 19, 216, 54, 84, 28, 67, 91,
                        255, 94, 55, 178, 135, 68, 48, 27, 111, 195, 39, 23, 64, 170, 3, 187, 114,
                        243, 200, 110, 13, 56, 94, 177, 249, 80, 157, 192, 40, 13, 145, 165, 246,
                        84, 94, 22, 64, 179, 103, 120, 222, 16, 54, 195, 86, 46, 174, 229, 49, 212,
                        18, 24, 95, 242, 38, 230, 133, 143, 66, 27, 69, 101, 183, 201, 238, 81,
                        114, 131, 123, 141, 123, 0, 227, 252, 64, 143, 50, 33, 46, 12, 48, 243,
                        114, 111, 210, 160, 99, 207, 116, 150, 102, 123, 136, 135, 189, 34, 0, 203,
                        249, 232, 91, 197, 23, 48, 35, 218, 106, 152, 111, 14, 64, 54, 18, 78, 18,
                        236, 82, 85, 237, 148, 8, 110, 43, 133, 33, 147, 201, 96, 125, 165, 108,
                        182, 161, 2, 138, 225, 195, 95, 40, 125, 93, 128, 202, 67, 25, 185, 37,
                        141, 78, 74, 1, 19, 160, 233, 35, 235, 226, 107, 121, 123, 236, 121, 126,
                        216, 110, 203, 184, 145, 150, 27, 136, 152, 9, 91, 195, 99, 181, 134, 158,
                        69, 154, 243, 97, 67, 203, 79, 234, 138, 240, 45, 155, 14, 160, 18, 214,
                        128, 27, 73, 48, 27, 86, 53, 215, 101, 142, 85, 110, 16, 121, 3, 119, 57,
                        102, 37, 52, 107, 94, 41, 23, 207, 183, 227, 160, 225, 158, 156, 114, 3,
                        207, 118, 217, 120, 62, 184, 244, 59, 20, 112, 126, 126, 221, 136, 228,
                        203, 18, 220, 172, 35, 154, 100, 219, 239, 132, 211, 238, 37, 242, 139,
                        218, 120, 112, 158, 75, 53, 172, 162, 136, 202, 94, 117, 152, 175, 205, 34,
                        198, 99, 49, 174, 187, 80, 151, 225, 169, 120, 192, 77, 61, 38, 2, 158, 45,
                        216, 78, 215, 134, 255, 7, 46, 144, 119, 60, 168, 202, 24, 239, 147, 122,
                        58, 48, 50, 178, 58, 148, 243, 242, 169, 238, 42, 78, 123, 37, 181, 17,
                        109, 175, 84, 6, 212, 122, 89, 60, 111, 248, 41, 226, 251, 176, 250, 213,
                        103, 85, 220, 71, 47, 212, 190, 76, 149, 167, 241, 212, 217, 131, 146, 34,
                        118, 218, 240, 246, 108, 34, 254, 172, 214, 100, 169, 240, 165, 131, 50,
                        80, 54, 254, 128, 94, 168, 233, 22, 39, 213, 46, 135, 62, 158, 235, 160,
                        130, 168, 42, 228, 113, 139, 158, 61, 191, 23, 230, 65, 238, 199, 210, 113,
                        213, 209, 196, 183, 138, 114, 64, 179, 189, 15, 139, 124, 227, 37, 149,
                        121, 13, 123, 201, 51, 61, 67, 220, 161, 13, 76, 176, 202, 28, 241, 105,
                        144, 10, 76, 124, 3, 46, 143, 133, 114, 167, 250, 199, 108, 141, 19, 111,
                        212, 231, 18, 70, 143, 221, 206, 22, 148, 73, 198, 5, 210, 18, 232, 78, 25,
                        223, 133, 245, 220, 161, 237, 197, 21, 5, 86, 212, 162, 237, 131, 116, 41,
                        241, 57, 24, 102, 126, 132, 135, 119, 226, 111, 2, 36, 10, 18, 28, 50, 138,
                        143, 213, 226, 229, 196, 162, 172, 24, 139, 250, 223, 231, 244, 26, 232,
                        94, 123, 59, 55, 123, 101, 203, 188, 73, 225, 95, 191, 244, 161, 170, 46,
                        242, 122, 34, 136, 126, 51, 191, 61, 120, 207, 212, 49, 229, 70, 152, 120,
                        92, 235, 187, 55, 189, 231, 126, 226, 215, 189, 78, 22, 166, 212, 223, 179,
                        205, 210, 141, 61, 210, 251, 10, 185, 20, 243, 147, 112, 160, 45, 11, 227,
                        216, 138, 63, 45, 88, 87, 84, 199, 9, 113, 207, 85, 217, 57, 194, 113, 48,
                        204, 239, 212, 155, 237, 158, 21, 204, 135, 151, 252, 28, 95, 87, 91, 169,
                        160, 236, 79, 81, 221, 65, 1, 215, 22, 203, 205, 195, 133, 29, 183, 194,
                        11, 154, 168, 110, 242, 19, 167, 195, 205, 68, 4, 151, 99, 196, 164, 13,
                        137, 140, 175, 134, 102, 47, 63, 0, 229, 73, 218, 226, 121, 230, 98, 168,
                        184, 246, 43, 170, 246, 90, 59, 193, 190, 122, 12, 254, 191, 72, 158
                    ]
                )
            }
            _ => unreachable!(),
        }
    }
}
