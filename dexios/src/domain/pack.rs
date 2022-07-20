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
        let mut compress_files = stor.read_dir(&file).unwrap();
        compress_files.sort_by(|a, b| a.path().cmp(b.path()));

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
                        131, 70, 76, 147, 108, 49, 191, 191, 127, 223, 64, 127, 248, 65, 201, 130,
                        166, 129, 195, 245, 241, 188, 143, 148, 191, 86, 7, 102, 124, 253, 12, 44,
                        172, 79, 236, 207, 68, 229, 117, 49, 250, 55, 6, 48, 86, 48, 244, 189, 137,
                        27, 142, 241, 44, 118, 35, 5, 138, 237, 47, 248, 108, 30, 224, 42, 91, 16,
                        216, 14, 235, 132, 33, 123, 83, 188, 196, 205, 18, 71, 152, 231, 231, 127,
                        182, 29, 156, 157, 203, 178, 178, 3, 216, 51, 84, 28, 67, 91, 255, 14, 124,
                        180, 131, 80, 48, 27, 111, 195, 39, 127, 37, 231, 111, 82, 132, 168, 253,
                        149, 230, 199, 161, 78, 6, 175, 98, 210, 9, 25, 145, 199, 151, 38, 142,
                        199, 217, 35, 247, 168, 73, 138, 94, 175, 45, 0, 184, 252, 55, 250, 19, 8,
                        79, 247, 38, 230, 133, 143, 66, 27, 69, 96, 183, 201, 238, 81, 114, 131,
                        123, 229, 78, 39, 140, 151, 4, 196, 49, 37, 58, 12, 48, 243, 83, 111, 84,
                        6, 82, 249, 200, 120, 238, 190, 136, 135, 189, 34, 237, 52, 18, 23, 43,
                        164, 113, 31, 111, 221, 119, 216, 110, 0, 74, 53, 81, 86, 83, 234, 70, 69,
                        194, 224, 96, 26, 47, 133, 49, 147, 204, 96, 125, 165, 105, 182, 161, 2,
                        143, 225, 195, 95, 64, 24, 49, 236, 210, 124, 32, 214, 69, 201, 5, 73, 5,
                        7, 160, 233, 35, 202, 226, 40, 104, 45, 214, 0, 39, 55, 167, 203, 184, 145,
                        150, 233, 119, 115, 246, 55, 162, 5, 154, 147, 144, 69, 217, 185, 39, 82,
                        223, 87, 132, 164, 148, 85, 234, 15, 160, 2, 214, 133, 27, 73, 53, 27, 86,
                        53, 215, 96, 142, 85, 25, 127, 11, 111, 19, 1, 72, 74, 92, 16, 14, 98, 20,
                        203, 163, 227, 160, 192, 158, 223, 99, 116, 212, 137, 101, 150, 182, 125,
                        244, 59, 20, 157, 129, 149, 34, 21, 136, 185, 41, 242, 168, 45, 135, 100,
                        219, 239, 132, 211, 238, 37, 242, 139, 218, 120, 112, 158, 75, 53, 172,
                        162, 136, 202, 94, 117, 152, 175, 205, 34, 198, 99, 49, 174, 187, 80, 151,
                        225, 169, 120, 192, 77, 61, 38, 2, 158, 45, 216, 78, 215, 134, 255, 7, 46,
                        144, 119, 60, 168, 202, 24, 239, 147, 122, 58, 48, 50, 178, 58, 153, 243,
                        242, 169, 238, 42, 78, 123, 37, 181, 17, 109, 175, 84, 6, 212, 122, 89, 60,
                        111, 248, 41, 156, 214, 222, 151, 212, 52, 10, 221, 69, 1, 215, 170, 76,
                        149, 134, 241, 212, 217, 131, 179, 34, 240, 124, 224, 192, 105, 34, 254,
                        165, 211, 100, 169, 240, 171, 131, 50, 80, 54, 254, 128, 179, 233, 223, 22,
                        39, 56, 205, 221, 76, 177, 197, 164, 140, 181, 42, 154, 82, 239, 240, 127,
                        211, 45, 146, 57, 154, 151, 153, 112, 215, 222, 199, 37, 44, 98, 118, 182,
                        189, 15, 139, 88, 227, 37, 149, 107, 13, 123, 201, 51, 61, 67, 220, 161,
                        13, 72, 176, 39, 157, 128, 105, 144, 10, 46, 29, 113, 1, 76, 162, 157, 200,
                        213, 175, 107, 128, 13, 47, 170, 216, 107, 48, 241, 149, 219, 20, 186, 74,
                        210, 5, 210, 18, 201, 78, 159, 121, 180, 195, 154, 176, 154, 255, 21, 5,
                        86, 212, 181, 237, 131, 116, 59, 241, 57, 24, 102, 126, 132, 135, 154, 99,
                        217, 2, 201, 139, 202, 125, 64, 165, 195, 210, 255, 165, 197, 172, 166, 27,
                        200, 226, 158, 225, 224, 10, 150, 97, 2, 77, 73, 51, 112, 201, 146, 74,
                        245, 95, 191, 244, 128, 170, 109, 227, 44, 24, 11, 216, 35, 137, 61, 120,
                        207, 212, 57, 229, 70, 152, 118, 92, 235, 187, 55, 189, 231, 126, 15, 86,
                        66, 78, 251, 39, 181, 191, 193, 226, 199, 131, 61, 145, 177, 76, 168, 0,
                        235, 172, 21, 213, 87, 81, 176, 135, 139, 61, 3, 91, 67, 84, 199, 40, 113,
                        140, 68, 174, 34, 199, 50, 33, 187, 208, 209, 155, 237, 140, 16, 204, 135,
                        151, 241, 28, 95, 87, 91, 169, 160, 1, 206, 18, 220, 65, 236, 52, 63, 184,
                        226, 237, 129, 19, 170, 194, 11, 154, 168, 110, 242, 19, 167, 195, 205, 68,
                        4, 151, 99, 196, 164, 13, 137, 140, 175, 134, 102, 47, 63, 0, 229, 73, 218,
                        226, 121, 230, 98, 31, 102, 161, 40, 233, 229, 39, 224, 19, 92, 220, 151,
                        154, 193, 191, 30
                    ]
                )
            }
            _ => unreachable!(),
        }
    }
}
