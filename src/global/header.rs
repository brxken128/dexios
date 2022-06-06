use crate::{
    global::states::{Algorithm, CipherMode, HeaderVersion},
    global::SALT_LEN,
};
use anyhow::{Context, Result};
use blake3::Hasher;
use std::io::Read;
use std::{
    fs::File,
    io::{Seek, Write},
};

// the information needed to easily serialize a header
pub struct HeaderType {
    pub header_version: HeaderVersion,
    pub cipher_mode: CipherMode,
    pub algorithm: Algorithm,
}

// the data used returned after reading/deserialising a header
pub struct Header {
    pub header_type: HeaderType,
    pub nonce: Vec<u8>,
    pub salt: [u8; SALT_LEN],
}

// !!!attach context
impl Header {
    fn get_tag(&self) -> HeaderTag {
        let version = self.serialize_version();
        let algorithm = self.serialize_algorithm();
        let mode = self.serialize_mode();
        HeaderTag {
            version,
            algorithm,
            mode,
        }
    }

    fn serialize_version(&self) -> [u8; 2] {
        match self.header_type.header_version {
            HeaderVersion::V1 => {
                let info: [u8; 2] = [0xDE, 0x01];
                info
            }
            HeaderVersion::V2 => {
                let info: [u8; 2] = [0xDE, 0x02];
                info
            }
            HeaderVersion::V3 => {
                let info: [u8; 2] = [0xDE, 0x03];
                info
            }
        }
    }

    fn deserialize_version<R>(reader: &mut R) -> Result<HeaderVersion>
    where
        R: std::io::Read,
    {
        let mut bytes = [0u8; 2];
        reader
            .read_exact(&mut bytes)
            .context("Unable to read version's bytes from header")?;

        let version = match bytes {
            [0xDE, 0x01] => HeaderVersion::V1,
            [0xDE, 0x02] => HeaderVersion::V2,
            [0xDE, 0x03] => HeaderVersion::V3,
            _ => return Err(anyhow::anyhow!("Error getting version from header")),
        };

        Ok(version)
    }

    // returns a header and the associated AAD
    // the AAD for v3+ headers will be the full 64 bytes
    // AAD for < v3 headers will be empty, as that's the default
    pub fn deserialize(reader: &mut (impl Read + Seek)) -> Result<(Self, Vec<u8>)> {
        let mut version_bytes = [0u8; 2];
        reader
            .read_exact(&mut version_bytes)
            .context("Unable to read version's bytes from header")?;

        let version = match version_bytes {
            [0xDE, 0x01] => HeaderVersion::V1,
            [0xDE, 0x02] => HeaderVersion::V2,
            [0xDE, 0x03] => HeaderVersion::V3,
            _ => return Err(anyhow::anyhow!("Error getting version from header")),
        };

        let mut algorithm_bytes = [0u8; 2];
        reader
            .read_exact(&mut algorithm_bytes)
            .context("Unable to read algorithm's bytes from header")?;

        let algorithm = match algorithm_bytes {
            [0x0E, 0x01] => Algorithm::XChaCha20Poly1305,
            [0x0E, 0x02] => Algorithm::Aes256Gcm,
            [0x0E, 0x03] => Algorithm::DeoxysII256,
            _ => return Err(anyhow::anyhow!("Error getting encryption mode from header")),
        };

        let mut mode_bytes = [0u8; 2];
        reader
            .read_exact(&mut mode_bytes)
            .context("Unable to read encryption mode's bytes from header")?;

        let mode = match mode_bytes {
            [0x0C, 0x01] => CipherMode::StreamMode,
            [0x0C, 0x02] => CipherMode::MemoryMode,
            _ => return Err(anyhow::anyhow!("Error getting cipher mode from header")),
        };

        let header_type = HeaderType {
            header_version: version,
            algorithm,
            cipher_mode: mode,
        };
        let nonce_len = calc_nonce_len(&header_type);
        let mut salt = [0u8; 16];
        let mut nonce = vec![0u8; nonce_len];

        match header_type.header_version {
            HeaderVersion::V1 => {
                reader.read_exact(&mut salt)?; // !!! add context
                reader.read_exact(&mut [0; 16])?;
                reader.read_exact(&mut nonce)?;
                reader.read_exact(&mut vec![0u8; 26 - nonce_len])?;
            }
            HeaderVersion::V2 => {
                reader.read_exact(&mut salt)?; // !!! add context
                reader.read_exact(&mut nonce)?;
                reader.read_exact(&mut vec![0u8; 26 - nonce_len])?;
                reader.read_exact(&mut [0u8; 16])?;
            }
            HeaderVersion::V3 => {
                reader
                    .read_exact(&mut salt)
                    .context("Unable to read salt from header")?;
                reader
                    .read_exact(&mut [0u8; 16])
                    .context("Unable to read empty bytes from header")?; // read and subsequently discard the next 16 bytes
                reader
                    .read_exact(&mut nonce)
                    .context("Unable to read nonce from header")?;
                reader
                    .read_exact(&mut vec![0u8; 26 - nonce_len])
                    .context("Unable to read final padding from header")?;
            }
        };

        let aad = match header_type.header_version {
            HeaderVersion::V1 => Vec::<u8>::new(),
            HeaderVersion::V2 => Vec::<u8>::new(),
            HeaderVersion::V3 => {
                let mut buffer = [0u8; 64];
                reader.seek(std::io::SeekFrom::Current(-64))?; // go back to start of input
                reader.read_exact(&mut buffer)?;
                buffer.to_vec()
            }
        };

        let header = Header {
            header_type,
            nonce,
            salt,
        };

        Ok((header, aad))
    }

    fn serialize_algorithm(&self) -> [u8; 2] {
        match self.header_type.algorithm {
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
        }
    }
    fn serialize_mode(&self) -> [u8; 2] {
        match self.header_type.cipher_mode {
            CipherMode::StreamMode => {
                let info: [u8; 2] = [0x0C, 0x01];
                info
            }
            CipherMode::MemoryMode => {
                let info: [u8; 2] = [0x0C, 0x02];
                info
            }
        }
    }

    fn serialize_v3(&self, tag: HeaderTag) -> Vec<u8> {
        let padding = vec![0u8; 26 - calc_nonce_len(&self.header_type)];
        let mut header_bytes = Vec::<u8>::new();
        header_bytes.extend_from_slice(&tag.version);
        header_bytes.extend_from_slice(&tag.algorithm);
        header_bytes.extend_from_slice(&tag.mode);
        header_bytes.extend_from_slice(&self.salt);
        header_bytes.extend_from_slice(&[0; 16]);
        header_bytes.extend_from_slice(&self.nonce);
        header_bytes.extend(&padding);
        header_bytes
    }

    // returns the raw header bytes
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let tag = self.get_tag();
        let bytes = match self.header_type.header_version {
            HeaderVersion::V1 => {
                return Err(anyhow::anyhow!(
                    "Serializing V1 headers has been deprecated"
                ))
            }
            HeaderVersion::V2 => {
                return Err(anyhow::anyhow!(
                    "Serializing V2 headers has been deprecated"
                ))
            }
            HeaderVersion::V3 => self.serialize_v3(tag),
        };

        Ok(bytes)
    }

    // convenience function for writing the header to a file/buffer
    pub fn write(&self, writer: &mut impl Write) -> Result<()> {
        let header_bytes = self.serialize()?;
        writer
            .write(&header_bytes)
            .context("Unable to write header")?;

        Ok(())
    }
}

pub struct HeaderTag {
    pub version: [u8; 2],
    pub algorithm: [u8; 2],
    pub mode: [u8; 2],
}

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
fn serialize(header_info: &HeaderType) -> HeaderTag {
    let version = match header_info.header_version {
        HeaderVersion::V1 => {
            let info: [u8; 2] = [0xDE, 0x01];
            info
        }
        HeaderVersion::V2 => {
            let info: [u8; 2] = [0xDE, 0x02];
            info
        }
        HeaderVersion::V3 => {
            let info: [u8; 2] = [0xDE, 0x03];
            info
        }
    };
    let algorithm = match header_info.algorithm {
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

    let mode = match header_info.cipher_mode {
        CipherMode::StreamMode => {
            let info: [u8; 2] = [0x0C, 0x01];
            info
        }
        CipherMode::MemoryMode => {
            let info: [u8; 2] = [0x0C, 0x02];
            info
        }
    };

    HeaderTag {
        version,
        algorithm,
        mode,
    }
}

// this writes a header to a file
// it handles padding and serialising the specific information
// it ensures the buffer is left at 64 bytes, so other functions can write the data without further hassle

// this hashes a header with the salt, nonce, and info provided
pub fn hash(hasher: &mut Hasher, header: &Header) {
    match &header.header_type.header_version {
        HeaderVersion::V1 | HeaderVersion::V3 => {
            let nonce_len = calc_nonce_len(&header.header_type);
            let padding = vec![0u8; 26 - nonce_len];
            let header_tag = serialize(&header.header_type);

            hasher.update(&header_tag.version);
            hasher.update(&header_tag.algorithm);
            hasher.update(&header_tag.mode);
            hasher.update(&header.salt);
            hasher.update(&[0; 16]);
            hasher.update(&header.nonce);
            hasher.update(&padding);
        }
        HeaderVersion::V2 => {
            let nonce_len = calc_nonce_len(&header.header_type);
            let padding = vec![0u8; 26 - nonce_len];
            let header_tag = serialize(&header.header_type);

            hasher.update(&header_tag.version);
            hasher.update(&header_tag.algorithm);
            hasher.update(&header_tag.mode);
            hasher.update(&header.salt);
            hasher.update(&header.nonce);
            hasher.update(&padding);
        }
    }
}

// // this is used for converting raw bytes from the header to enums that dexios can understand
// // this involves the header version, encryption algorithm/mode, and possibly more in the future
// fn deserialize(header_tag: &HeaderTag) -> Result<HeaderType> {
//     let header_version = match header_tag.version {
//         [0xDE, 0x01] => HeaderVersion::V1,
//         [0xDE, 0x02] => HeaderVersion::V2,
//         [0xDE, 0x03] => HeaderVersion::V3,
//         _ => return Err(anyhow::anyhow!("Error getting cipher mode from header")),
//     };

//     let algorithm = match header_tag.algorithm {
//         [0x0E, 0x01] => Algorithm::XChaCha20Poly1305,
//         [0x0E, 0x02] => Algorithm::Aes256Gcm,
//         [0x0E, 0x03] => Algorithm::DeoxysII256,
//         _ => return Err(anyhow::anyhow!("Error getting encryption mode from header")),
//     };

//     let cipher_mode = match header_tag.mode {
//         [0x0C, 0x01] => CipherMode::StreamMode,
//         [0x0C, 0x02] => CipherMode::MemoryMode,
//         _ => return Err(anyhow::anyhow!("Error getting cipher mode from header")),
//     };

//     Ok(HeaderType {
//         header_version,
//         cipher_mode,
//         algorithm,
//     })
// }

// // this takes an input file, and gets all of the data necessary from the header of the file
// // it ensures that the buffer starts at 64 bytes, so that other functions can just read encrypted data immediately
// pub fn read_from_file(file: &mut File) -> Result<(Header, Vec<u8>)> {
//     let mut version = [0u8; 2];
//     let mut algorithm = [0u8; 2];
//     let mut mode = [0u8; 2];

//     let mut salt = [0u8; SALT_LEN];

//     file.read_exact(&mut version)
//         .context("Unable to read version from header")?;
//     file.read_exact(&mut algorithm)
//         .context("Unable to read algorithm from header")?;
//     file.read_exact(&mut mode)
//         .context("Unable to read encryption mode from header")?;

//     let header_tag = HeaderTag {
//         version,
//         algorithm,
//         mode,
//     };

//     let header_info = deserialize(&header_tag)?;

//     match header_info.header_version {
//         HeaderVersion::V1 => {
//             warn!("You are using an older version of the Dexios header standard, please re-encrypt your files at your earliest convenience");
//             let nonce_len = calc_nonce_len(&header_info);
//             let mut nonce = vec![0u8; nonce_len];

//             file.read_exact(&mut salt)
//                 .context("Unable to read salt from header")?;
//             file.read_exact(&mut [0; 16])
//                 .context("Unable to read empty bytes from header")?; // read and subsequently discard the next 16 bytes
//             file.read_exact(&mut nonce)
//                 .context("Unable to read nonce from header")?;
//             file.read_exact(&mut vec![0u8; 26 - nonce_len])
//                 .context("Unable to read final padding from header")?; // read and discard the final padding

//             let header = Header {
//                 header_type: header_info,
//                 nonce,
//                 salt,
//             };

//             let aad = get_aad(&header, None, None);

//             Ok((header, aad))
//         }
//         HeaderVersion::V2 => {
//             warn!("You are using an older version of the Dexios header standard, please re-encrypt your files at your earliest convenience");
//             let nonce_len = calc_nonce_len(&header_info);
//             let mut nonce = vec![0u8; nonce_len];

//             file.read_exact(&mut salt)
//                 .context("Unable to read salt from header")?;
//             file.read_exact(&mut nonce)
//                 .context("Unable to read nonce from header")?;
//             file.read_exact(&mut vec![0u8; 26 - nonce_len])
//                 .context("Unable to read final padding from header")?; // read and discard the padding
//             file.read_exact(&mut [0u8; 16])
//                 .context("Unable to read signature from header")?; // read signature

//             let header = Header {
//                 header_type: header_info,
//                 nonce,
//                 salt,
//             };

//             let aad = get_aad(&header, None, None);

//             Ok((header, aad))
//         }
//         HeaderVersion::V3 => {
//             let nonce_len = calc_nonce_len(&header_info);
//             let mut nonce = vec![0u8; nonce_len];
//             let mut padding1 = [0u8; 16];
//             let mut padding2 = vec![0u8; 26 - nonce_len];

//             file.read_exact(&mut salt)
//                 .context("Unable to read salt from header")?;
//             file.read_exact(&mut padding1)
//                 .context("Unable to read empty bytes from header")?; // read and subsequently discard the next 16 bytes
//             file.read_exact(&mut nonce)
//                 .context("Unable to read nonce from header")?;
//             file.read_exact(&mut padding2)
//                 .context("Unable to read final padding from header")?; // read and discard the final padding

//             let header = Header {
//                 header_type: header_info,
//                 nonce,
//                 salt,
//             };

//             let aad = get_aad(&header, Some(padding1), Some(padding2));

//             Ok((header, aad))
//         }
//     }
// }

// fn get_aad(header: &Header, padding1: Option<[u8; 16]>, padding2: Option<Vec<u8>>) -> Vec<u8> {
//     match header.header_type.header_version {
//         HeaderVersion::V3 => {
//             let header_tag = serialize(&header.header_type);

//             let mut header_bytes = header_tag.version.to_vec();
//             header_bytes.extend_from_slice(&header_tag.mode);
//             header_bytes.extend_from_slice(&header_tag.algorithm);
//             header_bytes.extend_from_slice(&header.salt);
//             header_bytes.extend_from_slice(&padding1.unwrap());
//             header_bytes.extend_from_slice(&header.nonce);
//             header_bytes.extend_from_slice(&padding2.unwrap());
//             header_bytes
//         }
//         _ => Vec::new(),
//     }
// }

// pub fn create_aad(header: &Header) -> Vec<u8> {
//     match header.header_type.header_version {
//         HeaderVersion::V3 => {
//             let nonce_len = calc_nonce_len(&header.header_type);
//             let header_tag = serialize(&header.header_type);

//             let mut header_bytes = header_tag.version.to_vec();
//             header_bytes.extend_from_slice(&header_tag.mode);
//             header_bytes.extend_from_slice(&header_tag.algorithm);
//             header_bytes.extend_from_slice(&header.salt);
//             header_bytes.extend_from_slice(&[0; 16]);
//             header_bytes.extend_from_slice(&header.nonce);
//             header_bytes.extend_from_slice(&vec![0; 26 - nonce_len]);
//             header_bytes
//         }
//         _ => Vec::new(),
//     }
// }
