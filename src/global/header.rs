use crate::{
    global::states::{Algorithm, CipherMode, HeaderVersion},
    global::SALT_LEN,
};
use anyhow::{Context, Result};
use std::io::{Read, Seek, Write};

// the "tag" that contains version/mode information
pub struct HeaderType {
    pub header_version: HeaderVersion,
    pub cipher_mode: CipherMode,
    pub algorithm: Algorithm,
}

// the "tag"/HeaderType, but in raw bytes
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

// the full header, including version, salt, nonce, mode, encryption algorithm, etc
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
            HeaderVersion::V1 | HeaderVersion::V3 => {
                reader
                    .read_exact(&mut salt)
                    .context("Unable to read salt from header")?;
                reader
                    .read_exact(&mut [0; 16])
                    .context("Unable to read empty bytes from header")?;
                reader
                    .read_exact(&mut nonce)
                    .context("Unable to read nonce from header")?;
                reader
                    .read_exact(&mut vec![0u8; 26 - nonce_len])
                    .context("Unable to read final padding from header")?;
            }
            HeaderVersion::V2 => {
                reader
                    .read_exact(&mut salt)
                    .context("Unable to read salt from header")?;
                reader
                    .read_exact(&mut nonce)
                    .context("Unable to read nonce from header")?;
                reader
                    .read_exact(&mut vec![0u8; 26 - nonce_len])
                    .context("Unable to read empty bytes from header")?;
                reader
                    .read_exact(&mut [0u8; 16])
                    .context("Unable to read final padding from header")?;
            }
        };

        let aad = match header_type.header_version {
            HeaderVersion::V1 | HeaderVersion::V2 => Vec::<u8>::new(),
            HeaderVersion::V3 => {
                let mut buffer = [0u8; 64];
                reader
                    .seek(std::io::SeekFrom::Current(-64))
                    .context("Unable to seek buffer")?; // go back to start of input
                reader
                    .read_exact(&mut buffer)
                    .context("Unable to read header")?;
                buffer.to_vec()
            }
        };

        Ok((
            Header {
                header_type,
                nonce,
                salt,
            },
            aad,
        ))
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

    fn serialize_v3(&self, tag: &HeaderTag) -> Vec<u8> {
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
            HeaderVersion::V3 => self.serialize_v3(&tag),
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
