use anyhow::{Ok, Result};

// this simply just hashes the provided salt, nonce and data
// it returns a blake3 hash in hex format
pub fn hash_data_blake3(salt: &[u8; 16], nonce: &[u8; 12], data: &[u8]) -> Result<String> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(salt);
    hasher.update(nonce);
    hasher.update(data);
    let hash = hasher.finalize().to_hex().to_string();
    Ok(hash)
}
