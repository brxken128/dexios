use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct DexiosFile {
    pub salt: String,
    pub nonce: String,
    pub data: String,
}
