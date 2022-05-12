pub struct DexiosFile {
    pub salt: [u8; 256],
    pub nonce: [u8; 12],
    pub data: Vec<u8>,
}
