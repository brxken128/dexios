use self::parameters::DexiosVersion;

// this file sets constants that are used throughout the codebase
// these can be customised easily by anyone to suit their own needs
pub const BLOCK_SIZE: usize = 1_048_576; // 1024*1024 bytes
pub const SALT_LEN: usize = 16; // bytes
pub const VERSION: DexiosVersion = DexiosVersion::V8;

pub mod crypto;
pub mod parameters;
