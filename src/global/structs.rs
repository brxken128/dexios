use crate::global::states::{HashMode, PasswordMode, SkipMode};

use super::states::{Compression, DirectoryMode, EraseMode, EraseSourceDir, PrintMode, Key};

pub struct CryptoParams {
    pub hash_mode: HashMode,
    pub skip: SkipMode,
    pub password: PasswordMode,
    pub erase: EraseMode,
    pub key: Key,
}

pub struct PackParams {
    pub dir_mode: DirectoryMode,
    pub print_mode: PrintMode,
    pub erase_source: EraseSourceDir,
    pub compression: Compression,
}
