use crate::global::states::{HashMode, KeyFile, PasswordMode, SkipMode};

use super::states::{Compression, DirectoryMode, EraseMode, EraseSourceDir, PrintMode};

pub struct CryptoParams {
    pub hash_mode: HashMode,
    pub skip: SkipMode,
    pub password: PasswordMode,
    pub erase: EraseMode,
    pub keyfile: KeyFile,
}

pub struct PackParams {
    pub dir_mode: DirectoryMode,
    pub print_mode: PrintMode,
    pub erase_source: EraseSourceDir,
    pub compression: Compression,
}
