use crate::global::states::{HashMode, KeyFile, PasswordMode, SkipMode};

use super::states::EraseMode;

pub struct CryptoParams {
    pub hash_mode: HashMode,
    pub skip: SkipMode,
    pub password: PasswordMode,
    pub erase: EraseMode,
    pub keyfile: KeyFile,
}
