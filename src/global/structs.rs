use crate::global::states::{
    BenchMode, HashMode, KeyFile, PasswordMode,
    SkipMode,
};

use super::states::EraseMode;

pub struct CryptoParams {
    pub hash_mode: HashMode,
    pub skip: SkipMode,
    pub bench: BenchMode,
    pub password: PasswordMode,
    pub erase: EraseMode,
    pub keyfile: KeyFile,
}