// this file contains enums found all around the codebase
// they act as toggles for certain features, so they can be
// enabled if selected by the user
// some enums are used purely by dexios to handle things (e.g. detached header files)

use anyhow::Result;

#[derive(PartialEq, Clone, Copy)]
pub enum EraseMode {
    EraseFile(i32),
    IgnoreFile(i32),
}

#[derive(PartialEq, Clone, Copy)]
pub enum HashMode {
    CalculateHash,
    NoHash,
}

#[derive(PartialEq, Copy, Clone)]
pub enum SkipMode {
    ShowPrompts,
    HidePrompts,
}

#[derive(PartialEq, Copy, Clone)]
pub enum PasswordMode {
    ForceUserProvidedPassword,
    NormalKeySourcePriority,
}

#[derive(PartialEq)]
pub enum KeyFile {
    Some(String),
    None,
}

pub enum HeaderFile {
    Some(String),
    None,
}

impl EraseMode {
    pub fn get_passes(self) -> i32 {
        match self {
            EraseMode::EraseFile(passes) => passes,
            EraseMode::IgnoreFile(_) => 0,
        }
    }
}

impl KeyFile {
    pub fn get_inner(&self) -> Result<String> {
        match self {
            KeyFile::Some(data) => Ok(data.to_string()),
            KeyFile::None => Err(anyhow::anyhow!(
                "Tried using a keyfile when one wasn't provided"
            )), // should never happen
        }
    }
}
