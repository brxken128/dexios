#[derive(Debug)]
pub enum Error {
    PasswordsDontMatch,
    EmptyKey,
    Unsupported,
    KeyfileRead,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;
        match self {
            PasswordsDontMatch => f.write_str("The passwords provided don't match"),
            EmptyKey => f.write_str("The provided key is empty"),
            KeyfileRead => f.write_str("Unable to read the keyfile"),
            Unsupported => f.write_str("This feature is not supported with the provided values"),
        }
    }
}

impl std::error::Error for Error {}
