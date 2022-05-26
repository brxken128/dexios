// this is a basic, auditable wrapper for secret data
// any data stored in this type will be zeroized on drop
// the `hidden` data can only be exposed via the `expose` function
// this means we can prevent accidental leaking of keys/other hidden values
// it implements debug which redacts the data to prevent leakage
// it was inspired by the `secrecy` crate, so a huge thanks to @tarcieri (github)

use std::fmt::Debug;
use zeroize::Zeroize;

pub struct Secret<T>
where
    T: Zeroize,
{
    hidden: T,
}

impl<T> Secret<T>
where
    T: Zeroize,
{
    pub fn new(secret: T) -> Self {
        Secret { hidden: secret }
    }

    pub fn expose(&self) -> &T {
        &self.hidden
    }
}

impl<T> Drop for Secret<T>
where
    T: Zeroize,
{
    fn drop(&mut self) {
        self.hidden.zeroize();
    }
}

impl<T> Debug for Secret<T>
where
    T: Zeroize,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}
