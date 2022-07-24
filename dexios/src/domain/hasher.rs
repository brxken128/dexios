pub trait Hasher {
    fn write(&mut self, input: &[u8]);
    fn finish(&mut self) -> String;
}

pub struct Blake3Hasher {
    inner: blake3::Hasher,
}

impl Default for Blake3Hasher {
    fn default() -> Self {
        Self {
            inner: blake3::Hasher::new(),
        }
    }
}

impl Hasher for Blake3Hasher {
    fn write(&mut self, input: &[u8]) {
        self.inner.update(input);
    }

    fn finish(&mut self) -> String {
        self.inner.finalize().to_hex().to_string()
    }
}
