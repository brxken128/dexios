// TODO(pleshevskiy): dedup these utils

#[cfg(test)]
mod test {
    use dexios_core::primitives::{get_nonce_len, Algorithm, Mode, MASTER_KEY_LEN, SALT_LEN};
    use dexios_core::protected::Protected;
    use rand::{prelude::StdRng, RngCore, SeedableRng};

    const SALT_SEED: u64 = 123456;
    const NONCE_SEED: u64 = SALT_SEED + 1;
    const MASTER_KEY_SEED: u64 = NONCE_SEED + 2;

    pub fn gen_salt() -> [u8; SALT_LEN] {
        let mut salt = [0u8; SALT_LEN];
        StdRng::seed_from_u64(SALT_SEED).fill_bytes(&mut salt);
        salt
    }

    pub fn gen_nonce(algorithm: &Algorithm, mode: &Mode) -> Vec<u8> {
        let nonce_len = get_nonce_len(algorithm, mode);
        let mut nonce = vec![0u8; nonce_len];
        StdRng::seed_from_u64(NONCE_SEED).fill_bytes(&mut nonce);
        nonce
    }

    pub fn gen_master_key() -> Protected<[u8; MASTER_KEY_LEN]> {
        let mut master_key = [0u8; MASTER_KEY_LEN];
        StdRng::seed_from_u64(MASTER_KEY_SEED).fill_bytes(&mut master_key);
        Protected::new(master_key)
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

#[cfg(test)]
pub use test::gen_master_key;
#[cfg(test)]
pub use test::gen_nonce;
#[cfg(test)]
pub use test::gen_salt;

#[cfg(not(test))]
pub use dexios_core::primitives::gen_master_key;
#[cfg(not(test))]
pub use dexios_core::primitives::gen_nonce;
#[cfg(not(test))]
pub use dexios_core::primitives::gen_salt;
