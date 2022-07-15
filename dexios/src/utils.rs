// TODO(pleshevskiy): dedup these utils

#[cfg(test)]
mod test {
    use dexios_core::primitives::{get_nonce_len, Algorithm, Mode, SALT_LEN};
    use dexios_core::protected::Protected;
    use rand::{prelude::StdRng, RngCore, SeedableRng};

    const SEED: u64 = 123456;

    pub fn gen_salt() -> [u8; SALT_LEN] {
        let mut salt = [0u8; SALT_LEN];
        StdRng::seed_from_u64(SEED).fill_bytes(&mut salt);
        salt
    }

    pub fn gen_nonce(algorithm: &Algorithm, mode: &Mode) -> Vec<u8> {
        let nonce_len = get_nonce_len(algorithm, mode);
        let mut nonce = vec![0u8; nonce_len];
        StdRng::seed_from_u64(SEED).fill_bytes(&mut nonce);
        nonce
    }

    pub fn gen_master_key() -> Protected<[u8; 32]> {
        let mut master_key = [0u8; 32];
        StdRng::seed_from_u64(SEED).fill_bytes(&mut master_key);
        Protected::new(master_key)
    }
}

#[cfg(test)]
pub use test::gen_master_key;
#[cfg(test)]
pub use test::gen_nonce;
#[cfg(test)]
pub use test::gen_salt;

#[cfg(not(test))]
pub use dexios_core::key::gen_salt;
#[cfg(not(test))]
pub use dexios_core::primitives::gen_nonce;

#[cfg(not(test))]
use dexios_core::protected::Protected;
#[cfg(not(test))]
use rand::{prelude::StdRng, RngCore, SeedableRng};
#[cfg(not(test))]
pub fn gen_master_key() -> Protected<[u8; 32]> {
    let mut master_key = [0u8; 32];
    StdRng::from_entropy().fill_bytes(&mut master_key);
    Protected::new(master_key)
}
