// TODO(pleshevskiy): dedup these utils

use dexios_core::protected::Protected;

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

// this autogenerates a passphrase, which can be selected with `--auto`
// it reads the EFF large list of words, and puts them all into a vec
// 3 words are then chosen at random, and 6 digits are also
// the 3 words and the digits are separated with -
// the words are also capitalised
// this passphrase should provide adequate protection, while not being too hard to remember
pub fn gen_passphrase() -> Protected<String> {
    use rand::{prelude::StdRng, Rng, SeedableRng};
    let collection = include_str!("wordlist.lst");
    let words = collection.lines().collect::<Vec<_>>();

    let mut passphrase = String::new();

    for _ in 0..3 {
        let index = StdRng::from_entropy().gen_range(0..=words.len());
        let word = words[index];
        let capitalized_word = word
            .char_indices()
            .map(|(i, ch)| match i {
                0 => ch.to_ascii_uppercase(),
                _ => ch,
            })
            .collect::<String>();
        passphrase.push_str(&capitalized_word);
        passphrase.push('-');
    }

    for _ in 0..6 {
        let number: i64 = StdRng::from_entropy().gen_range(0..=9);
        passphrase.push_str(&number.to_string());
    }

    Protected::new(passphrase)
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
