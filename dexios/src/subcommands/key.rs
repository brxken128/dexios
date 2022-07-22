use anyhow::{Context, Result};
use dexios_core::protected::Protected;
use dexios_core::Zeroize;
use paris::warn;
use rand::{prelude::StdRng, Rng, SeedableRng};

use crate::global::states::PasswordState;

// this interactively gets the user's password from the terminal
// it takes the password twice, compares, and returns the bytes
// if direct mode is enabled, it just reads the password once and returns it instantly
pub fn get_password(pass_state: &PasswordState) -> Result<Protected<Vec<u8>>> {
    Ok(loop {
        let input = rpassword::prompt_password("Password: ").context("Unable to read password")?;
        if pass_state == &PasswordState::Direct {
            return Ok(Protected::new(input.into_bytes()));
        }

        let mut input_validation =
            rpassword::prompt_password("Confirm password: ").context("Unable to read password")?;

        if input == input_validation && !input.is_empty() {
            input_validation.zeroize();
            break Protected::new(input.into_bytes());
        } else if input.is_empty() {
            warn!("Password cannot be empty, please try again.");
        } else {
            warn!("The passwords aren't the same, please try again.");
        }
    })
}

// this autogenerates a passphrase, which can be selected with `--auto`
// it reads the EFF large list of words, and puts them all into a vec
// 3 words are then chosen at random, and 6 digits are also
// the 3 words and the digits are separated with -
// the words are also capitalised
// this passphrase should provide adequate protection, while not being too hard to remember
pub fn generate_passphrase() -> Protected<String> {
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
