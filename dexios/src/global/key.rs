use anyhow::{Context, Result};
use dexios_core::protected::Protected;
use dexios_core::Zeroize;

use crate::{global::states::PasswordState, warn};

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
