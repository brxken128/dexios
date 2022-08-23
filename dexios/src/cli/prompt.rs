use anyhow::{Context, Result};
use std::io::{self, stdin, Write};

use crate::{
    global::states::{ForceMode, PasswordState},
    question, warn,
};

use core::protected::Protected;
use core::Zeroize;

// this handles user-interactivity, specifically getting a "yes" or "no" answer from the user
// it requires the question itself, if the default is true/false
// if force is enabled then it will just return the `default`
pub fn get_answer(prompt: &str, default: bool, force: ForceMode) -> Result<bool> {
    if force == ForceMode::Force {
        return Ok(true);
    }

    let switch = if default { "(Y/n)" } else { "(y/N)" };

    let answer_bool = loop {
        question!("{prompt} {switch}: ");
        io::stdout().flush().context("Unable to flush stdout")?;

        let mut answer = String::new();
        stdin()
            .read_line(&mut answer)
            .context("Unable to read from stdin")?;

        let answer_lowercase = answer.to_lowercase();
        let first_char = answer_lowercase
            .chars()
            .next()
            .context("Unable to get first character of your answer")?;
        break match first_char {
            '\n' | '\r' => default,
            'y' => true,
            'n' => false,
            _ => {
                warn!("Unrecognised answer - please try again");
                continue;
            }
        };
    };
    Ok(answer_bool)
}

// this checks if the file exists
// then it prompts the user if they'd like to overwrite a file (while showing the associated file name)
// if they have the force argument supplied, this will just assume true
// if force mode is true, avoid prompts at all
pub fn overwrite_check(name: &str, force: ForceMode) -> Result<bool> {
    let answer = if std::fs::metadata(name).is_ok() {
        let prompt = format!("{} already exists, would you like to overwrite?", name);
        get_answer(&prompt, true, force)?
    } else {
        true
    };
    Ok(answer)
}

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
