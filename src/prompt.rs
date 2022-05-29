use anyhow::{Context, Result};
use paris::{warn, Logger};
use std::io::{self, stdin, Write};

use crate::global::enums::{BenchMode, SkipMode};

// this handles user-interactivity, specifically getting a "yes" or "no" answer from the user
// it requires the question itself, if the default is true/false
// if skip is enabled then it will just return the `default`
pub fn get_answer(prompt: &str, default: bool, skip: bool) -> Result<bool> {
    if skip {
        return Ok(true);
    }

    let switch = if default { "(Y/n)" } else { "(y/N)" };

    let answer_bool = loop {
        let mut logger = Logger::new();
        
        logger.same().warn(format!("{prompt} {switch}: "));
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
// if they have the skip argument supplied, this will just assume true
// if benchmarking or skip are true, skip the prompt entirely
pub fn overwrite_check(name: &str, skip: SkipMode, bench: BenchMode) -> Result<bool> {
    let answer = if std::fs::metadata(name).is_ok() {
        let prompt = format!("{} already exists, would you like to overwrite?", name);
        let skip_or_bench = skip == SkipMode::HidePrompts || bench == BenchMode::BenchmarkInMemory;
        get_answer(&prompt, true, skip_or_bench)?
    } else {
        true
    };
    Ok(answer)
}
