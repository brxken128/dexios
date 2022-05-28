use anyhow::Result;
use global::parameters::get_param;
use list::show_values;
use std::result::Result::Ok;
use global::enums::SkipMode;

mod cli;
mod decrypt;
mod encrypt;
mod erase;
mod file;
mod global;
mod hashing;
mod header;
mod key;
mod list;
mod pack;
mod prompt;
mod secret;
mod streams;
mod subcommands;

// this is where subcommand function calling is handled
// it goes hand-in-hand with `subcommands.rs`
// it works so that's good enough, and any changes are rather simple to make to it
// it handles the calling of other functions, and some (minimal) argument parsing
fn main() -> Result<()> {
    let matches = cli::get_matches();

    match matches.subcommand() {
        Some(("encrypt", sub_matches)) => {
            subcommands::encrypt(sub_matches)?;
        }
        Some(("decrypt", sub_matches)) => {
            subcommands::decrypt(sub_matches)?;
        }
        Some(("erase", sub_matches)) => {
            subcommands::erase(sub_matches)?;
        }
        Some(("hash", sub_matches)) => {
            let input = get_param("input", sub_matches)?;
            hashing::hash_stream(&input)?;
        }
        Some(("list", sub_matches)) => {
            show_values(&get_param("input", sub_matches)?)?;
        }
        Some(("pack", sub_matches)) => match sub_matches.subcommand_name() {
            Some("encrypt") => {
                subcommands::pack(sub_matches)?;
            }
            Some("decrypt") => {
                subcommands::unpack(sub_matches)?;
            }
            _ => (),
        },
        Some(("header", sub_matches)) => match sub_matches.subcommand_name() {
            Some("dump") => {
                let sub_matches_dump = sub_matches.subcommand_matches("dump").unwrap();
                let skip = if sub_matches_dump.is_present("skip") {
                    SkipMode::HidePrompts
                } else {
                    SkipMode::ShowPrompts
                };

                header::dump(
                    &get_param("input", sub_matches_dump)?,
                    &get_param("output", sub_matches_dump)?,
                    skip,
                )?;
            }
            Some("restore") => {
                let sub_matches_restore = sub_matches.subcommand_matches("restore").unwrap();
                let skip = if sub_matches_restore.is_present("skip") {
                    SkipMode::HidePrompts
                } else {
                    SkipMode::ShowPrompts
                };

                header::restore(
                    &get_param("input", sub_matches_restore)?,
                    &get_param("output", sub_matches_restore)?,
                    skip,
                )?;
            }
            Some("strip") => {
                let sub_matches_strip = sub_matches.subcommand_matches("strip").unwrap();
                let skip = if sub_matches_strip.is_present("skip") {
                    SkipMode::HidePrompts
                } else {
                    SkipMode::ShowPrompts
                };

                header::strip(&get_param("input", sub_matches_strip)?, skip)?;
            }
            _ => (),
        },
        _ => (),
    }
    Ok(())
}
