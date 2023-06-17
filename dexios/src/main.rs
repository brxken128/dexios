#![forbid(unsafe_code)]
#![warn(clippy::all)]

use anyhow::Result;

mod cli;
mod global;
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
        Some(("pack", sub_matches)) => {
            subcommands::pack(sub_matches)?;
        }
        Some(("unpack", sub_matches)) => {
            subcommands::unpack(sub_matches)?;
        }
        Some(("hash", sub_matches)) => {
            subcommands::hash_stream(sub_matches)?;
        }
        Some(("header", sub_matches)) => match sub_matches.subcommand_name() {
            Some("dump") => {
                subcommands::header_dump(sub_matches)?;
            }
            Some("restore") => {
                subcommands::header_restore(sub_matches)?;
            }
            Some("strip") => {
                subcommands::header_strip(sub_matches)?;
            }
            Some("details") => {
                subcommands::header_details(sub_matches)?;
            }
            _ => (),
        },
        Some(("key", sub_matches)) => match sub_matches.subcommand_name() {
            Some("change") => {
                subcommands::key_change(sub_matches)?;
            }
            Some("add") => {
                subcommands::key_add(sub_matches)?;
            }
            Some("del") => {
                subcommands::key_del(sub_matches)?;
            }
            Some("verify") => {
                subcommands::key_verify(sub_matches)?;
            }
            _ => (),
        },
        _ => (),
    }
    Ok(())
}
