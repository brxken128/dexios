#![deny(clippy::all)]

use anyhow::Result;
use global::parameters::forcemode;
use global::parameters::get_param;
use global::parameters::key_manipulation_params;

use crate::global::states::KeyParams;

mod cli;
mod file;
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
            let files: Vec<String> = if sub_matches.is_present("input") {
                let list: Vec<&str> = sub_matches.values_of("input").unwrap().collect();
                list.iter().map(std::string::ToString::to_string).collect()
            } else {
                Vec::new()
            };

            subcommands::hashing::hash_stream(&files)?;
        }
        Some(("header", sub_matches)) => match sub_matches.subcommand_name() {
            Some("dump") => {
                let sub_matches_dump = sub_matches.subcommand_matches("dump").unwrap();
                let force = forcemode(sub_matches_dump);

                subcommands::header::dump(
                    &get_param("input", sub_matches_dump)?,
                    &get_param("output", sub_matches_dump)?,
                    force,
                )?;
            }
            Some("restore") => {
                let sub_matches_restore = sub_matches.subcommand_matches("restore").unwrap();
                let force = forcemode(sub_matches_restore);

                subcommands::header::restore(
                    &get_param("input", sub_matches_restore)?,
                    &get_param("output", sub_matches_restore)?,
                    force,
                )?;
            }
            Some("strip") => {
                let sub_matches_strip = sub_matches.subcommand_matches("strip").unwrap();
                let force = forcemode(sub_matches_strip);

                subcommands::header::strip(&get_param("input", sub_matches_strip)?, force)?;
            }
            Some("details") => {
                let sub_matches_details = sub_matches.subcommand_matches("details").unwrap();

                subcommands::header::details(&get_param("input", sub_matches_details)?)?;
            }
            _ => (),
        },
        Some(("key", sub_matches)) => match sub_matches.subcommand_name() {
            Some("change") => {
                let sub_matches_change_key = sub_matches.subcommand_matches("change").unwrap();

                let (key_old, key_new) = key_manipulation_params(sub_matches_change_key)?;

                subcommands::key::change(
                    &get_param("input", sub_matches_change_key)?,
                    &key_old,
                    &key_new,
                )?;
            }
            Some("add") => {
                let sub_matches_add_key = sub_matches.subcommand_matches("add").unwrap();

                let (key_old, key_new) = key_manipulation_params(sub_matches_add_key)?;

                subcommands::key::add(
                    &get_param("input", sub_matches_add_key)?,
                    &key_old,
                    &key_new,
                )?;
            }
            Some("del") => {
                use crate::global::states::Key;

                let sub_matches_del_key = sub_matches.subcommand_matches("del").unwrap();
                let key = Key::init(sub_matches_del_key, KeyParams::default(), "keyfile")?;

                subcommands::key::delete(&get_param("input", sub_matches_del_key)?, &key)?;
            }
            _ => (),
        },
        _ => (),
    }
    Ok(())
}
