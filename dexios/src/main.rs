use anyhow::Result;
use global::parameters::get_param;
use global::parameters::key_update_params;
use global::parameters::skipmode;
use subcommands::list::show_values;

mod cli;
mod domain;
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
            // this fixes 'static lifetime issues
            } else {
                Vec::new()
            };

            subcommands::hashing::hash_stream(&files)?;
        }
        Some(("list", sub_matches)) => {
            show_values(&get_param("input", sub_matches)?)?;
        }
        Some(("header", sub_matches)) => match sub_matches.subcommand_name() {
            Some("update-key") => {
                let sub_matches_update_key = sub_matches.subcommand_matches("update-key").unwrap();

                let (keyfile_old, keyfile_new) = key_update_params(sub_matches_update_key)?;

                subcommands::header::update_key(
                    &get_param("input", sub_matches_update_key)?,
                    &keyfile_old,
                    &keyfile_new,
                )?;
            }
            Some("dump") => {
                let sub_matches_dump = sub_matches.subcommand_matches("dump").unwrap();
                let skip = skipmode(sub_matches_dump);

                subcommands::header::dump(
                    &get_param("input", sub_matches_dump)?,
                    &get_param("output", sub_matches_dump)?,
                    skip,
                )?;
            }
            Some("restore") => {
                let sub_matches_restore = sub_matches.subcommand_matches("restore").unwrap();
                let skip = skipmode(sub_matches_restore);

                subcommands::header::restore(
                    &get_param("input", sub_matches_restore)?,
                    &get_param("output", sub_matches_restore)?,
                    skip,
                )?;
            }
            Some("strip") => {
                let sub_matches_strip = sub_matches.subcommand_matches("strip").unwrap();
                let skip = skipmode(sub_matches_strip);

                subcommands::header::strip(&get_param("input", sub_matches_strip)?, skip)?;
            }
            _ => (),
        },
        _ => (),
    }
    Ok(())
}
