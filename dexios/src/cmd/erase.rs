use anyhow::Result;
use domain::storage::Storage;
use std::{path::PathBuf, sync::Arc};

use crate::ui::prompt::get_answer;

#[derive(clap::Args)]
pub struct Args {
    #[clap(
        short,
        long = "passes",
        default_value = "1",
        help = "Specify the number of passes (default is 1)"
    )]
    erase_passes: u32,

    #[clap(short, long, default_value_t, help = "Force all actions")]
    force: bool,

    #[clap(help = "The file to erase")]
    input: PathBuf,
}

// this function securely erases a file
// read the docs for some caveats with file-erasure on flash storage
// it takes the file name/relative path, and the number of times to go over the file's contents with random bytes
pub fn execute(args: Args) -> Result<()> {
    // TODO: It is necessary to raise it to a higher level
    let stor = Arc::new(domain::storage::FileStorage);

    let file = stor.read_file(args.input)?;
    if file.is_dir()
        && !get_answer(
            "This is a directory, would you like to erase all files within it?",
            false,
            args.force,
        )?
    {
        std::process::exit(0);
    }

    if file.is_dir() {
        domain::erase_dir::execute(
            stor,
            domain::erase_dir::Request {
                entry: file,
                passes: args.erase_passes,
            },
        )?;
    } else {
        domain::erase::execute(
            stor,
            domain::erase::Request {
                path: args.input,
                passes: args.erase_passes,
            },
        )?;
    }

    Ok(())
}
