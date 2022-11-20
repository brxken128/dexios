use anyhow::Result;
use domain::storage::Storage;
use std::sync::Arc;

use crate::global::states::ForceMode;

use crate::cli::prompt::get_answer;

// this function securely erases a file
// read the docs for some caveats with file-erasure on flash storage
// it takes the file name/relative path, and the number of times to go over the file's contents with random bytes
#[allow(clippy::module_name_repetitions)]
pub fn secure_erase(input: &str, passes: i32, force: ForceMode) -> Result<()> {
    // TODO: It is necessary to raise it to a higher level
    let stor = Arc::new(domain::storage::FileStorage);

    let file = stor.read_file(input)?;
    if file.is_dir()
        && !get_answer(
            "This is a directory, would you like to erase all files within it?",
            false,
            force,
        )?
    {
        std::process::exit(0);
    }

    if file.is_dir() {
        domain::erase_dir::execute(
            stor,
            domain::erase_dir::Request {
                entry: file,
                passes,
            },
        )?;
    } else {
        domain::erase::execute(
            stor,
            domain::erase::Request {
                path: input,
                passes,
            },
        )?;
    }

    Ok(())
}
