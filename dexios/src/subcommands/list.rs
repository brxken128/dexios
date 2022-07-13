use anyhow::Result;

use dexios_core::primitives::{ALGORITHMS, Algorithm};

// this just lists values contained within arrays
pub fn show_values(input: &str) -> Result<()> {
    match input.to_lowercase().as_str() {
        "aead" => {
            println!("Here are all possible AEADs you can select:");
            for (i, algorithm) in ALGORITHMS.iter().enumerate() {
                if algorithm == &Algorithm::DeoxysII256 { // this is temporary, until deoxys is improved upstream
                    continue;
                }
                println!("{} => {}", (i + 1), algorithm);
            }
        }
        _ => return Err(anyhow::anyhow!(format!("Item \"{}\" not found", input))),
    }

    Ok(())
}
