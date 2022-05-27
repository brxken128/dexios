use anyhow::{Result, Ok};

use crate::global::parameters::ALGORITHMS;

pub fn list_values(input: &str) -> Result<()> {
    match input.to_lowercase().as_str() {
        "aead" => {
            println!("Here are all possible AEADs you can select:");
            for i in 0..ALGORITHMS.len() {
                println!("{} => {}", (i+1), ALGORITHMS[i]);
            }
        }
        _ => {
            return Err(anyhow::anyhow!(format!("Item \"{}\" not found", input)))
        }
    }
    
    Ok(())
}