use anyhow::{Context, Result};
use rand::Rng;
use std::{
    fs::File,
    io::{BufWriter, Write},
    time::Instant,
};

pub fn secure_erase(input: &str) -> Result<()> {
    let start_time = Instant::now();
    let file = File::open(input).with_context(|| format!("Unable to open file: {}", input))?;
    let data = file
        .metadata()
        .with_context(|| format!("Unable to get input file metadata: {}", input))?;
        
    for _ in 0..64 {
        // generate enough random bytes in accordance to data's size
        let mut random_bytes: Vec<u8> = Vec::new();
        for _ in 0..data.len() {
            random_bytes.push(rand::thread_rng().gen::<[u8; 1]>()[0]);
        }

        let file =
            File::create(input).with_context(|| format!("Unable to open file: {}", input))?;
        let mut writer = BufWriter::new(file);
        writer
            .write_all(&random_bytes)
            .with_context(|| format!("Unable to overwrite with random bytes: {}", input))?;
        writer
            .flush()
            .with_context(|| format!("Unable to flush file: {}", input))?;
    }

    // overwrite with zeros for good measure
    let file = File::create(input).with_context(|| format!("Unable to open file: {}", input))?;
    let mut writer = BufWriter::new(file);
    for _ in 0..data.len() {
        writer
            .write(&[0])
            .with_context(|| format!("Unable to overwrite with zeros: {}", input))?;
    }
    writer
        .flush()
        .with_context(|| format!("Unable to flush file: {}", input))?;
    drop(writer);

    // keep this at the end
    let file = File::create(input).context("Unable to open the input file")?;
    file.set_len(0)
        .with_context(|| format!("Unable to truncate file: {}", input))?;
    drop(file);

    std::fs::remove_file(input).with_context(|| format!("Unable to remove file: {}", input))?;

    let duration = start_time.elapsed();

    println!(
        "Erased {} successfully [took {:.2}s]",
        input,
        duration.as_secs_f32()
    );

    Ok(())
}
