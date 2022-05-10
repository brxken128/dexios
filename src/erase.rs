use anyhow::{Context, Result};
use rand::Rng;
use std::{
    fs::File,
    io::{BufWriter, Write},
    time::Instant,
};

pub fn secure_erase(input: &str) -> Result<()> {
    let start_time = Instant::now();
    let file = File::open(input).context("Unable to open the input file")?;
    let data = file.metadata()?;

    for _ in 0..32 {
        // overwrite the data 16 times with random bytes
        // generate enough random bytes in accordance to data's size
        let mut random_bytes: Vec<u8> = Vec::new();
        for _ in 0..data.len() {
            random_bytes.push(rand::thread_rng().gen::<[u8; 1]>()[0]);
        }

        let file = File::create(input).context("Unable to open the input file")?;
        let mut writer = BufWriter::new(file);
        writer
            .write_all(&random_bytes)
            .context("Unable to overwrite with random bytes")?;
        writer.flush().context("Unable to flush random bytes")?;
    }

    // overwrite with zeros for good measure
    let zeros: Vec<u8> = vec![0; data.len().try_into().unwrap()];
    let file = File::create(input).context("Unable to open the input file")?;
    let mut writer = BufWriter::new(file);
    writer
        .write_all(&zeros)
        .context("Unable to overwrite with zeros")?;
    writer.flush().context("Unable to flush zeros")?;
    drop(writer);

    // keep this at the end
    let file = File::create(input).context("Unable to open the input file")?;
    file.set_len(0).context("Unable to truncate file")?;
    drop(file);

    std::fs::remove_file(input).context("Unable to remove file")?;

    let duration = start_time.elapsed();

    println!(
        "Erased {} successfully [took {:.2}s]",
        input,
        duration.as_secs_f32()
    );

    Ok(())
}
