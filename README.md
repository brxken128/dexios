# Dexios

- [Dexios](#dexios)
  - [What is it?](#what-is-it)
  - [Building notes](#building-notes)
  - [Stream Encryption](#stream-encryption)
  - [Checksums](#checksums)
    - [Performance](#performance)
  - [Output file sizes](#output-file-sizes)
  - [Environment Variables](#environment-variables)
  - [Key Inputs](#key-inputs)
  - [Usage Examples](#usage-examples)
  - [To Do](#to-do)

## What is it?

Dexios is a command-line file encryption utility, suitable for encrypting files before uploading them to a cloud-service. It is written entirely in rust and contains no unsafe code (some dependencies may contain unsafe code, but they have received the correct audits and are deemed secure).

It uses `AES-256-GCM` encryption with `argon2id` to generate the encryption key.

It has been tested on Void Linux, but more platforms will be tested in the future.

For securely erasing the file, it's about as good as we will get. It doesn't factor in how the host OS handles things, or the filesystems. It overwrites the file with many random bytes, and then with zeros, before truncating it and "removing" it with the OS.

## Building notes

As mentioned in the [AES-GCM crate docs](https://docs.rs/aes-gcm/latest/aes_gcm/index.html#performance-notes), please enable certain flags while building. For example:

`RUSTFLAGS="-Ctarget-cpu=native -Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"`

Change native to whichever CPU family/model you are going to be running the code on, if it's going to be ran on a different machine.

## Stream Encryption

Stream encryption and decryption are ideal for **large** files - things that won't fit into RAM on their own.

Streaming functions do not support hashing mode, and the argument will be ignored if you pass it. This is due to the file likely not fitting into RAM, which is necessary to calculate the hash.

Files encrypted in streaming mode will need to subsequently be decrypted in streaming mode. **The streaming/non-streaming modes are not interchangable.**

Streaming mode can be enabled with `-s`.

## Checksums

Hashing mode uses `Blake3` for verification, due to it's speed, security and regular updates. (very ideal for this use case).

This was originally `sha3-512` in versions 3.x.x and below, and was `KangarooTwelve` in 4.x.x (via the `tiny_keccak` crate) but since v5 it has been changed to Blake3 for a number of reasons.

The `tiny_keccak` crate hasn't received updates in a long while, and is no longer actively maintained.

The `k12` crate is ideal for this situation - but it is rather immature compared to some other hashing implementations, so `Blake3` will be our main hashing algorithm, and there are no plans to change this as of yet.

Blake3 also offered some *marginal* performance benefits, but this could be due to a number of factors.

### Performance

Tests were ran on a system with a Ryzen 7 3700x and 16gb of 3000MHz RAM - running Void Linux. The file used was originally 3.5GiB, and it was stored on a Cruicial MX500 SSD.

Version 6 removed JSON entirely, and dropped `base64`, which really shows in the performance metrics.

The time was determined via `/usr/bin/time -f "%e"`

| Version     | -eHyk       | -dHyk       |
| ----------- | ----------- | ----------- |
| 3.2.8       | 44.37s      | 40.91s      |
| 4.0.0       | 23.70s      | 30.43s      |
| 5.0.0       | 22.48s      | 28.66s      |
| 5.0.2       | 20.14s      | 21.26s      |
| 5.0.9       | 19.31s      | 18.92s      |
| 6.0.0       | 11.74s      | 11.59s      |

## Output file sizes

In versions 5.x.x and below, the 3.5GiB test file was encrypted at 4.72GiB - this involved a lot of overhead for `base64` and a tiny amount with the JSON.

As of version 6, JSON and `base64` has been dropped entirely. This has reduced the file size down to be *marginally* higher than our 3.5GiB test file (284 bytes higher, to be exact).

## Environment Variables

Dexios can read your key from an environment variable! Just set `DEXIOS_KEY` and it will automatically be detected and used. Due to using different salts and nonces for every encryption, there is no inherent risk in reusing keys - although it's not a good security practice.

## Key Inputs

The priority is as follows:

1. First, Dexios will check for whether or not you have specified a keyfile (via `-k` or `--keyfile`)
2. If no keyfile is detected, it will look for the `DEXIOS_KEY` environment variable
3. If neither of the above are found, you will be shown a prompt to enter a password manually

## Usage Examples

To encrypt a file, and show the hash of the encrypted (output) file for verification later on:

`dexios -eH test.txt test.enc`

To decrypt a file, and show the hash of the encrypted file beforehand (to compare with the hash generated above):

`dexios -dH test.enc test.txt`

To encrypt a file, and erase the original file:

`dexios -e --erase test.txt test.enc`

To use a keyfile for encryption:

`dexios -ek keyfile test.txt test.enc`

To encrypt a **large** file:

`dexios -esk keyfile test.txt test.enc`

To encrypt all `.mp4` files in a directory, we can use `find`. This works a LOT better with a keyfile/environment variable key as you will have to input the password manually each time otherwise. It will append `.enc` to the end of your files. You can remove `-maxdepth 1` to make this run recursively.

`find *.mp4 -type f -maxdepth 1 -exec dexios -eyk keyfile {} {}.enc \;`

To encrypt all `.mp4` files in a directory, and remove the original files once encrypted:

`find *.mp4 -type f -maxdepth 1 -exec dexios -ey --erase -k keyfile {} {}.enc \;`

## To Do

- [x] Error handling
- [x] Ensure the encryption and decryption functions are air-tight
- [x] Add a secure-erase function for the input/source file
- [x] Run some more tests, specifically on large files
- [x] Test keyfile functionality
- [x] Don't show stdin text when entering password inside of the terminal
- [x] Add checks for output files so we don't overwrite any by mistake
- [x] Hash the file before encryption and after decryption, so the user can confirm the data is *exactly* the same
- [x] Use clap subcommands instead of arguments to make it easier to use
- [x] Optimise reading the input/output files, so less disk usage
  - [x] Find a way to encrypt **large** files (larger than the system's memory)
  - [x] Optimise memory usage in general too
- [x] Further optimise the reading and handling of the data, especially in memory.
  - [x] Larger files in `hashing` mode will cause `dexios` to force quit, due to absurdly high memory usage. This is because the data is being copied in memory multiple times, instead of re-using the same buffer. I believe this needs a `Cursor` to resolve, and a patch will be released once I have found the best solution.
- [x] Refactor/split everything into semi-specialised files, to make the codebase more maintainable
- [x] Add benchmarking switch that doesn't write to the disk
- [ ] Manually `zeroize` sensitive data in RAM
- [ ] Add nice error handling for AES-GCM functions
- [x] AES-GCM stream with [StreamLE31](https://docs.rs/aead/latest/aead/stream/struct.StreamLE31.html)
  - [x] Use a clap argument
    - [x] It'll be primarily used for files larger than (system memory/2.2)
- [ ] Unify rng (maybe OsRng?)
- [ ] Add a check for when the keyfile exists, but it has no data
- [ ] Prevent the output file from even being created in bench+stream mode
- [ ] Add print for "encrypting in normal mode"