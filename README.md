# Dexios

- [Dexios](#dexios)
  - [What is it?](#what-is-it)
  - [Building notes](#building-notes)
  - [Checksums](#checksums)
    - [Performance](#performance)
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

## Checksums

Hashing mode uses `Blake3` for verification, due to it's speed, security and regular updates. (very ideal for this use case).

This was originally `sha3-512` in versions 3.x.x and below, and was `KangarooTwelve` in 4.x.x (via the `tiny_keccak` crate) but since v5 it has been changed to Blake3 for a number of reasons. The `tiny_keccak` crate hasn't received updates in a long while, and is no longer actively maintained. The `k12` crate is ideal for this situation, but it is rather immature compared to some other hashing implementations, so `Blake3` will be our main hashing algorithm, and there are no plans to change this as of yet.

Blake3 also offered some *marginal* performance benefits, but this could be due to a number of factors.

### Performance

Tests were ran on a system with a Ryzen 7 3700x and 16gb of 3000MHz RAM - running Void Linux. The file used was originally 3.5GiB, and it was stored on a Cruicial MX500 SSD.

The time was determined via `/usr/bin/time -f "%e"`

| Version     | -esyk       | -dsyk       |
| ----------- | ----------- | ----------- |
| 3.2.8       | 44.37s      | 40.91s      |
| 4.0.0       | 23.70s      | 30.43s      |
| 5.0.0       | 22.48s      | 28.66s      |

## Usage Examples

To encrypt a file, and show the hash of the encrypted (output) file for verification later on:

`dexios -es test.txt test.enc`

To decrypt a file, and show the hash of the encrypted file beforehand (to compare with the hash generated above):

`dexios -ds test.enc test.txt`

To encrypt a file, and erase the original file:

`dexios -e --erase test.txt test.enc`

To use a keyfile for encryption:

`dexios -ek keyfile test.txt test.enc`

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
  - [ ] Find a way to encrypt **large** files (larger than the system's memory) - this is just another optimisation though
  - [x] Optimise memory usage in general too