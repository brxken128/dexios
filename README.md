# Dexios

## What is it?

Dexios is a command-line file encryption utility, suitable for encrypting files before uploading them to a cloud-service. It is written entirely in rust and contains no unsafe code (some dependencies may contain unsafe code, but they have received the correct audits and are deemed secure).

It uses `AES-256-GCM` encryption with 122880 iterations of `PBKDF2_HMAC_SHA512` to generate the encryption key.

It has been tested on Void Linux, but more platforms will be tested in the future.

For securely erasing the file, it's about as good as we will get. It doesn't factor in how the host OS handles things, or the filesystems. It overwrites the file with many random bytes, and then with zeros, before truncating it and "removing" it with the OS.

## Usage Examples

To encrypt a file, and show the hash of the original (input) file for verification later on:

`dexios -es test.txt test.enc`

To decrypt a file, and show the hash of the decrypted file (to compare with the hash generated above):

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
- [ ] Optimise reading the input/output files, so less disk usage
  - [ ] Find a way to encrypt **large** files (larger than the system's memory) - this is just another optimisation though
  - [ ] Optimise memory usage in general too