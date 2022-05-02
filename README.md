# Dexios

## What is it?

Dexios is a command-line file encryption utility, suitable for encrypting files before uploading them to a cloud-service. It is written entirely in rust and contains no unsafe code (some dependencies may contain unsafe code, but they have received the correct audits and are deemed secure).

It uses `AES-256-GCM` encryption with 122880 iterations of `PBKDF2_HMAC_SHA512` to generate the encryption key.

It has been tested on Void Linux, but more platforms will be tested in the future.

For securely erasing the file, it's about as good as we will get. It doesn't factor in how the host OS handles things, or the filesystems. It overwrites the file with many random bytes, and then with zeros, before truncating it and "removing" it with the OS.

## To Do

- [x] Error handling
- [x] Ensure the encryption and decryption functions are air-tight
- [x] Add a secure-erase function for the input/source file
- [x] Run some more tests, specifically on large files
- [x] Test keyfile functionality
- [x] Don't show stdin text when entering password inside of the terminal
- [x] Add checks for output files so we don't overwrite any by mistake
- [x] Hash the file before encryption and after decryption, so the user can confirm the data is *exactly* the same
- [ ] HMAC signing