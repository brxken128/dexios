# Dexios

## What is it?

Dexios is a command-line file encryption utility, suitable for encrypting files before uploading them to a cloud-service. It is written entirely in rust and contains no unsafe code (some dependencies may contain unsafe code, but they have received the correct audits and are deemed secure).

It uses `AES-256-GCM` encryption with 122880 iterations of `PBKDF2_HMAC_SHA512` to generate the encryption key.

It has been tested on Void Linux, but more platforms will be tested in the future.

## To Do

- [x] Error handling
- [x] Ensure the encryption and decryption functions are air-tight
- [ ] Add a secure-erase function for the input/source file
- [ ] Run some more tests, specifically on large files
- [ ] Test keyfile functionality
- [ ] Don't show stdin text when entering password inside of the terminal
- [ ] Add checks for output files so we don't overwrite any by mistake