<p align="center">
  <img src="https://github.com/brxken128/dexios/raw/master/assets/long-logo.png" width="320" />
</p>

## What is it?

Dexios-Core is a library used for managing cryptographic functions and headers
that adhere to the Dexios format.

## Security

Dexios-Core uses modern, secure and audited<sup>1</sup> AEADs for encryption and
decryption.

You may find the audits for both AES-256-GCM and XChaCha20-Poly1305 on
[the NCC Group's website](https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/).

<sup>1</sup> Deoxys-II-256 does not have an official audit, so use it at your
own risk

## Who uses Dexios-Core?

This library is implemented by [Dexios](https://github.com/brxken128/dexios), a
secure command-line file encryption utility.

Dexios-Core makes it easy to integrate the Dexios format into your own projects
(and if there's a feature that you'd like to see, please don't hesitate to
[open a Github issue](https://github.com/brxken128/dexios-core/issues)). The
[documentation](https://docs.rs/dexios-core/latest/dexios_core/) is packed with
information to help you get started!

## Features

- Convenience functions for encrypting/decrypting
- 3 AEADs (XChaCha20-Poly1305, AES-256-GCM, Deoxys-II-256)
- Easy management of encrypted headers (no more worrying about where to store a
  nonce!)
- Easy `argon2id` hashing with secure parameters
- Easy `balloon` hashing with secure parameters and BLAKE3
- Frequent updates and feature additions!

## Donating

If you like my work, and want to help support Dexios, or Dexios-Core, feel free
to donate! This is not necessary by any means, so please don't feel obliged to
do so.

```
XMR: 84zSGS18aHtT3CZjZUnnWpCsz1wmA5f65G6BXisbrvAiH7PxZpP8GorbdjAQYRtfeiANZywwUPjZcHu8eXJeWdafJQFK46G
BTC: bc1q8x0r7khrfj40qd0zr5xv3t9nl92rz2387pu48u
ETH: 0x9630f95F11dFa8703b71DbF746E5c83A31A3F2DD
```

## Examples

Deserializing a header:

```rust
let header_bytes: [u8; 64] = [
  222, 2, 14, 1, 12, 1, 142, 88, 243, 144, 119, 187, 189, 190, 121, 90, 211, 56, 185, 14, 76,
  45, 16, 5, 237, 72, 7, 203, 13, 145, 13, 155, 210, 29, 128, 142, 241, 233, 42, 168, 243,
  129, 0, 0, 0, 0, 0, 0, 214, 45, 3, 4, 11, 212, 129, 123, 192, 157, 185, 109, 151, 225, 233,
  161,
];

let mut cursor = Cursor::new(header_bytes);

// the cursor may be a file, this is just an example

let (header, aad) = Header::deserialize(&mut cursor).unwrap();
```

Writing a header to a file:

```rust
let mut output_file = File::create("test").unwrap();
header.write(&mut output_file).unwrap();
```

Encrypting and decrypting in-memory:

```rust
// obviously the key should contain data, not be an empty vec
let raw_key = Protected::new(vec![0u8; 128]);
let salt = gen_salt();
let key = balloon_hash(raw_key, &salt, &HeaderVersion::V4).unwrap();
let cipher = Ciphers::initialize(key, &Algorithm::XChaCha20Poly1305).unwrap();

let secret = "super secret information";

let nonce = gen_nonce(&Algorithm::XChaCha20Poly1305, &Mode::MemoryMode);
let encrypted_data = cipher.encrypt(&nonce, secret.as_bytes()).unwrap();

let decrypted_data = cipher.decrypt(&nonce, encrypted_data.as_slice()).unwrap();

assert_eq!(secret, decrypted_data);
```

You can read more about Dexios, Dexios-Core and the technical details
[in the project's main documentation](https://brxken128.github.io/dexios/)!

## Thank you!

Dexios-Core exclusively uses AEADs provided by the
[RustCrypto Team](https://github.com/RustCrypto), so I'd like to give them a
huge thank you for their hard work (this wouldn't have been possible without
them!)
