[![Dexios Tests](https://img.shields.io/github/workflow/status/brxken128/dexios/Dexios%20Tests?label=Dexios%20Tests&style=flat-square)](https://github.com/brxken128/dexios/actions/workflows/dexios-tests.yml) [![Build and Upload](https://img.shields.io/github/workflow/status/brxken128/dexios/Build%20and%20Upload?style=flat-square)](https://github.com/brxken128/dexios/actions/workflows/cargo-build.yml) [![Dexios Crate](https://img.shields.io/crates/v/dexios.svg?style=flat-square)](https://lib.rs/crates/dexios) [![Docs](https://img.shields.io/badge/docs-github%20wiki-blue?style=flat-square)](https://github.com/brxken128/dexios/wiki) [![BSD-2-Clause](https://img.shields.io/badge/License-BSD_2--Clause-blue.svg?style=flat-square)](https://opensource.org/licenses/BSD-2-Clause)

## Dexios - What is it?

Dexios is a fast, secure, and open source command-line encryption tool. It's written entirely in Rust and prioritises security, performance and convenience the most. It uses modern cryptographic AEADs (XChaCha20-Poly1305, AES-256-GCM, and Deoxys-II-256), with audited backends to ensure the safety and integrity of your data. It's extremely easy to use Dexios before uploading your files to a cloud service, to ensure that no prying eyes can read them.

For notes on Deoxys-II, please see the [Security Notices](https://github.com/brxken128/dexios/wiki#security-notices) section of the Wiki.

You can install Dexios through cargo, with

`RUSTFLAGS="-Ctarget-cpu=native -Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3" cargo install dexios`

The `RUSTFLAGS` tell the rust compiler to optimise the binary for your processor's architecture, and to enable features that will speed up cryptographic functions. It really is a **lot** faster!

Or you can download a pre-compiled binary from [the releases page](https://github.com/brxken128/dexios/releases)!

## Why is the version so high?

We made a lot of (necessary) changes to how Dexios works. In hindsight, earlier versions should've been v0.x.x, but it's too late for that.

Going forward, starting with version 8, we have zero plans to make any incompatible changes. The header prepended to the start of each encrypted file contains a version identifier, and with that, we can be sure to always keep and maintain support for older versions.

We encourage anyone who used an older version of Dexios to decrypt their files, update, and re-encrypt at your earliest convenience. This is to ensure that your files use the new [header standard](https://github.com/brxken128/dexios/wiki/Headers).

## Basic Usage

To encrypt a file:

`dexios encrypt secret.txt secret.enc`

And to decrypt that same file:

`dexios decrypt secret.enc secret.txt`

To securely erase a file:

`dexios erase secret.txt`

Here is a screenshot of Dexios in action! The performance is great (that is a 3.5GiB file), and the checksums match meaning the file is exactly the same as it was before encryption.

![Dexios in action](https://github.com/brxken128/dexios/wiki/assets/dexios-in-action.png)

## Multiple Files

Dexios itself does not have support for encrypting multiple files *individually*, but you can do so with the `find` utility:

```
To encrypt all `.mp4` files in a directory, and remove the original files once encrypted:

find *.mp4 -type f -maxdepth 1 -exec dexios -ey --erase -k keyfile {} {}.enc \;

To decrypt all `.mp4.enc` files in a directory, and remove the `.enc` suffix:

find . -type f -iname "*.mp4.enc" -exec sh -c 'dexios -dk keyfile "$0" "${0%.enc}"' {} \;
```

To "pack" and then encrypt multiple files, you can use:

```
dexios pack encrypt /home/user/Documents documents.enc

and

dexios pack decrypt documents.enc /home/user/Documents

pack decrypt signifies that you are unpacking the encrypted archive
```

## Update Status

Dexios will receive frequent updates, and they are always tested before being released.

Version 8.0.0 did make some breaking changes, and we'd like to apologise for this. The previous headers (containing salt, nonce, etc) we not standardised, and varied in size from 24 bytes to 40 bytes. With v8.0.0, this has been changed completely - now each header is the first 64 bytes of the file, and it contains information such as what mode the file was encrypted in, and which AEAD algorithm was used. It also contains a version tag, meaning we can update things while still supporting older files. We apologise for the inconvenience caused.

## Reporting a Vulnerability

Please report any vulnerabilities as a Github issue - we believe all issues should be known, and they are likely to get resolved very quickly this way. Thank you.

As an alternative, you may contact `brxken128@tutanota.com`

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 8.x.x   | :white_check_mark: |
| 7.x.x   | :white_check_mark: |
| 6.x.x   | :x:                |
| 5.0.x   | :x:                |
| 4.0.x   | :x:                |
| < 4.0   | :x:                |

## More Information

Please view the [Github Wiki](https://github.com/brxken128/dexios/wiki) to find all of the information related to this project.

It receives frequent updates and is the main source of documentation for Dexios.

### Quick Wiki Links:

- [Tested Operating Systems](https://github.com/brxken128/dexios/wiki#tested-operating-systems)
- [Performance Benchmarks](https://github.com/brxken128/dexios/wiki/Checksums#performance)
- [Usage Examples](https://github.com/brxken128/dexios/wiki/Usage-Examples)
- [Technical Details](https://github.com/brxken128/dexios/wiki/Technical-Details)
