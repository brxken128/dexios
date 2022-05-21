[![Dexios Tests](https://img.shields.io/github/workflow/status/brxken128/dexios/Dexios%20Tests?label=Dexios%20Tests&style=flat-square)](https://github.com/brxken128/dexios/actions/workflows/dexios-tests.yml) [![Build and Upload](https://img.shields.io/github/workflow/status/brxken128/dexios/Build%20and%20Upload?style=flat-square)](https://github.com/brxken128/dexios/actions/workflows/cargo-build.yml) [![Dexios Crate](https://img.shields.io/crates/v/dexios.svg?style=flat-square)](https://lib.rs/crates/dexios) [![Docs](https://img.shields.io/badge/docs-github%20wiki-blue?style=flat-square)](https://github.com/brxken128/dexios/wiki) [![BSD-2-Clause](https://img.shields.io/badge/License-BSD_2--Clause-blue.svg?style=flat-square)](https://opensource.org/licenses/BSD-2-Clause)

## Dexios - What is it?

Dexios is a fast, secure, and open source command-line encryption tool. It's written entirely in Rust and prioritises security, performance and convenience the most. It uses modern cryptographic algorithms (XChaCha20-Poly1305 and AES-256-GCM), with audited backends to ensure the safety and integrity of your data. It's extremely easy to use Dexios before uploading your files to a cloud service, to ensure that no prying eyes can read them.

You can install Dexios through cargo, with

`cargo install dexios`

Or you can download a pre-compiled binary from [the releases page](https://github.com/brxken128/dexios/releases)!

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

Dexios itself does not have support for encrypting multiple files, but you can do so with the `find` utility:

```
To encrypt all `.mp4` files in a directory, and remove the original files once encrypted:

find *.mp4 -type f -maxdepth 1 -exec dexios -ey --erase -k keyfile {} {}.enc \;

To decrypt all `.mp4.enc` files in a directory, and remove the `.enc` suffix:

find . -type f -iname "*.mp4.enc" -exec sh -c 'dexios -dk keyfile "$0" "${0%.enc}"' {} \;
```

## Update Status

Dexios will receive frequent updates, and they are always tested before being released. Starting with v7.0.0, there should be no breaking changes made to anything - this means your files will be backwards-compatible, and always supported.

## Reporting a Vulnerability

Please report any vulnerabilities as a Github issue - we believe all issues should be known, and they are likely to get resolved very quickly this way. Thank you.

As an alternative, you may contact `brxken128@tutanota.com`

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 7.x.x   | :white_check_mark: |
| 6.x.x   | :white_check_mark: |
| 5.0.x   | :x:                |
| 4.0.x   | :x:                |
| < 4.0   | :x:                |

## More Information

Please view the [Github Wiki](https://github.com/brxken128/dexios/wiki) to find all the information related to this project.

### Quick Wiki Links:

- [Tested Operating Systems](https://github.com/brxken128/dexios/wiki#tested-operating-systems)
- [Performance Benchmarks](https://github.com/brxken128/dexios/wiki/Checksums#performance)
- [Usage Examples](https://github.com/brxken128/dexios/wiki/Usage-Examples)
- [Technical Details](https://github.com/brxken128/dexios/wiki/Technical-Details)
