<p align="center">
  <img src="https://github.com/brxken128/dexios/raw/master/assets/long-logo.png" width="320" />
</p>

[![Dexios Tests](https://img.shields.io/github/workflow/status/brxken128/dexios/Dexios%20Tests?label=Dexios%20Tests&style=flat-square)](https://github.com/brxken128/dexios/actions/workflows/dexios-tests.yml)
[![Build and Upload](https://img.shields.io/github/workflow/status/brxken128/dexios/Build%20and%20Upload?style=flat-square)](https://github.com/brxken128/dexios/actions/workflows/cargo-build.yml)
[![Dexios Crate](https://img.shields.io/crates/v/dexios.svg?style=flat-square)](https://lib.rs/crates/dexios)
[![BSD-2-Clause](https://img.shields.io/badge/License-BSD_2--Clause-blue.svg?style=flat-square)](https://opensource.org/licenses/BSD-2-Clause)

## Dexios - What is it?

Dexios is a fast, secure, and open source command-line encryption tool. It's
written entirely in Rust and prioritises security, performance and convenience
the most. It uses modern cryptographic AEADs (XChaCha20-Poly1305 and AES-256-GCM),
with audited backends to ensure the safety and integrity of your data. It's
extremely easy to use Dexios before uploading your files to a
cloud service, to ensure that no prying eyes can read them.

You can install Dexios through cargo, with:

`cargo install dexios`

Or you can download a pre-compiled binary from
[the releases page](https://github.com/brxken128/dexios/releases)!

## Donating

If you like my work, and want to help support the project, feel free to donate!
This is not necessary by any means, so please don't feel obliged to do so.

```
XMR: 84zSGS18aHtT3CZjZUnnWpCsz1wmA5f65G6BXisbrvAiH7PxZpP8GorbdjAQYRtfeiANZywwUPjZcHu8eXJeWdafJQFK46G
BTC: bc1q8x0r7khrfj40qd0zr5xv3t9nl92rz2387pu48u
ETH: 0x9630f95F11dFa8703b71DbF746E5c83A31A3F2DD
```

## Why is the version so high?

We made a lot of (necessary) changes to how Dexios works. In hindsight, earlier
versions should've been v0.x.x, but it's too late for that.

Going forward, starting with version 8, we have zero plans to make any
incompatible changes. The header prepended to the start of each encrypted file
contains a version identifier, and with that, we can be sure to always keep and
maintain support for older versions.

We encourage anyone who used an older version of Dexios to decrypt their files,
update, and re-encrypt at your earliest convenience. This is to ensure that your
files use the new
[header standard](https://brxken128.github.io/dexios/dexios-core/Headers.html).

## Supported Operating Systems

Windows, FreeBSD, Linux, MacOS and Android all are supported by Dexios!

Windows support was added in v8.3.0 - however, there is a catch. When you enter
a password into the terminal, it will not be hidden - we have plans to fix this
in the near future (keyfiles and environment variables still work flawlessly!)
Please [open a Github issue](https://github.com/brxken128/dexios/issues) if you
encounter anything not outlined here.

Android 12 was tested, and Dexios was installed within Termux. Everything is in
working order, but please
[open a Github issue](https://github.com/brxken128/dexios/issues) if you find
something that doesn't work as intended.

You may find notes on installing for specific platforms
[in the documentation!](https://brxken128.github.io/dexios/Installing-and-Building.html)

## Contributing

Contributions are very welcome! You're free to submit a PR and I'll take a look
at it, provide feedback and (most likely) merge it, provided the tests pass.

## Basic Usage

To encrypt a file:

`dexios encrypt secret.txt secret.enc`

And to decrypt that same file:

`dexios decrypt secret.enc secret.txt`

To securely erase a file:

`dexios erase secret.txt`

## The Defaults

The defaults used in Dexios are more than adequate for even the most paranoid of
users.

By running the simple command `dexios -e input.txt output.enc`, you are using
the following:

- `XChaCha20-Poly1305`
- `BLAKE3-Balloon` hashing, with appropriately-hard parameters
- Sensitive data being completely erased from memory
- A tamper-resistant header that is authenticated along with every block of
  encrypted data
- LE31 STREAM encryption

## Update Status

Dexios will receive frequent updates, and they are always tested before being
released.

Version 8.0.0 did make some breaking changes, and we'd like to apologise for
this. The previous headers (containing salt, nonce, etc) were not standardised,
and varied in size from 24 bytes to 40 bytes. With v8.0.0, this has been changed
completely - now each header is the first 64 bytes of the file, and it contains
information such as what mode the file was encrypted in, and which AEAD
algorithm was used. It also contains a version tag, meaning we can update things
while still supporting older files. We apologise for the inconvenience caused.

## Reporting a Vulnerability

Please report any vulnerabilities as a Github issue - we believe all issues
should be known, and they are likely to get resolved very quickly this way.
Thank you.

As an alternative, you may contact `brxken128@tutanota.com`

If you find any vulnerabilities within Dexios, and can provide steps/pointers to
reproduce, please report them. You may do this anonymously via the email above.
I'm afraid I cannot offer any money in return, but I can add you to the list of
contributors (at your request).

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

Please view the [Documentation](https://brxken128.github.io/dexios/) to find all
of the information related to this project.

It receives frequent updates and is the main source of documentation for Dexios.

### Quick Docs Links:

- [Tested Operating Systems](https://brxken128.github.io/dexios/#tested-operating-systems)
- [Performance Benchmarks](https://brxken128.github.io/dexios/Checksums.html#performance)
- [Usage Examples](https://brxken128.github.io/dexios/Usage-Examples.html)
- [Technical Details](https://brxken128.github.io/dexios/technical-details/)
- [Dexios-Core Details](https://brxken128.github.io/dexios/dexios-core/index.html)
