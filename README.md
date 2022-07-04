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
the most. It uses modern cryptographic AEADs (XChaCha20-Poly1305, AES-256-GCM,
and Deoxys-II-256), with audited backends to ensure the safety and integrity of
your data. It's extremely easy to use Dexios before uploading your files to a
cloud service, to ensure that no prying eyes can read them.

For notes on Deoxys-II, please see the
[Security Notices](https://brxken128.github.io/dexios/Introduction.html#security-notices)
section of the Documentation.

You can install Dexios through cargo, with:

`cargo install dexios`

Or you can download a pre-compiled binary from
[the releases page](https://github.com/brxken128/dexios/releases)!

This repo also contains the Dexios-Core library - it's used by Dexios itself for
managing headers and cryptographic functions. This allows us to keep them
isolated, and ensure that security-critical pieces of code remain maintainable.

You may view more information about [Dexios](dexios/README.md) and
[Dexios-Core](dexios-core/README.md) in their respective folders. You can also
[view the documentation](https://brxken128.github.io/dexios/) for the technical
info!

## Donating

If you like my work, and want to help support the project, feel free to donate!
This is not necessary by any means, so please don't feel obliged to do so.

```
XMR: 84zSGS18aHtT3CZjZUnnWpCsz1wmA5f65G6BXisbrvAiH7PxZpP8GorbdjAQYRtfeiANZywwUPjZcHu8eXJeWdafJQFK46G
BTC: bc1q8x0r7khrfj40qd0zr5xv3t9nl92rz2387pu48u
ETH: 0x9630f95F11dFa8703b71DbF746E5c83A31A3F2DD
```
