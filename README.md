<p align="center">
<!-- product name logo -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/zama-ai/tfhe-rs/assets/157474013/5283e0ba-da1e-43af-9f2a-c5221367a12b">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/zama-ai/tfhe-rs/assets/157474013/b94a8c96-7595-400b-9311-70765c706955">
  <img width=600 alt="Zama TFHE-rs">
</picture>
</p>

<hr/>

<p align="center">
  <a href="https://github.com/zama-ai/tfhe-rs-handbook/blob/main/tfhe-rs-handbook.pdf"> 📃 Read Handbook</a> |<a href="https://docs.zama.org/tfhe-rs"> 📒 Documentation</a> | <a href="https://www.zama.org/community-channels"> 💛 Community support</a> | <a href="https://github.com/zama-ai/awesome-zama"> 📚 FHE resources by Zama</a>
</p>


<p align="center">
  <a href="https://github.com/zama-ai/tfhe-rs/releases"><img src="https://img.shields.io/github/v/release/zama-ai/tfhe-rs?style=flat-square"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-BSD--3--Clause--Clear-%23ffb243?style=flat-square"></a>
  <a href="https://github.com/zama-ai/bounty-program"><img src="https://img.shields.io/badge/Contribute-Zama%20Bounty%20Program-%23ffd208?style=flat-square"></a>
  <a href="https://slsa.dev"><img alt="SLSA 3" src="https://slsa.dev/images/gh-badge-level3.svg" /></a>
</p>

## About

### What is TFHE-rs

**TFHE-rs** is a pure Rust implementation of TFHE for boolean and integer arithmetics over encrypted data.

It includes:
- a **Rust** API
- a **C** API
- and a **client-side WASM** API

TFHE-rs is designed for developers and researchers who want full control over
what they can do with TFHE, while not having to worry about the low-level
implementation. The goal is to have a stable, simple, high-performance, and
production-ready library for all the advanced features of TFHE.
<br></br>

### Main features

- **Low-level cryptographic library** that implements Zama’s variant of TFHE, including programmable bootstrapping
- **Implementation of the original TFHE boolean API** that can be used as a drop-in replacement for other TFHE libraries
- **Short integer API** that enables exact, unbounded FHE integer arithmetics with up to 8 bits of message space
- **Size-efficient public key encryption**
- **Ciphertext and server key compression** for efficient data transfer
- **Full Rust API, C bindings to the Rust High-Level API, and client-side JavaScript API using WASM**.

*Learn more about TFHE-rs features in the [documentation](https://docs.zama.org/tfhe-rs).*
<br></br>

## Table of Contents
- **[Getting started](#getting-started)**
   - [Cargo.toml configuration](#cargotoml-configuration)
   - [A simple example](#a-simple-example)
- **[Resources](#resources)**
   - [TFHE deep dive](#tfhe-deep-dive)
   - [Tutorials](#tutorials)
   - [Documentation](#documentation)
- **[Working with TFHE-rs](#working-with-tfhe-rs)**
   - [Disclaimers](#disclaimers)
   - [Citations](#citations)
   - [Contributing](#contributing)
   - [License](#license)
- **[Support](#support)**
<br></br>

## Getting started

> [!Important]
> **TFHE-rs** released its first stable version v1.0.0 in February 2025, stabilizing the high-level API for the x86 CPU backend.

### Cargo.toml configuration
To use the latest version of `TFHE-rs` in your project, you first need to add it as a dependency in your `Cargo.toml`:

```toml
tfhe = { version = "*", features = ["boolean", "shortint", "integer"] }
```

> [!Note]
> Note: You need Rust version 1.91.1 or newer to compile TFHE-rs. You can check your version with `rustc --version`.

> [!Note]
> Note: AArch64-based machines are not supported for Windows as it's currently missing an entropy source to be able to seed the [CSPRNGs](https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator) used in TFHE-rs.

<p align="right">
  <a href="#about" > ↑ Back to top </a>
</p>

### A simple example

Here is a full example:

``` rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32, FheUint8};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Basic configuration to use homomorphic integers
    let config = ConfigBuilder::default().build();

    // Key generation
    let (client_key, server_keys) = generate_keys(config);

    let clear_a = 1344u32;
    let clear_b = 5u32;
    let clear_c = 7u8;

    // Encrypting the input data using the (private) client_key
    // FheUint32: Encrypted equivalent to u32
    let mut encrypted_a = FheUint32::try_encrypt(clear_a, &client_key)?;
    let encrypted_b = FheUint32::try_encrypt(clear_b, &client_key)?;

    // FheUint8: Encrypted equivalent to u8
    let encrypted_c = FheUint8::try_encrypt(clear_c, &client_key)?;

    // On the server side:
    set_server_key(server_keys);

    // Clear equivalent computations: 1344 * 5 = 6720
    let encrypted_res_mul = &encrypted_a * &encrypted_b;

    // Clear equivalent computations: 6720 >> 5 = 210
    encrypted_a = &encrypted_res_mul >> &encrypted_b;

    // Clear equivalent computations: let casted_a = a as u8;
    let casted_a: FheUint8 = encrypted_a.cast_into();

    // Clear equivalent computations: min(210, 7) = 7
    let encrypted_res_min = &casted_a.min(&encrypted_c);

    // Operation between clear and encrypted data:
    // Clear equivalent computations: 7 & 1 = 1
    let encrypted_res = encrypted_res_min & 1_u8;

    // Decrypting on the client side:
    let clear_res: u8 = encrypted_res.decrypt(&client_key);
    assert_eq!(clear_res, 1_u8);

    Ok(())
}
```

To run this code, use the following command:
<p align="center"> <code> cargo run --release </code> </p>

> [!Note]
> Note that when running code that uses `TFHE-rs`, it is highly recommended
to run in release mode with cargo's `--release` flag to have the best performance possible.

*Find an example with more explanations in [this part of the documentation](https://docs.zama.org/tfhe-rs/get-started/quick-start)*

<p align="right">
  <a href="#about" > ↑ Back to top </a>
</p>



## Resources

### TFHE-rs Handbook
A document containing scientific and technical details about algorithms implemented into the library is available here: [TFHE-rs: A (Practical) Handbook](https://github.com/zama-ai/tfhe-rs-handbook/blob/main/tfhe-rs-handbook.pdf).

### TFHE deep dive
- [TFHE Deep Dive - Part I - Ciphertext types](https://www.zama.org/post/tfhe-deep-dive-part-1)
- [TFHE Deep Dive - Part II - Encodings and linear leveled operations](https://www.zama.org/post/tfhe-deep-dive-part-2)
- [TFHE Deep Dive - Part III - Key switching and leveled multiplications](https://www.zama.org/post/tfhe-deep-dive-part-3)
- [TFHE Deep Dive - Part IV - Programmable Bootstrapping](https://www.zama.org/post/tfhe-deep-dive-part-4)
<br></br>

### Tutorials
- [Video tutorial: Implement signed integers using TFHE-rs](https://www.zama.org/post/video-tutorial-implement-signed-integers-sing-tfhe-rs)
- [Homomorphic parity bit](https://docs.zama.org/tfhe-rs/tutorials/parity-bit)
- [Homomorphic case changing on Ascii string](https://docs.zama.org/tfhe-rs/tutorials/ascii-fhe-string)
- [Boolean SHA256 with TFHE-rs](https://www.zama.org/post/boolean-sha256-tfhe-rs)
- [Dark market with TFHE-rs](https://www.zama.org/post/dark-market-tfhe-rs)
- [Regular expression engine with TFHE-rs](https://www.zama.org/post/regex-engine-tfhe-rs)

*Explore more useful resources in [TFHE-rs tutorials](https://docs.zama.org/tfhe-rs/tutorials) and [Awesome Zama repo](https://github.com/zama-ai/awesome-zama)*
<br></br>
### Documentation

Full, comprehensive documentation is available here: [https://docs.zama.org/tfhe-rs](https://docs.zama.org/tfhe-rs).
<p align="right">
  <a href="#about" > ↑ Back to top </a>
</p>


## Working with TFHE-rs

### Disclaimers

#### Security estimation

Security estimations are done using the
[Lattice Estimator](https://github.com/malb/lattice-estimator)
with `red_cost_model = reduction.RC.BDGL16`.

When a new update is published in the Lattice Estimator, we update parameters accordingly.

### Security model

By default, the parameter sets used in the High-Level API have a failure probability $\le 2^{-128}$ to securely work in the IND-CPA^D model using the algorithmic techniques provided in our code base [1].
If you want to work within the IND-CPA security model, which is less strict than the IND-CPA-D model, the parameter sets can easily be changed and would have slightly better performance. More details can be found in the [TFHE-rs documentation](https://docs.zama.org/tfhe-rs).

[1] Bernard, Olivier, et al. "Drifting Towards Better Error Probabilities in Fully Homomorphic Encryption Schemes". https://eprint.iacr.org/2024/1718.pdf

[2] Li, Baiyu, et al. "Securing approximate homomorphic encryption using differential privacy." Annual International Cryptology Conference. Cham: Springer Nature Switzerland, 2022. https://eprint.iacr.org/2022/816.pdf

#### Side-channel attacks

Mitigation for side-channel attacks has not yet been implemented in TFHE-rs,
and will be released in upcoming versions.
<br></br>

### Citations
To cite TFHE-rs in academic papers, please use the following entry:

```text
@Misc{TFHE-rs,
  title={{TFHE-rs: A Pure Rust Implementation of the TFHE Scheme for Boolean and Integer Arithmetics Over Encrypted Data}},
  author={Zama},
  year={2022},
  note={\url{https://github.com/zama-ai/tfhe-rs}},
}
```

### Contributing

There are two ways to contribute to TFHE-rs:

- [Open issues](https://github.com/zama-ai/tfhe-rs/issues/new/choose) to report bugs and typos, or to suggest new ideas
- Request to become an official contributor by emailing [hello@zama.org](mailto:hello@zama.org).

Becoming an approved contributor involves signing our Contributor License Agreement (CLA). Only approved contributors can send pull requests, so please make sure to get in touch before you do!
<br></br>

### License
This software is distributed under the **BSD-3-Clause-Clear** license. Read [this](LICENSE) for more details.

#### FAQ
**Is Zama’s technology free to use?**
>Zama’s libraries are free to use under the BSD 3-Clause Clear license only for development, research, prototyping, and experimentation purposes. However, for any commercial use of Zama's open source code, companies must purchase Zama’s commercial patent license.
>
>Everything we do is open source and we are very transparent on what it means for our users, you can read more about how we monetize our open source products at Zama in [this blogpost](https://www.zama.org/post/open-source).

**What do I need to do if I want to use Zama’s technology for commercial purposes?**
>To commercially use Zama’s technology you need to be granted Zama’s patent license. Please contact us hello@zama.org for more information.

**Do you file IP on your technology?**
>Yes, all Zama’s technologies are patented.

**Can you customize a solution for my specific use case?**
>We are open to collaborating and advancing the FHE space with our partners. If you have specific needs, please email us at hello@zama.org.

<p align="right">
  <a href="#about" > ↑ Back to top </a>
</p>


## Support

<a target="_blank" href="https://community.zama.org">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/zama-ai/tfhe-rs/assets/157474013/08656d0a-3f44-4126-b8b6-8c601dff5380">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/zama-ai/tfhe-rs/assets/157474013/1c9c9308-50ac-4aab-a4b9-469bb8c536a4">
  <img alt="Support">
</picture>
</a>

🌟 If you find this project helpful or interesting, please consider giving it a star on GitHub! Your support helps to grow the community and motivates further development.

<p align="right">
  <a href="#about" > ↑ Back to top </a>
</p>
