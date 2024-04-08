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
  <a href="https://docs.zama.ai/tfhe-rs"> 📒 Documentation</a> | <a href="https://zama.ai/community"> 💛 Community support</a> | <a href="https://github.com/zama-ai/awesome-zama"> 📚 FHE resources by Zama</a>
</p>


<p align="center">
  <a href="https://github.com/zama-ai/tfhe-rs/releases"><img src="https://img.shields.io/github/v/release/zama-ai/tfhe-rs?style=flat-square"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-BSD--3--Clause--Clear-%23ffb243?style=flat-square"></a>
  <a href="https://github.com/zama-ai/bounty-program"><img src="https://img.shields.io/badge/Contribute-Zama%20Bounty%20Program-%23ffd208?style=flat-square"></a>
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
- **Full Rust API, C bindings to the Rust High-Level API, and client-side Javascript API using WASM**.

*Learn more about TFHE-rs features in the [documentation](https://docs.zama.ai/tfhe-rs/readme).*
<br></br>

## Table of Contents
- **[Getting Started](#getting-started)**
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

## Getting Started

### Cargo.toml configuration
To use the latest version of `TFHE-rs` in your project, you first need to add it as a dependency in your `Cargo.toml`:

+ For x86_64-based machines running Unix-like OSes:

```toml
tfhe = { version = "*", features = ["boolean", "shortint", "integer", "x86_64-unix"] }
```

+ For Apple Silicon or aarch64-based machines running Unix-like OSes:

```toml
tfhe = { version = "*", features = ["boolean", "shortint", "integer", "aarch64-unix"] }
```

+ For x86_64-based machines with the [`rdseed instruction`](https://en.wikipedia.org/wiki/RDRAND) running Windows:

```toml
tfhe = { version = "*", features = ["boolean", "shortint", "integer", "x86_64"] }
```

> [!Note]
> Note: You need to use a Rust version >= 1.73 to compile TFHE-rs.

> [!Note]
> Note: aarch64-based machines are not yet supported for Windows as it's currently missing an entropy source to be able to seed the [CSPRNGs](https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator) used in TFHE-rs.

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
to run in release mode with cargo's `--release` flag to have the best performances possible.

*Find an example with more explanations in [this part of the documentation](https://docs.zama.ai/tfhe-rs/getting-started/quick_start)*

<p align="right">
  <a href="#about" > ↑ Back to top </a> 
</p>



## Resources 

### TFHE deep dive
- [TFHE Deep Dive - Part I - Ciphertext types](https://www.zama.ai/post/tfhe-deep-dive-part-1)
- [TFHE Deep Dive - Part II - Encodings and linear leveled operations](https://www.zama.ai/post/tfhe-deep-dive-part-2)
- [TFHE Deep Dive - Part III - Key switching and leveled multiplications](https://www.zama.ai/post/tfhe-deep-dive-part-3)
- [TFHE Deep Dive - Part IV - Programmable Bootstrapping](https://www.zama.ai/post/tfhe-deep-dive-part-4)
<br></br>

### Tutorials
- [[Video tutorial] Implement signed integers using TFHE-rs ](https://www.zama.ai/post/video-tutorial-implement-signed-integers-ssing-tfhe-rs)
- [Homomorphic parity bit](https://docs.zama.ai/tfhe-rs/tutorials/parity_bit)
- [Homomorphic case changing on Ascii string](https://docs.zama.ai/tfhe-rs/tutorials/ascii_fhe_string)
- [Boolean SHA256 with TFHE-rs](https://www.zama.ai/post/boolean-sha256-tfhe-rs)
- [Dark market with TFHE-rs](https://www.zama.ai/post/dark-market-tfhe-rs)
- [Regular expression engine with TFHE-rs](https://www.zama.ai/post/regex-engine-tfhe-rs)

*Explore more useful resources in [TFHE-rs tutorials](https://docs.zama.ai/tfhe-rs/tutorials) and [Awesome Zama repo](https://github.com/zama-ai/awesome-zama)*
<br></br>
### Documentation

Full, comprehensive documentation is available here: [https://docs.zama.ai/tfhe-rs](https://docs.zama.ai/tfhe-rs).
<p align="right">
  <a href="#about" > ↑ Back to top </a> 
</p>


## Working with TFHE-rs

### Disclaimers

#### Security Estimation

Security estimations are done using the
[Lattice Estimator](https://github.com/malb/lattice-estimator)
with `red_cost_model = reduction.RC.BDGL16`.

When a new update is published in the Lattice Estimator, we update parameters accordingly.

### Security Model

The default parameters for the TFHE-rs library are chosen considering the IND-CPA security model, and are selected with a bootstrapping failure probability fixed at p_error = $2^{-40}$. In particular, it is assumed that the results of decrypted computations are not shared by the secret key owner with any third parties, as such an action can lead to leakage of the secret encryption key. If you are designing an application where decryptions must be shared, you will need to craft custom encryption parameters which are chosen in consideration of the IND-CPA^D security model [1]. 

[1] Li, Baiyu, et al. "Securing approximate homomorphic encryption using differential privacy." Annual International Cryptology Conference. Cham: Springer Nature Switzerland, 2022. https://eprint.iacr.org/2022/816.pdf

#### Side-Channel Attacks

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
- Request to become an official contributor by emailing [hello@zama.ai](mailto:hello@zama.ai).

Becoming an approved contributor involves signing our Contributor License Agreement (CLA). Only approved contributors can send pull requests, so please make sure to get in touch before you do!
<br></br>

### License
This software is distributed under the **BSD-3-Clause-Clear** license. If you have any questions, please contact us at hello@zama.ai.
<p align="right">
  <a href="#about" > ↑ Back to top </a> 
</p>


## Support

<a target="_blank" href="https://community.zama.ai">
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
