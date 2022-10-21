<p align="center">
<!-- product name logo -->
  <img width=600 src="https://user-images.githubusercontent.com/5758427/177340641-f152edb7-1957-49a3-86ab-246774701aab.png">
</p>
<p align="center">
<!-- Version badge using shields.io -->
  <a href="https://github.com/zama-ai/concrete/releases">
    <img src="https://img.shields.io/github/v/release/zama-ai/concrete-ml?style=flat-square">
  </a>
<!-- Link to docs badge using shields.io -->
  <a href="https://docs.zama.ai/concrete">
    <img src="https://img.shields.io/badge/read-documentation-yellow?style=flat-square">
  </a>
<!-- Link to tutorials badge using shields.io -->
  <a href="https://docs.zama.ai/concrete/tutorials">
    <img src="https://img.shields.io/badge/tutorials-and%20demos-orange?style=flat-square">
  </a>
<!-- Community forum badge using shields.io -->
  <a href="https://community.zama.ai">
    <img src="https://img.shields.io/badge/community%20forum-online-brightgreen?style=flat-square">
  </a>
<!-- Open source badge using shields.io -->
  <a href="https://docs.zama.ai/concrete/developer/contributing">
    <img src="https://img.shields.io/badge/we're%20open%20source-contributing.md-blue?style=flat-square">
  </a>
<!-- Follow on twitter badge using shields.io -->
  <a href="https://twitter.com/zama_fhe">
    <img src="https://img.shields.io/twitter/follow/zama_fhe?color=blue&style=flat-square">
  </a>
</p>

The `concrete` ecosystem is a set of crates that implements Zama's variant of
[TFHE](https://eprint.iacr.org/2018/421.pdf). In a nutshell,
[fully homomorphic encryption (FHE)](https://en.wikipedia.org/wiki/Homomorphic_encryption), allows
you to perform computations over encrypted data, allowing you to implement Zero Trust services.

Concrete is based on the
[Learning With Errors (LWE)](https://cims.nyu.edu/~regev/papers/lwesurvey.pdf) and the
[Ring Learning With Errors (RLWE)](https://eprint.iacr.org/2012/230.pdf) problems, which are well
studied cryptographic hardness assumptions believed to be secure even against quantum computers.

## Links

- [documentation](https://docs.zama.ai/concrete)
- [whitepaper](http://whitepaper.zama.ai)
- [community website](https://community.zama.ai)

## Concrete crates

Concrete is implemented using the [Rust Programming language](https://www.rust-lang.org/), which
allows very fast, yet very secure implementations.

The ecosystem is composed of several crates (packages in the Rust language).
The crates are split into 2 repositories:

- The `concrete` repository which contains crates intended to be more approachable by
non-cryptographers.
- The [concrete-core](https://github.com/zama-ai/concrete-core) repository which contains the crates
  implementing the low level cryptographic primitives.

The crates within this repository are:
- [`concrete`](concrete): A high-level library, useful to cryptographers that want to quickly
  implement homomorphic applications, without having to understand the details of the
  jmplementation.
- [`concrete-boolean`](concrete-boolean): A high-level library, implementing homomorphic Boolean gates, making it easy
  to run any kind of circuits over encrypted data.
- [`concrete-shortint`](concrete-shortint): A high-level library, implementing operations on short integers (about 1 to 4 bits).

## Installation

As `concrete` relies on `concrete-core`, `concrete` is only supported on `x86_64 Linux` and `x86_64 macOS`.
Windows users can use `concrete` through the `WSL`. For Installation instructions see [Install.md](INSTALL.md)
or [documentation](https://docs.zama.ai/concrete).

## Getting Started

Here is a simple example of an encrypted addition between two encrypted 8-bit variables. For more
information please read the [documentation](https://docs.zama.ai/concrete).

```rust
use concrete::{ConfigBuilder, generate_keys, set_server_key, FheUint8};
use concrete::prelude::*;

fn main() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_uint8()
        .build();

    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let clear_a = 27u8;
    let clear_b = 128u8;

    let a = FheUint8::encrypt(clear_a, &client_key);
    let b = FheUint8::encrypt(clear_b, &client_key);

    let result = a + b;

    let decrypted_result: u8 = result.decrypt(&client_key);

    let clear_result = clear_a + clear_b;

    assert_eq!(decrypted_result, clear_result);
}
```

## Contributing

There are two ways to contribute to Concrete:

- you can open issues to report bugs or typos and to suggest new ideas
- you can ask to become an official contributor by emailing [hello@zama.ai](mailto:hello@zama.ai).
(becoming an approved contributor involves signing our Contributor License Agreement (CLA))

Only approved contributors can send pull requests, so please make sure to get in touch before you do!

## Citing Concrete

To cite Concrete in academic papers, please use the following entry:

```text
@inproceedings{WAHC:CJLOT20,
  title={CONCRETE: Concrete Operates oN Ciphertexts Rapidly by Extending TfhE},
  author={Chillotti, Ilaria and Joye, Marc and Ligier, Damien and Orfila, Jean-Baptiste and Tap, Samuel},
  booktitle={WAHC 2020--8th Workshop on Encrypted Computing \& Applied Homomorphic Cryptography},
  volume={15},
  year={2020}
}
```

## Credits

This library uses several dependencies and we would like to thank the contributors of those
libraries.

We thank [Daniel May](https://gitlab.com/danieljrmay) for supporting this project and donating the
`concrete` crate.

## License

This software is distributed under the BSD-3-Clause-Clear license. If you have any questions,
please contact us at `hello@zama.ai`.

## Disclaimers

### Security Estimation

Security estimation, in this repository, used to be based on
the [LWE Estimator](https://bitbucket.org/malb/lwe-estimator/src/master/),
with `reduction_cost_model = BKZ.sieve`.
We are currently moving to the [Lattice Estimator](https://github.com/malb/lattice-estimator)
with `red_cost_model = reduction.RC.BDGL16`.

When a new update is published in the Lattice Estimator, we update parameters accordingly.

### Side-Channel Attacks

Mitigation for side channel attacks have not yet been implemented in Concrete,
and will be released in upcoming versions.
