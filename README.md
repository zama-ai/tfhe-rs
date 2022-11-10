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

`TFHE.rs` implements Zama's variant of
[TFHE](https://eprint.iacr.org/2018/421.pdf). In a nutshell,
[fully homomorphic encryption (FHE)](https://en.wikipedia.org/wiki/Homomorphic_encryption), allows
you to perform computations over encrypted data, allowing you to implement Zero Trust services.

TFHE.rs is based on the
[Learning With Errors (LWE)](https://cims.nyu.edu/~regev/papers/lwesurvey.pdf) and the
[Ring Learning With Errors (RLWE)](https://eprint.iacr.org/2012/230.pdf) problems, which are well
studied cryptographic hardness assumptions believed to be secure even against quantum computers.

## Links

- [documentation](https://docs.zama.ai/thfe)
- [whitepaper](http://whitepaper.zama.ai)
- [community website](https://community.zama.ai)

## Installation

See [here](tfhe/docs/getting_started/installation.md)


## Getting Started

To use `TFHE.rs` in your project, you first need to add it as a dependency in your `Cargo.toml`:

```toml
tfhe = { version = "0.1.0", features = [ "boolean","shortint","x86_64-unix" ] }
```

Here is a full example using ``tfhe::shortint``

```rust
use tfhe::shortint::prelude::*;

fn main() {
    // We generate a set of client/server keys, using the default parameters:
    let (client_key, server_key) = gen_keys(Parameters::default());

    let msg1 = 1;
    let msg2 = 0;

    let modulus = client_key.parameters.message_modulus.0;

    // We use the client key to encrypt two messages:
    let ct_1 = client_key.encrypt(msg1);
    let ct_2 = client_key.encrypt(msg2);

    // We use the server public key to execute an integer circuit:
    let ct_3 = server_key.unchecked_add(&ct_1, &ct_2);

    // We use the client key to decrypt the output of the circuit:
    let output = client_key.decrypt(&ct_3);
    assert_eq!(output, (msg1 + msg2) % modulus as u64);
}
```

Another example of how the library can be used to evaluate a Boolean circuit:

```rust
use tfhe::boolean::prelude::*;

fn main() {
// We generate a set of client/server keys, using the default parameters:
    let (mut client_key, mut server_key) = gen_keys();

// We use the client secret key to encrypt two messages:
    let ct_1 = client_key.encrypt(true);
    let ct_2 = client_key.encrypt(false);

// We use the server public key to execute a boolean circuit:
// if ((NOT ct_2) NAND (ct_1 AND ct_2)) then (NOT ct_2) else (ct_1 AND ct_2)
    let ct_3 = server_key.not(&ct_2);
    let ct_4 = server_key.and(&ct_1, &ct_2);
    let ct_5 = server_key.nand(&ct_3, &ct_4);
    let ct_6 = server_key.mux(&ct_5, &ct_3, &ct_4);

// We use the client key to decrypt the output of the circuit:
    let output = client_key.decrypt(&ct_6);
    assert_eq!(output, true);
}
```

## Contributing

There are two ways to contribute to TFHE.rs:

- you can open issues to report bugs or typos and to suggest new ideas
- you can ask to become an official contributor by emailing [hello@zama.ai](mailto:hello@zama.ai).
(becoming an approved contributor involves signing our Contributor License Agreement (CLA))

Only approved contributors can send pull requests, so please make sure to get in touch before you do!

## Citing Concrete

TODO

## Credits

This library uses several dependencies and we would like to thank the contributors of those
libraries.

## License

This software is distributed under the BSD-3-Clause-Clear license. If you have any questions,
please contact us at `hello@zama.ai`.

## Disclaimers

### Security Estimation

Security estimations are done using the 
[Lattice Estimator](https://github.com/malb/lattice-estimator)
with `red_cost_model = reduction.RC.BDGL16`.

When a new update is published in the Lattice Estimator, we update parameters accordingly.

### Side-Channel Attacks

Mitigation for side channel attacks have not yet been implemented in TFHE.rs,
and will be released in upcoming versions.
