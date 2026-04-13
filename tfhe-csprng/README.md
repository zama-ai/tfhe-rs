# TFHE-CSPRNG

This crate contains a fast *Cryptographically Secure Pseudorandom Number Generator*, used in the
[TFHE-rs](https://crates.io/crates/tfhe) library, you can find it [here](../tfhe/) in this repo.

The implementation is based on the AES blockcipher used in CTR mode, as described in the ISO/IEC
18033-4 standard.

Two implementations are available, an accelerated one on x86_64 CPUs with the `aes` feature and the `sse2` feature, and a pure software one that can be used on other platforms.

The crate also makes seeders available: one using the x86_64 `rdseed` instruction when present, and one using OS entropy via the `getrandom` crate on Unix-like systems and on Windows (the latter takes a user-supplied secret mixed into the entropy, as documented on the type).

## Running the benchmarks

To execute the benchmarks on an x86_64 platform:
```shell
RUSTFLAGS="-Ctarget-cpu=native" cargo bench
```

## License

This software is distributed under the BSD-3-Clause-Clear license. If you have any questions,
please contact us at `hello@zama.org`.
