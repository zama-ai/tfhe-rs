# Concrete CSPRNG

This crate contains a fast *Cryptographically Secure Pseudoramdon Number Generator*, used in the
['concrete-core'](https://crates.io/crates/concrete-core) library, you can find it [here](../concrete-core/) in this repo.

The implementation is based on the AES blockcipher used in CTR mode, as described in the ISO/IEC
18033-4 standard.

Two implementations are available, an accelerated one on x86_64 CPUs with the `aes` feature and the `sse2` feature, and a pure software one that can be used on other platforms.

The crate also makes two seeders available, one needing the x86_64 feature `rdseed` and another one based on the Unix random device `/dev/random` the latter requires the user to provide a secret.

## Running the benchmarks

To execute the benchmarks on an x86_64 platform:
```shell
RUSTFLAGS="-Ctarget-cpu=native" cargo bench --features=seeder_x86_64_rdseed,generator_x86_64_aesni 
```

## License

This software is distributed under the BSD-3-Clause-Clear license. If you have any questions,
please contact us at `hello@zama.ai`.
