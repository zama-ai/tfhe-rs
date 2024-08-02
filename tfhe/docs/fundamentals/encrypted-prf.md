# Generate encrypted pseudo random values

This document explains the mechanism and steps to generate an oblivious encrypted random value using only server keys.

The goal is to give to the server the possibility to generate a random value, which will be obtained in a encrypted format and will remain unknown to the server. The implementation is based on [this article](https://eprint.iacr.org/2024/665).

In *TFHE-rs*, this is possible through the method `generate_oblivious_pseudo_random` of `FheUint` and `FheInt`.
It relies on the use of the usual server keys.
The method takes two inputs: a seed `Seed`, which could be any `u128` value and an upper bound on the range of the random values `random_bits_count`. 
It outputs a `FheIntN` or `FheUintN`, where `N` is the number of bits of the homomorphic integer. 
The output is reproducible, i.e., the method is deterministic from the inputs: assuming the same hardware, seed and server key, this method outputs the same random encrypted value.

More in details, these are the possibilities depending on the output type and the on the specification used:
- a `FheUint_N` taken uniformly in `[0; 2^random_bits_count[` for any `random_bits_count <= N`
- a `FheInt_N` taken uniformly in `[0; 2^random_bits_count[` for any `random_bits_count <= N - 1` 
- a `FheInt_N` taken uniformly in its full range ([-2^N; 2^N[).

Here is an example of the usage:


```rust
use tfhe::prelude::FheDecrypt;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8, FheInt8, SignedRandomizationSpec, Seed};

pub fn main() {
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let random_bits_count = 3;

    // You can pass a 128 bits Seed here
    let ct_res = FheUint8::generate_oblivious_pseudo_random(Seed(0), random_bits_count);
    // The generated values will always be the same for a given server key
    // The server cannot know what value was generated

    let dec_result: u8 = ct_res.decrypt(&client_key);
    assert!(dec_result < (1 << random_bits_count));

    let ct_res = FheInt8::generate_oblivious_pseudo_random(Seed(0), SignedRandomizationSpec::Unsigned { random_bits_count });

    let dec_result: i8 = ct_res.decrypt(&client_key);
    assert!(dec_result < (1 << random_bits_count));


    let ct_res = FheInt8::generate_oblivious_pseudo_random(Seed(0), SignedRandomizationSpec::FullSigned);

    let dec_result: i8 = ct_res.decrypt(&client_key);
}
```
