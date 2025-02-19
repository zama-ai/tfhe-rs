# Generate encrypted pseudo random values

This document explains the mechanism and steps to generate an oblivious encrypted random value using only server keys.

The goal is to give to the server the possibility to generate a random value, which will be obtained in an encrypted format and will remain unknown to the server. The implementation is based on [this article](https://eprint.iacr.org/2024/665).

This is possible through two methods on `FheUint` and `FheInt`: 
- `generate_oblivious_pseudo_random` which return an integer taken uniformly in the full integer range (`[0; 2^N[` for a `FheUintN` and `[-2^(N-1); 2^(N-1)[` for a `FheIntN`).
- `generate_oblivious_pseudo_random_bounded` which return an integer taken uniformly in `[0; 2^random_bits_count[`. For a `FheUintN`, we must have  `random_bits_count <= N`. For a `FheIntN`, we must have  `random_bits_count <= N - 1`.

Both methods functions take a seed `Seed` as input, which could be any `u128` value.
They both rely on the use of the usual server key.
The output is reproducible, i.e., the function is deterministic from the inputs: assuming the same hardware, seed and server key, this function outputs the same random encrypted value.


Here is an example of the usage:


```rust
use tfhe::prelude::FheDecrypt;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8, FheInt8, Seed};

pub fn main() {
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let random_bits_count = 3;

    let ct_res = FheUint8::generate_oblivious_pseudo_random(Seed(0));

    let dec_result: u8 = ct_res.decrypt(&client_key);

    let ct_res = FheUint8::generate_oblivious_pseudo_random_bounded(Seed(0), random_bits_count);

    let dec_result: u8 = ct_res.decrypt(&client_key);
    assert!(dec_result < (1 << random_bits_count));

    let ct_res = FheInt8::generate_oblivious_pseudo_random(Seed(0));
    
    let dec_result: i8 = ct_res.decrypt(&client_key);
    
    let ct_res = FheInt8::generate_oblivious_pseudo_random_bounded(Seed(0), random_bits_count);

    let dec_result: i8 = ct_res.decrypt(&client_key);
    assert!(dec_result < (1 << random_bits_count));
}
```
