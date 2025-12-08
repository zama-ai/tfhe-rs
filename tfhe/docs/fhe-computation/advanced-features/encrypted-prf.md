# Generate encrypted pseudo random values

This document explains the mechanism and steps to generate an oblivious encrypted random value using only server keys.

The goal is to give to the server the possibility to generate a random value, which will be obtained in an encrypted format and will remain unknown to the server.

The main method for this is `FheUint::generate_oblivious_pseudo_random_custom_range` which returns an integer in the given range.
Currently the range can only be in the form `[0, excluded_upper_bound[` with any `excluded_upper_bound` in `[1, 2^64[`
It follows a distribution close to the uniform.

This function guarantees the norm-1 distance (defined as ∆(P,Q) := 1/2 Sum[ω∈Ω] |P(ω) − Q(ω)|)
between the actual distribution and the target uniform distribution will be below the `max_distance` argument (which must be in ]0, 1[).
The higher the distance, the more dissimilar the actual distribution is from the target uniform distribution.

The default value for `max_distance` is `2^-128` if `None` is provided.

Higher values allow better performance but must be considered carefully in the context of their target application as it may have serious unintended consequences.

If the range is a power of 2, the distribution is uniform (for any `max_distance`) and the cost is smaller.


For powers of 2 specifically there are two methods on `FheUint` and `FheInt` (based on [this article](https://eprint.iacr.org/2024/665)): 
- `generate_oblivious_pseudo_random` which return an integer taken uniformly in the full integer range (`[0; 2^N[` for a `FheUintN` and `[-2^(N-1); 2^(N-1)[` for a `FheIntN`).
- `generate_oblivious_pseudo_random_bounded` which return an integer taken uniformly in `[0; 2^random_bits_count[`. For a `FheUintN`, we must have  `random_bits_count <= N`. For a `FheIntN`, we must have  `random_bits_count <= N - 1`.


These method functions take a seed `Seed` as input, which could be any `u128` value.
They rely on the use of the usual server key.
The output is reproducible, i.e., the function is deterministic from the inputs: assuming the same hardware, seed and server key, this function outputs the same random encrypted value.


Here is an example of the usage:


```rust
use tfhe::prelude::FheDecrypt;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8, FheInt8, RangeForRandom, Seed};
use std::num::NonZeroU64;

pub fn main() {
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let excluded_upper_bound = NonZeroU64::new(3).unwrap();
    let range = RangeForRandom::new_from_excluded_upper_bound(excluded_upper_bound);

    // in [0, excluded_upper_bound[ = {0, 1, 2}
    let ct_res = FheUint8::generate_oblivious_pseudo_random_custom_range(Seed(0), &range, None);
    let dec_result: u8 = ct_res.decrypt(&client_key);

    let random_bits_count = 3;

    // in [0, 2^8[
    let ct_res = FheUint8::generate_oblivious_pseudo_random(Seed(0));
    let dec_result: u8 = ct_res.decrypt(&client_key);

    // in [0, 2^random_bits_count[ = [0, 8[
    let ct_res = FheUint8::generate_oblivious_pseudo_random_bounded(Seed(0), random_bits_count);
    let dec_result: u8 = ct_res.decrypt(&client_key);
    assert!(dec_result < (1 << random_bits_count));

    // in [-2^7, 2^7[
    let ct_res = FheInt8::generate_oblivious_pseudo_random(Seed(0));
    let dec_result: i8 = ct_res.decrypt(&client_key);
    
    // in [0, 2^random_bits_count[ = [0, 8[
    let ct_res = FheInt8::generate_oblivious_pseudo_random_bounded(Seed(0), random_bits_count);
    let dec_result: i8 = ct_res.decrypt(&client_key);
    assert!(dec_result < (1 << random_bits_count));
}
```
