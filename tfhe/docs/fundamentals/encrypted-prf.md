# Generate encrypted pseudo random values

Server side, it's possible to generate an encryption of a random value which is oblivious to the server.

This takes a seed as input and uses a standard secret key.
The output is reproductible (same seed and server key gives the same output, if the bootstrap is reproductible).

It's possible to generate:
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
