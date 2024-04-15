# Generate encrypted pseudo random values

This document gives an example of generating pseudo random values in FHE that are not known by the server.

```rust
use tfhe::prelude::FheDecrypt;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8, Seed};

pub fn main() {
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let random_bits_count = 3;

    // You can pass a 128 bits Seed here
    // The generated values will always be the same for a given server key
    // The server cannot know what value was generated
    let ct_res = FheUint8::generate_oblivious_pseudo_random(Seed(0), random_bits_count);

    let dec_result: u8 = ct_res.decrypt(&client_key);
    assert!(dec_result < (1 << random_bits_count));
}
```
