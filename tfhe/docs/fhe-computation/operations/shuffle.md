# Shuffle

This document details the shuffle operation supported by **TFHE-rs**.

| name            | symbol            | type  |
|-----------------|-------------------|-------|
| Bitonic shuffle | `bitonic_shuffle` | Unary |

`bitonic_shuffle` shuffles a `Vec` of encrypted integers into an uniformly random
order. Internally, it generates random sort keys via an OPRF;
`BitonicShuffleKeySize` controls the bit-width of the keys used,
either by a target collision probability or a raw bit count.

Collision probability is the recommended parameter as it adapts the bit-width to the number of
elements to be shuffled.

The following example shuffles a small deck of cards:

```rust
use tfhe::prelude::*;
use tfhe::integer::server_key::BitonicShuffleKeySize;
use tfhe::{bitonic_shuffle, generate_keys, set_server_key, ConfigBuilder, FheUint8, Seed};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    set_server_key(server_key);

    // A small deck of cards numbered 1..=10
    let deck: Vec<FheUint8> = (1u8..=10)
        .map(|v| FheUint8::encrypt(v, &client_key))
        .collect();

    // Target a collision probability of 2^-40 for the internal sort keys
    let key_size = BitonicShuffleKeySize::collision_probability(2f64.powi(-40));
    let shuffled = bitonic_shuffle(deck, key_size, Seed(0))?;

    let drawn: Vec<u8> = shuffled.iter().map(|c| c.decrypt(&client_key)).collect();

    let mut sorted = drawn.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, (1u8..=10).collect::<Vec<_>>());

    Ok(())
}
```
