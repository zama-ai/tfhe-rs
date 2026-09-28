# Shuffle

This document details the shuffle operation supported by **TFHE-rs**.

`bitonic_shuffle` shuffles a `Vec` of encrypted integers into a random permutation, oblivious to the server.
A random sort key is generated with the [encrypted PRF](../advanced-features/encrypted-prf.md) for each element, and the elements are then sorted by their keys using a bitonic sorting network.

{% hint style="warning" %}
If your usage of **TFHE-rs** falls under the sIND-CPA^D security model described in [Ciphertexts Rerandomization](../advanced-features/rerand.md) then you **must** use `re_randomized_keys_bitonic_shuffle` instead, which re-randomizes the random sort keys generated with the PRF.
This does not re-randomize the elements to shuffle: like any other encrypted input of your FHE program, they must be re-randomized beforehand.
See the [re-randomized shuffle example](../advanced-features/rerand.md#re-randomized-shuffle).
{% endhint %}

## Key size and attacker advantage

If all keys are distinct, the resulting permutation is exactly uniform.
If two keys collide, the deterministic tie-breaking of the sorting network biases the permutation.
The `key_size` argument (a `BitonicShuffleKeySize`) sets the bit-width `k` of the keys: larger keys make collisions less likely, and therefore reduce the bias of the permutation.
For `n` elements:
- `BitonicShuffleKeySize::attacker_advantage(advantage, involved_slot_count)` chooses `k` to bound the *multiplicative* advantage of an attacker: any guess about the shuffle that succeeds with probability `p` against a perfectly uniform permutation succeeds with probability at most `p * (1 + advantage)`.
  - With `involved_slot_count = None`, the bound holds for any attack.
    The advantage is then at most `exp(n(n-1) / (2^k - n + 1)) - 1`, which is approximately `n^2 / 2^k`.
  - With `involved_slot_count = Some(t)`, the bound only covers attacks involving at most `t` slots of the shuffled array: those the attacker observes plus those they try to guess.
    For example, observing `m` slots and guessing one more gives `t = m + 1`.
    The advantage is then at most `7.3 * t * n / 2^k`, which allows much smaller keys when `t` is small compared to `n`.
    This finer bound requires `n >= 8` and `t <= n / 4`; otherwise the `None` bound is used.
  - In both cases the key size is at least `log2(128 * n^2)` bits.
- `BitonicShuffleKeySize::collision_probability(p)` chooses `k` such that the probability of at least one collision (which is below `n^2 / 2^(k+1)`) is at most `p`.
  If your concern is an attacker exploiting collisions to guess the shuffle, use `attacker_advantage` instead.
- `BitonicShuffleKeySize::num_bits(k)` sets `k` directly.
  It gives no guarantee and should only be used if you have done the analysis for your use case.

In all cases, `k` is rounded up to a multiple of the number of message bits of a block.

These bounds hold for a single shuffle: reusing a seed with the same server key reproduces the same permutation.

## Example: card games

In repeated games, such as an online casino, the attacker's advantage does not need to be zero: the game remains economically secure as long as the advantage is much smaller than the house edge, which is typically between 1% and 5%.

Consider a 52-card deck (`n = 52`) and an attacker observing 5 dealt cards and predicting the next one (`t = 6`).
With 32-bit keys (`BitonicShuffleKeySize::num_bits(32)`), the attacker advantage is at most `7.3 * 6 * 52 / 2^32 ≈ 5.3 * 10^-7`, and it is still at most `≈ 5.2 * 10^-6` for a batch of `n = 512` elements.
Both are orders of magnitude below a 1% house edge.
Conversely, `BitonicShuffleKeySize::attacker_advantage(1e-4, NonZeroU32::new(6))` selects 25-bit keys for a 52-card deck (26 bits after rounding up to a multiple of 2 message bits per block).
Here the `None` bound would also give 25 bits, as `7.3 * t` is close to `n`: the gain shows up for larger batches.

## Usage

The following example shuffles a small deck of cards:

```rust
use std::num::NonZeroU32;
use tfhe::prelude::{FheDecrypt, FheEncrypt};
use tfhe::{
    bitonic_shuffle, generate_keys, set_server_key, BitonicShuffleKeySize, ConfigBuilder, FheUint8,
    Seed,
};

pub fn main() {
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    // A small deck of cards numbered 0..8
    let deck: Vec<u8> = (0..8).collect();

    let encrypted: Vec<FheUint8> = deck
        .iter()
        .map(|&v| FheUint8::encrypt(v, &client_key))
        .collect();

    // Attacks involving at most 2 positions of the shuffled deck (observed + guessed)
    // succeed at most 1% more often than against a perfectly uniform shuffle
    let key_size = BitonicShuffleKeySize::attacker_advantage(0.01, NonZeroU32::new(2));

    // DANGER: Static Seed(0) given as an example only
    // use proper seeding strategy depending on use case
    let shuffled = bitonic_shuffle(encrypted, key_size, Seed(0)).unwrap();

    let mut drawn: Vec<u8> = shuffled.iter().map(|ct| ct.decrypt(&client_key)).collect();

    drawn.sort_unstable();
    assert_eq!(drawn, deck);
}
```
