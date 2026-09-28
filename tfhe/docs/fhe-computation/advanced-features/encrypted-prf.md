# Generate encrypted pseudo random values

{% hint style="warning" %}
If your usage of **TFHE-rs** falls under the sIND-CPA^D security model described in [Ciphertexts Rerandomization](./rerand.md) then you **must** use the re-randomized variants of the PRF APIs.
This includes array shuffling which calls the PRF.
You can check how to use these APIS [here](./rerand.md#re-randomized-prf)
{% endhint %}

This document explains the mechanism and steps to generate an oblivious encrypted random value using only server keys.

The goal is to give to the server the possibility to generate a random value, which will be obtained in an encrypted format and will remain unknown to the server.

The main method for this is `FheUint::generate_oblivious_pseudo_random_custom_range` which returns an integer in the given range.
Currently the range can only be in the form `[0, excluded_upper_bound)` with any `excluded_upper_bound` in `[1, 2^64)`.
It follows a distribution close to the uniform.

This function guarantees the total variation distance (defined as Δ(P,Q) := 1/2 Sum[ω∈Ω] |P(ω) - Q(ω)|)
between the actual distribution and the target uniform distribution will be below the `max_distance` argument (which must be in `(0, 1)`).
The higher the distance, the more dissimilar the actual distribution is from the target uniform distribution.

The default value for `max_distance` is `2^-128` if `None` is provided.

Higher values allow better performance but must be considered carefully in the context of their target application as it may have serious unintended consequences.
See the [roulette game example](#example-roulette-game) for an analysis of the impact of `max_distance` on an application.

## Power of 2 ranges

If the range is a power of 2, the distribution is uniform (for any `max_distance`) and the cost is smaller.

For powers of 2 specifically there are two methods on `FheUint` and `FheInt` (based on [this article](https://eprint.iacr.org/2024/665)): 
- `generate_oblivious_pseudo_random` which return an integer taken uniformly in the full integer range (`[0, 2^N)` for a `FheUintN` and `[-2^(N-1), 2^(N-1))` for a `FheIntN`).
- `generate_oblivious_pseudo_random_bounded` which return an integer taken uniformly in `[0, 2^random_bits_count)`.
  For a `FheUintN`, we must have  `random_bits_count <= N`. For a `FheIntN`, we must have  `random_bits_count <= N - 1`.

## Seed and reproducibility

All the methods above take a seed as input, which can be either a `Seed` (any `u128` value) or a byte slice (e.g. `&[u8]`, `&Vec<u8>`).
They rely on the use of the usual server key.
The output is reproducible, i.e., the function is deterministic from the inputs: assuming the same hardware, seed and server key, this function outputs the same random encrypted value.

## Usage example

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

    // in [0, excluded_upper_bound) = {0, 1, 2}
    // DANGER: Static Seed(0) given as an example only
    // use proper seeding strategy depending on use case
    let ct_res = FheUint8::generate_oblivious_pseudo_random_custom_range(Seed(0), &range, None);
    let dec_result: u8 = ct_res.decrypt(&client_key);

    let random_bits_count = 3;

    // in [0, 2^8)
    // DANGER: Static Seed(0) given as an example only
    // use proper seeding strategy depending on use case
    let ct_res = FheUint8::generate_oblivious_pseudo_random(Seed(0));
    let dec_result: u8 = ct_res.decrypt(&client_key);

    // in [0, 2^random_bits_count) = [0, 8)
    // DANGER: Static Seed(0) given as an example only
    // use proper seeding strategy depending on use case
    let ct_res = FheUint8::generate_oblivious_pseudo_random_bounded(Seed(0), random_bits_count);
    let dec_result: u8 = ct_res.decrypt(&client_key);
    assert!(dec_result < (1 << random_bits_count));

    // in [-2^7, 2^7)
    // DANGER: Static Seed(0) given as an example only
    // use proper seeding strategy depending on use case
    let ct_res = FheInt8::generate_oblivious_pseudo_random(Seed(0));
    let dec_result: i8 = ct_res.decrypt(&client_key);

    // in [0, 2^random_bits_count) = [0, 8)
    // DANGER: Static Seed(0) given as an example only
    // use proper seeding strategy depending on use case
    let ct_res = FheInt8::generate_oblivious_pseudo_random_bounded(Seed(0), random_bits_count);
    let dec_result: i8 = ct_res.decrypt(&client_key);
    assert!(dec_result < (1 << random_bits_count));
}
```

## Example: roulette game

Consider a roulette casino game with 37 pockets `{0, ..., 36}`, where each spin is drawn by the server with `generate_oblivious_pseudo_random_custom_range` with `excluded_upper_bound = 37` and `max_distance = Δ`.
Let `P` be the actual distribution of a spin and `U` the uniform distribution (`U(ω) = 1/37` for every pocket `ω`).

Threat model: the attacker is a player who knows the generation algorithm, and therefore the exact distribution `P` (including which pockets are slightly more likely).
They can choose any bet, but cannot see or influence the seed, nor see the spin result before betting.
The PRF is assumed ideal: only the statistical bias of `P` is considered here.

Metric: the expected gain of the player for a bet of 1 unit.

1. The player chooses one bet, which covers a set `S` of `n` pockets:
   - a single number: any one of the 37 pockets (`n = 1`), pays back 36,
   - a dozen: `{1, ..., 12}`, `{13, ..., 24}` or `{25, ..., 36}` (`n = 12`), pays back 3,
   - red, black, odd or even: 18 pockets each, 0 being in none of them (`n = 18`), pays back 2,
   - other bets (split, street, corner, six line, column, low/high) also pay back `36/n` for `n` pockets, so the analysis below applies to them too.

   In all cases, the bet pays back `36/n` units (stake included) if the result is in `S`, and 0 otherwise.
   The expected gain of the bet is `G(S) = 36/n * P(S) - 1`, so it depends on the chosen bet.
2. With a uniform wheel, `U(S) = n/37`, so `G(S) = 36/37 - 1 = -1/37 ≈ -2.7%` whatever the bet: this is the house edge.
3. For any set `S`, `P(S) - U(S) <= Δ`.
   Indeed, `P(S) - U(S) = Sum[ω∈S] (P(ω) - U(ω))` is at most the sum of all the positive terms `P(ω) - U(ω)` over all pockets.
   As `P` and `U` both sum to 1, the positive terms and the negative terms have the same total magnitude, so the sum of the positive terms is half of `Sum[ω∈Ω] |P(ω) - U(ω)|`, which is the total variation distance, at most `Δ`.
4. Combining 1. and 3.: `G(S) <= 36/n * (n/37 + Δ) - 1 = -1/37 + 36/n * Δ`.
   The bias increases the expected gain by at most `36/n * Δ`:

   | Bet                | `n` | Maximum expected gain |
   |--------------------|-----|-----------------------|
   | Single number      | 1   | `-1/37 + 36 * Δ`      |
   | Dozen              | 12  | `-1/37 + 3 * Δ`       |
   | Red/black/odd/even | 18  | `-1/37 + 2 * Δ`       |

   With a uniform wheel all bets have the same expected gain, but with `P` the attacker chooses the bet with the best expected gain.
   This is always a single number: among the `n` pockets of `S`, at least one pocket `ω` has `P(ω) >= P(S)/n`, so betting on it gives `36 * P(ω) - 1 >= 36/n * P(S) - 1 = G(S)`.
   The expected gain of the attacker is thus at most `-1/37 + 36 * Δ`.
5. The player can only have a positive expected gain if `36 * Δ > 1/37`, i.e. `Δ > 1/1332 ≈ 2^-10.4`.

Numerical examples for a single number bet:
- With the default `Δ = 2^-128`, the expected gain is at most `-1/37 + 36 * 2^-128 ≈ -1/37 + 2^-122.8`: the bias is negligible and the house edge is unchanged in practice.
- With `Δ = 2^-8`, the expected gain is at most `-1/37 + 36/256 ≈ +11.4%`: the guarantee no longer excludes a player winning on average 0.11 unit per unit bet.
