# FHE implementation of PRINCEv2 using TFHE-rs

This crate implements homomorphic encryption and decryption of the PRINCEv2 block cipher [BEK+20] using TFHE-rs's shortint API. It takes FHE ciphertexts representing the plaintext (resp. ciphertext) block and the two halves of the PRINCEv2 key and produces FHE ciphertexts of the encrypted (resp. decrypted) block.

Inputs and outputs encrypt 64-bit integers that are represented as vectors of 2-bit nibbles, most significant nibble first, stacked in the lower part of the FHE message space of each ciphertext.

The cipher itself (a succession of S-box, Linear, Permutation, Xor layers) is evaluated under FHE using the `shortint` API, systematically operating on 4-bit lookup tables. More details on the FHE design can be found in [BJ26, Section 6].

## References

PRINCEv2 is specified in:
> [BEK+20] Dusan Božilov, Maria Eichlseder, Miroslav Kneževic, Baptiste Lambin, Gregor Leander, Thorben Moos, Ventzislav Nikov, Shahram Rasoolzadeh, Yosuke Todo, and Friedrich Wiemer. *PRINCEv2: More security for (almost) no overhead.* In Selected Areas in Cryptography (SAC 2020), volume 12804 of LNCS, pp.483--511, Springer, 2020. DOI:10.1007/978-3-030-81652-0_19.

Test vectors are those of Appendix B of the paper.

More details on the FHE implementation design can be found in Section 6 of:
> [BJ26] Olivier Bernard and Marc Joye. *Hash function constructions from lightweight block ciphers for fully homomorphic encryption*. Cryptology ePrint Archive, ePrint:2026/309, 2026.

## Layout

- `src/u64_conv.rs` — plaintext-side conversions between `u64` and the 32-element 2-bit-nibble vectors used on the FHE side; it exposes `u64_to_vec_u2` and `vec_u2_to_u64` as part of the encoding contract for the underlying plaintexts of the inputs and outputs.
- `src/permute.rs` — generic permutation helper over ciphertext arrays.
- `src/pv2_lut.rs` — precomputed S-box, inverse S-box, M-layer and round-constant lookup tables.
- `src/pv2_cipher.rs` — the homomorphic round functions and the public `pv2_encrypt` / `pv2_decrypt` entry points.
- `tests/pv2_kat.rs` — known-answer tests against the paper vectors.

## Usage

```rust
use tfhe::shortint::prelude::*;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
use tfhe_princev2::{pv2_encrypt, u64_to_vec_u2, vec_u2_to_u64};

let (s_key, ev_key) = tfhe::shortint::gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128);

let encode = |x: u64| -> [Ciphertext; 32] {
    let nibbles = u64_to_vec_u2(x);
    let v: Vec<_> = nibbles.into_iter().map(|n| s_key.encrypt(n as u64)).collect();
    v.try_into().unwrap()
};

let ct_m  = encode(0x0123456789abcdef);
let ct_k0 = encode(0x0123456789abcdef);
let ct_k1 = encode(0xfedcba9876543210);

let mut ct_out: [Ciphertext; 32] = std::array::from_fn(|_| ev_key.create_trivial(0));
pv2_encrypt(&ev_key, &mut ct_out, &ct_m, &ct_k0, &ct_k1);

let out_nibbles: [u8; 32] =
    std::array::from_fn(|i| s_key.decrypt_message_and_carry(&ct_out[i]) as u8);
assert_eq!(vec_u2_to_u64(out_nibbles), 0x603cd95fa72a8704);
```

## Running tests

```bash
RAYON_NUM_THREADS=64 cargo test --release --test pv2_kat -- --test-threads=1
```

Each KAT should take approximately 5 seconds (resp. 800ms) on 8 cores (resp. 64 cores) on an Amazon AWS hpc7a.96xlarge machine. There are currently 10 KATs (5 for encryption and same for decryption). Optimal timings depend on the hardware but will be structurally better using a number of threads which is a power of 2 less than 64; the best possible latency is obtained through 64 individual threads.


## Optional verbose timings

```bash
RAYON_NUM_THREADS=64 cargo test --release --test pv2_kat --features verbose-timings -- --test-threads=1 --nocapture
```

This times each internal round function call and emits one `eprintln!` per such call.


## Performance

Timings can be found in [BJ26, Table 6.1]. Benchmarks are out of scope for this initial PR and will follow in a separate submission.

