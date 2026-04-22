# FHE implementation of PRINCEv2 using TFHE-rs

This crate implements homomorphic encryption and decryption of the PRINCEv2 block cipher [BEK+20] using TFHE-rs's shortint API. It takes FHE ciphertexts representing the plaintext (resp. ciphertext) block and the two halves of the PRINCEv2 key and produces FHE ciphertexts of the encrypted (resp. decrypted) block.

Inputs and outputs encrypt 64-bit integers that are represented as vectors of 2-bit nibbles, most significant nibble first, stacked in the lower part of the FHE message space of each ciphertext. Inputs are required to be at nominal noise level and outputs are returned at nominal noise level.

The cipher itself (a succession of S-box, Linear, Permutation, Xor layers) is evaluated under FHE using the `shortint` API, systematically operating on 4-bit lookup tables. More details on the FHE design can be found in [BJ26, Section 6].

## References

PRINCEv2 is specified in:
> [BEK+20] Dusan Božilov, Maria Eichlseder, Miroslav Kneževic, Baptiste Lambin, Gregor Leander, Thorben Moos, Ventzislav Nikov, Shahram Rasoolzadeh, Yosuke Todo, and Friedrich Wiemer. *PRINCEv2: More security for (almost) no overhead.* In Selected Areas in Cryptography (SAC 2020), volume 12804 of LNCS, pp.483--511, Springer, 2020. DOI:10.1007/978-3-030-81652-0_19.

Test vectors are those of Appendix B of the paper.

More details on the FHE implementation design can be found in Section 6 of:
> [BJ26] Olivier Bernard and Marc Joye. *Hash function constructions from lightweight block ciphers for fully homomorphic encryption*. Cryptology ePrint Archive, ePrint:2026/309, 2026.

## Layout

- `src/u64_conv.rs` — plaintext-side conversions between `u64` and the 32-element 2-bit-nibble vectors used on the FHE side; it exposes `u64_to_vec_u2` and `vec_u2_to_u64` as part of the encoding contract for the underlying plaintexts of the inputs and outputs.
- `src/encryption.rs` — client-side counterpart of that contract: `encrypt_u64_as_u2l` / `decrypt_u2l_as_u64` (de-)serialize a `u64` to and from the ciphertext arrays taken and returned by `encrypt` / `decrypt`. Used by the tests, the benchmarks and the example below; the cipher itself never sees a `ClientKey`.
- `src/tables.rs` — precomputed S-box, inverse S-box, M-layer and round-constant lookup tables, plus the permutation tables.
- `src/cipher.rs` — the homomorphic round functions and the public `encrypt` / `decrypt` entry points.
- `tests/kat.rs` — known-answer tests against the paper vectors.
- `benches/princev2.rs` — benchmarks for a full call of `encrypt` and of `decrypt`.
- `docs/` — scripts generating SVG wiring diagrams of a round, both as specified and as evaluated under FHE; see `docs/README.md`.

## Usage

```rust,no_run
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
use tfhe::shortint::prelude::*;
use tfhe_princev2::encryption::{decrypt_u2l_as_u64, encrypt_u64_as_u2l};
use tfhe_princev2::encrypt;

let (c_key, ev_key) = tfhe::shortint::gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128);

let ct_m: [Ciphertext; 32] = encrypt_u64_as_u2l(&c_key, 0x0123456789abcdef);
let ct_k0: [Ciphertext; 32] = encrypt_u64_as_u2l(&c_key, 0x0123456789abcdef);
let ct_k1: [Ciphertext; 32] = encrypt_u64_as_u2l(&c_key, 0xfedcba9876543210);

let ct_out: [Ciphertext; 32] = encrypt(&ev_key, &ct_m, &ct_k0, &ct_k1);

assert_eq!(decrypt_u2l_as_u64(&c_key, &ct_out), 0x603cd95fa72a8704);
```

## Running tests

```bash
RAYON_NUM_THREADS=64 cargo test --release --test kat -- --test-threads=1
```

Each KAT should take approximately 5 seconds (resp. 800ms) on 8 cores (resp. 64 cores) on an Amazon AWS hpc7a.96xlarge machine. There are currently 10 KATs (5 for encryption and same for decryption). Optimal timings depend on the hardware but will be structurally better using a number of threads which is a power of 2 up to 64; the best possible latency is obtained through 64 individual threads.


## Optional verbose timings

```bash
RAYON_NUM_THREADS=64 cargo test --release --test kat --features verbose-timings -- --test-threads=1 --nocapture
```

This times each internal round function call and emits one `eprintln!` per such call.


## Running benchmarks

```bash
RAYON_NUM_THREADS=64 cargo bench --bench princev2
```

Timings obtained on up to 64 cores of an `Amazon AWS hpc7a.96xlarge` machine can also be found in [BJ26, Table 6.1].
