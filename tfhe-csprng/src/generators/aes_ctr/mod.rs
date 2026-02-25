//! A module implementing the random generator api with batched aes calls.
//!
//! This module provides a generic [`AesCtrGenerator`] structure which implements the
//! [`super::RandomGenerator`] api using the AES block cipher in counter mode. That is, the
//! generator holds a state (i.e. counter) which is incremented iteratively, to produce the stream
//! of random values:
//! ```ascii
//!        state=0        state=1        state=2
//!        ╔══↧══╗        ╔══↧══╗        ╔══↧══╗
//!    key ↦ AES ║    key ↦ AES ║    key ↦ AES ║ ...
//!        ╚══↧══╝        ╚══↧══╝        ╚══↧══╝
//!        output0        output1        output2
//!
//!          t=0            t=1            t=2
//! ```
//!
//! The [`AesCtrGenerator`] structure is generic over the AES block ciphers, which are
//! represented by the [`AesBlockCipher`] trait. Consequently, implementers only need to implement
//! the `AesBlockCipher` trait, to benefit from the whole api of the `AesCtrGenerator` structure.
//!
//! In the following section, we give details on the implementation of this generic generator.
//!
//! Coarse-grained pseudo-random lookup table
//! =========================================
//!
//! To generate random values, we use the AES block cipher in counter mode. If we denote f the aes
//! encryption function, we have:
//! ```ascii
//!     f: ⟦0;2¹²⁸ -1⟧ X ⟦0;2¹²⁸ -1⟧ ↦ ⟦0;2¹²⁸ -1⟧
//!     f(secret_key, input) ↦ output
//! ```

//! If we fix the secret key to a value k, we have a function fₖ from ⟦0;2¹²⁸ -1⟧ to ⟦0;2¹²⁸-1⟧,
//! transforming the state of the counter into a pseudo random value. Essentially, this fₖ
//! function can be considered as a the following lookup table, containing 2¹²⁸ pseudo-random
//! values:
//! ```ascii  
//!     ╭──────────────┬──────────────┬─────┬──────────────╮
//!     │       0      │       1      │     │    2¹²⁸ -1   │
//!     ├──────────────┼──────────────┼─────┼──────────────┤
//!     │     fₖ(0)    │     fₖ(1)    │     │  fₖ(2¹²⁸ -1) │
//!     ╔═══════↧══════╦═══════↧══════╦═════╦═══════↧══════╗
//!     ║┏━━━━━━━━━━━━┓║┏━━━━━━━━━━━━┓║     ║┏━━━━━━━━━━━━┓║
//!     ║┃    u128    ┃║┃    u128    ┃║ ... ║┃    u128    ┃║
//!     ║┗━━━━━━━━━━━━┛║┗━━━━━━━━━━━━┛║     ║┗━━━━━━━━━━━━┛║
//!     ╚══════════════╩══════════════╩═════╩══════════════╝
//! ```
//!
//! An input to the fₖ function is called an _aes index_ (also called state or counter in the
//! standards) of the pseudo-random table. The [`AesIndex`] structure defined in this module
//! represents such an index in the code.
//!
//! Fine-grained pseudo-random table lookup
//! =======================================
//!
//! Since we want to deliver the pseudo-random bytes one by one, we have to come with a finer
//! grained indexing. Fortunately, each `u128` value outputted by fₖ can be seen as a table of 16
//! `u8`:
//! ```ascii
//!     ╭──────────────┬──────────────┬─────┬──────────────╮
//!     │       0      │       1      │     │    2¹²⁸ -1   │
//!     ├──────────────┼──────────────┼─────┼──────────────┤
//!     │     fₖ(0)    │     fₖ(1)    │     │  fₖ(2¹²⁸ -1) │
//!     ╔═══════↧══════╦═══════↧══════╦═════╦═══════↧══════╗
//!     ║┏━━━━━━━━━━━━┓║┏━━━━━━━━━━━━┓║     ║┏━━━━━━━━━━━━┓║
//!     ║┃    u128    ┃║┃    u128    ┃║     ║┃    u128    ┃║
//!     ║┣━━┯━━┯━━━┯━━┫║┣━━┯━━┯━━━┯━━┫║ ... ║┣━━┯━━┯━━━┯━━┫║
//!     ║┃u8│u8│...│u8┃║┃u8│u8│...│u8┃║     ║┃u8│u8│...│u8┃║
//!     ║┗━━┷━━┷━━━┷━━┛║┗━━┷━━┷━━━┷━━┛║     ║┗━━┷━━┷━━━┷━━┛║
//!     ╚══════════════╩══════════════╩═════╩══════════════╝
//! ```
//!
//! We introduce a second function to select a chunk of 8 bits:
//! ```ascii
//!     g: ⟦0;2¹²⁸ -1⟧ X ⟦0;15⟧ ↦ ⟦0;2⁸ -1⟧
//!     g(big_int, index) ↦ byte
//! ```
//!
//! If we fix the `u128` value to a value e, we have a function gₑ from ⟦0;15⟧ to ⟦0;2⁸ -1⟧
//! transforming an index into a pseudo-random byte:
//! ```ascii
//!     ┏━━━━━━━━┯━━━━━━━━┯━━━┯━━━━━━━━┓
//!     ┃   u8   │   u8   │...│   u8   ┃
//!     ┗━━━━━━━━┷━━━━━━━━┷━━━┷━━━━━━━━┛
//!     │  gₑ(0) │  gₑ(1) │   │ gₑ(15) │
//!     ╰────────┴─────-──┴───┴────────╯
//! ```
//!
//! We call this input to the gₑ function, a _byte index_ of the pseudo-random table. The
//! [`ByteIndex`] structure defined in this module represents such an index in the code.
//!
//! By using both the g and the fₖ functions, we can define a new function l which allows to index
//! any byte of the pseudo-random table:
//! ```ascii
//!     l: ⟦0;2¹²⁸ -1⟧ X ⟦0;15⟧ ↦ ⟦0;2⁸ -1⟧
//!     l(aes_index, byte_index) ↦ g(fₖ(aes_index), byte_index)
//! ```
//!
//! In this sense, any member of ⟦0;2¹²⁸ -1⟧ X ⟦0;15⟧ uniquely defines a byte in this pseudo-random
//! table:
//! ```ascii
//!                          e = fₖ(a)
//!     ╔══════════════╦═══════↧══════╦═════╦══════════════╗
//!     ║┏━━━━━━━━━━━━┓║┏━━━━━━━━━━━━┓║     ║┏━━━━━━━━━━━━┓║
//!     ║┃    u128    ┃║┃    u128    ┃║     ║┃    u128    ┃║
//!     ║┣━━┯━━┯━━━┯━━┫║┣━━┯━━┯━━━┯━━┫║ ... ║┣━━┯━━┯━━━┯━━┫║
//!     ║┃u8│u8│...│u8┃║┃u8│u8│...│u8┃║     ║┃u8│u8│...│u8┃║
//!     ║┗━━┷━━┷━━━┷━━┛║┗━━┷↥━┷━━━┷━━┛║     ║┗━━┷━━┷━━━┷━━┛║
//!     ║              ║│    gₑ(b)   │║     ║              ║
//!     ║              ║╰───-────────╯║     ║              ║
//!     ╚══════════════╩══════════════╩═════╩══════════════╝
//! ```
//!
//! We call this input to the l function, a _table index_ of the pseudo-random table. The
//! [`TableIndex`] structure defined in this module represents such an index in the code.
//!
//! Prngs current table index
//! =========================
//!
//! When created, a prng is given an initial _table index_, denoted (a₀, b₀), which identifies the
//! first byte of the table to be outputted by the prng. Then, each time the prng is queried for a
//! new value, the byte corresponding to the current _table index_ is returned, and the current
//! _table index_ is incremented:
//! ```ascii
//!       e = fₖ(a₀)                                                  e = fₖ(a₁)
//!     ╔═════↧═════╦═══════════╦═════╦═══════════╗     ╔═══════════╦═════↧═════╦═════╦═══════════╗
//!     ║┏━┯━┯━━━┯━┓║┏━┯━┯━━━┯━┓║ ... ║┏━┯━┯━━━┯━┓║     ║┏━┯━┯━━━┯━┓║┏━┯━┯━━━┯━┓║ ... ║┏━┯━┯━━━┯━┓║
//!     ║┃ │ │...│ ┃║┃ │ │...│ ┃║     ║┃ │ │...│ ┃║     ║┃ │ │...│ ┃║┃ │ │...│ ┃║     ║┃ │ │...│ ┃║
//!     ║┗━┷━┷━━━┷↥┛║┗━┷━┷━━━┷━┛║     ║┗━┷━┷━━━┷━┛║  →  ║┗━┷━┷━━━┷━┛║┗↥┷━┷━━━┷━┛║     ║┗━┷━┷━━━┷━┛║
//!     ║│  gₑ(b₀) │║           ║     ║           ║     ║           ║│  gₑ(b₁) │║     ║           ║
//!     ║╰─────────╯║           ║     ║           ║     ║           ║╰─────────╯║     ║           ║
//!     ╚═══════════╩═══════════╩═════╩═══════════╝     ╚═══════════╩═══════════╩═════╩═══════════╝
//! ```
//!
//! Prng bound
//! ==========
//!
//! When created, a prng is also given a _bound_ (aₘ, bₘ) , that is a table index which it is not
//! allowed to exceed:
//! ```ascii
//!       e = fₖ(a₀)
//!     ╔═════↧═════╦═══════════╦═════╦═══════════╗
//!     ║┏━┯━┯━━━┯━┓║┏━┯━┯━━━┯━┓║ ... ║┏━┯━┯━━━┯━┓║
//!     ║┃ │ │...│ ┃║┃ │╳│...│╳┃║     ║┃╳│╳│...│╳┃║
//!     ║┗━┷━┷━━━┷↥┛║┗━┷━┷━━━┷━┛║     ║┗━┷━┷━━━┷━┛║ The current byte can be returned.
//!     ║│  gₑ(b₀) │║           ║     ║           ║
//!     ║╰─────────╯║           ║     ║           ║
//!     ╚═══════════╩═══════════╩═════╩═══════════╝
//!     
//!                   e = fₖ(aₘ)
//!     ╔═══════════╦═════↧═════╦═════╦═══════════╗
//!     ║┏━┯━┯━━━┯━┓║┏━┯━┯━━━┯━┓║ ... ║┏━┯━┯━━━┯━┓║
//!     ║┃ │ │...│ ┃║┃ │╳│...│╳┃║     ║┃╳│╳│...│╳┃║ The table index reached the bound,
//!     ║┗━┷━┷━━━┷━┛║┗━┷↥┷━━━┷━┛║     ║┗━┷━┷━━━┷━┛║ the current byte can not be
//!     ║           ║│  gₑ(bₘ) │║     ║           ║ returned.
//!     ║           ║╰─────────╯║     ║           ║
//!     ╚═══════════╩═══════════╩═════╩═══════════╝
//! ```
//!
//! Buffering
//! =========
//!
//! Calling the aes function every time we need to output a single byte would be a huge waste of
//! resources. In practice, we call aes 8 times in a row, for 8 successive values of aes index, and
//! store the results in a buffer. For platforms which have a dedicated aes chip, this allows to
//! fill the unit pipeline and reduces the amortized cost of the aes function.
//!
//! Together with the current table index of the prng, we also store a pointer p (initialized at
//! p₀=b₀) to the current byte in the buffer. If we denote v the lookup function we have :
//! ```ascii
//!                        e = fₖ(a₀)                         Buffer(length=128)
//!     ╔═════╦═══════════╦═════↧═════╦═══════════╦═════╗  ┏━┯━┯━┯━┯━┯━┯━┯━┯━━━┯━┓
//!     ║ ... ║┏━┯━┯━━━┯━┓║┏━┯━┯━━━┯━┓║┏━┯━┯━━━┯━┓║ ... ║  ┃▓│▓│▓│▓│▓│▓│▓│▓│...│▓┃
//!     ║     ║┃ │ │...│ ┃║┃▓│▓│...│▓┃║┃▓│▓│...│▓┃║     ║  ┗━┷↥┷━┷━┷━┷━┷━┷━┷━━━┷━┛
//!     ║     ║┗━┷━┷━━━┷━┛║┗━┷↥┷━━━┷━┛║┗━┷━┷━━━┷━┛║     ║  │ v(p₀)               │
//!     ║     ║           ║│  gₑ(b₀) │║           ║     ║  ╰─────────────────────╯
//!     ║     ║           ║╰─────────╯║           ║     ║
//!     ╚═════╩═══════════╩═══════════╩═══════════╩═════╝
//! ```
//!
//! We call this input to the v function, a _buffer pointer_. The [`BufferPointer`] structure
//! defined in this module represents such a pointer in the code.
//!
//! When the table index is incremented, the buffer pointer is incremented alongside:
//! ```ascii
//!                        e = fₖ(a)                          Buffer(length=128)
//!     ╔═════╦═══════════╦═════↧═════╦═══════════╦═════╗  ┏━┯━┯━┯━┯━┯━┯━┯━┯━━━┯━┓
//!     ║ ... ║┏━┯━┯━━━┯━┓║┏━┯━┯━━━┯━┓║┏━┯━┯━━━┯━┓║ ... ║  ┃▓│▓│▓│▓│▓│▓│▓│▓│...│▓┃
//!     ║     ║┃ │ │...│ ┃║┃▓│▓│...│▓┃║┃▓│▓│...│▓┃║     ║  ┗━┷━┷↥┷━┷━┷━┷━┷━┷━━━┷━┛
//!     ║     ║┗━┷━┷━━━┷━┛║┗━┷━┷↥━━┷━┛║┗━┷━┷━━━┷━┛║     ║  │   v(p)              │
//!     ║     ║           ║│  gₑ(b)  │║           ║     ║  ╰─────────────────────╯
//!     ║     ║           ║╰─────────╯║           ║     ║
//!     ╚═════╩═══════════╩═══════════╩═══════════╩═════╝
//! ```
//!
//! When the buffer pointer is incremented it is checked against the size of the buffer, and if
//! necessary, a new batch of aes index values is generated.

pub const AES_CALLS_PER_BATCH: usize = 8;
pub const BYTES_PER_AES_CALL: usize = 128 / 8;
pub const BYTES_PER_BATCH: usize = BYTES_PER_AES_CALL * AES_CALLS_PER_BATCH;

#[derive(
    Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, tfhe_versionable::Versionize,
)]
#[versionize(AesCtrParamsVersions)]
pub struct AesCtrParams {
    pub seed: SeedKind,
    pub first_index: TableIndex,
}

impl From<SeedKind> for AesCtrParams {
    fn from(seed: SeedKind) -> Self {
        Self {
            seed,
            first_index: TableIndex::SECOND,
        }
    }
}

impl From<Seed> for AesCtrParams {
    fn from(seed: Seed) -> Self {
        Self::from(SeedKind::Ctr(seed))
    }
}

impl From<XofSeed> for AesCtrParams {
    fn from(seed: XofSeed) -> Self {
        Self::from(SeedKind::Xof(seed))
    }
}

/// A module containing structures to manage table indices.
mod index;

pub use index::*;

/// A module containing structures to manage table indices and buffer pointers together properly.
mod states;

/// A module containing an abstraction for aes block ciphers.
mod block_cipher;
pub use block_cipher::*;

/// A module containing a generic implementation of a random generator.
mod generic;
pub use generic::*;

/// A module extending `generic` to the `rayon` paradigm.
#[cfg(feature = "parallel")]
mod parallel;

use crate::generators::backward_compatibility::AesCtrParamsVersions;
use crate::seeders::{Seed, SeedKind, XofSeed};
#[cfg(feature = "parallel")]
pub use parallel::*;

pub(crate) fn xof_init(seed: XofSeed) -> (AesKey, AesIndex) {
    let init_key = AesKey(0);
    let mut aes = crate::generators::default::DefaultBlockCipher::new(init_key);

    let blocks = seed
        .iter_u128_blocks()
        .chain(std::iter::once(seed.bit_len().to_le()));

    let mut prev_c = 0;
    let mut c = 0;
    for mi in blocks {
        prev_c = c;
        c = u128::from_ne_bytes(aes.generate_next(prev_c ^ mi));
    }

    let init = AesIndex(prev_c.to_le());
    let key = AesKey(c);

    (key, init)
}
