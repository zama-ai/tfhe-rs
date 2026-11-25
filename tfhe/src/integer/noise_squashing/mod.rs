mod keys;
#[cfg(test)]
pub(crate) mod tests;

pub use keys::*;

use crate::shortint::ciphertext::{Degree, MaxNoiseLevel, NoiseLevel};
use crate::shortint::{CarryModulus, MessageModulus};

/// Checks that a chunk of radix blocks (described by their degree and noise level) can be packed
/// and then noise squashed.
///
/// Integer noise squashing packs blocks by pairs as `low + message_modulus * high` before the
/// 128 bits PBS, `high` being `None` for the last block of a radix with an odd block count. This
/// requires:
/// - room for two messages in a block (carry modulus >= message modulus) when packing a pair;
/// - empty carries on every block, so that the packed value fits in the message and carry space and
///   does not reach the padding bit;
/// - a noise level for the packed block within the max noise level of the source server key.
///
/// Boolean blocks are checked as a single unpacked block (`high` is `None`). Their degree may be
/// above 1, but their carry must be empty as the squashed boolean is decrypted as `value != 0` over
/// the whole message and carry space.
///
/// This is shared between the CPU and GPU backends so both enforce the same invariants.
pub(crate) fn check_blocks_can_be_packed_and_squashed(
    blocks: impl IntoIterator<Item = (Degree, NoiseLevel)>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    max_noise_level: MaxNoiseLevel,
) -> crate::Result<()> {
    // Chunk the blocks by pairs here, so that both backends check the same chunks
    let mut blocks = blocks.into_iter();
    while let Some(low) = blocks.next() {
        check_block_chunk_can_be_packed_and_squashed(
            low,
            blocks.next(),
            message_modulus,
            carry_modulus,
            max_noise_level,
        )?;
    }
    Ok(())
}

fn check_block_chunk_can_be_packed_and_squashed(
    low: (Degree, NoiseLevel),
    high: Option<(Degree, NoiseLevel)>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    max_noise_level: MaxNoiseLevel,
) -> crate::Result<()> {
    if high.is_some() && carry_modulus.0 < message_modulus.0 {
        return Err(crate::error!(
            "Cannot pack if carry modulus ({carry_modulus:?}) is smaller than message modulus \
            ({message_modulus:?})"
        ));
    }

    let carry_is_empty = |degree: Degree| degree.get() < message_modulus.0;

    let (low_degree, low_noise) = low;
    let packed_noise = if let Some((high_degree, high_noise)) = high {
        if !carry_is_empty(low_degree) || !carry_is_empty(high_degree) {
            return Err(crate::error!(
                "Cannot pack blocks: need both carries to be empty \
                (got degrees {low_degree:?} and {high_degree:?}, \
                message modulus {message_modulus:?})."
            ));
        }
        high_noise * message_modulus.0 + low_noise
    } else {
        if !carry_is_empty(low_degree) {
            return Err(crate::error!(
                "Cannot squash block: need carry to be empty \
                (got degree {low_degree:?}, message modulus {message_modulus:?})."
            ));
        }
        low_noise
    };

    max_noise_level
        .validate(packed_noise)
        .map_err(|e| crate::error!("{}", e))
}
