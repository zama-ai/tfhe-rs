use super::{BooleanBlock, IntegerRadixCiphertext};
use crate::integer::backward_compatibility::ciphertext::DataKindVersions;
use crate::shortint::{Ciphertext, MessageModulus};
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use std::ops::Range;
use tfhe_versionable::Versionize;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(DataKindVersions)]
pub enum DataKind {
    /// The held value is a number of radix blocks.
    Unsigned(NonZeroUsize),
    /// The held value is a number of radix blocks.
    Signed(NonZeroUsize),
    Boolean,
    String {
        n_chars: u32,
        padded: bool,
    },
}

impl DataKind {
    pub fn num_blocks(self, message_modulus: MessageModulus) -> crate::Result<usize> {
        match self {
            Self::Unsigned(n) | Self::Signed(n) => Ok(n.get()),
            Self::Boolean => Ok(1),
            Self::String { n_chars, .. } => {
                let blocks_per_char = message_modulus.num_blocks_per_ascii_char()?;
                (n_chars as usize)
                    .checked_mul(blocks_per_char.get())
                    .ok_or_else(|| {
                        crate::error!("Overflow while trying to compute num blocks for string")
                    })
            }
        }
    }

    pub(crate) fn total_block_count(
        info: &[Self],
        message_modulus: MessageModulus,
    ) -> crate::Result<usize> {
        Self::total_count(info, message_modulus, Self::num_blocks)
    }

    /// Number of noise squashed ciphertexts used by this item
    pub(crate) fn num_squashed_blocks(
        self,
        message_modulus: MessageModulus,
    ) -> crate::Result<usize> {
        Ok(self.num_blocks(message_modulus)?.div_ceil(2))
    }

    /// Number of noise squashed ciphertexts used by a list: each item is packed on its own
    pub(crate) fn total_squashed_block_count(
        info: &[Self],
        message_modulus: MessageModulus,
    ) -> crate::Result<usize> {
        Self::total_count(info, message_modulus, Self::num_squashed_blocks)
    }

    /// Kind and range of the blocks used by the item at `index` in a list described by `info`
    ///
    /// Returns None if `index` is out of bounds, and an error if `message_modulus` is missing or if
    /// the range overflows
    pub(crate) fn locate(
        info: &[Self],
        index: usize,
        message_modulus: Option<MessageModulus>,
    ) -> crate::Result<Option<(Self, Range<usize>)>> {
        Self::locate_with(info, index, message_modulus, Self::num_blocks)
    }

    /// Same as [`Self::locate`], for a list of noise squashed ciphertexts
    pub(crate) fn locate_squashed(
        info: &[Self],
        index: usize,
        message_modulus: Option<MessageModulus>,
    ) -> crate::Result<Option<(Self, Range<usize>)>> {
        Self::locate_with(info, index, message_modulus, Self::num_squashed_blocks)
    }

    /// Number of ciphertexts used by the items of `info`, item is size counted with `count_blocks`
    fn total_count(
        info: &[Self],
        message_modulus: MessageModulus,
        count_blocks: BlocksCounter,
    ) -> crate::Result<usize> {
        if message_modulus.0 == 0 {
            return Err(crate::error!("Invalid message modulus in list: 0"));
        }

        info.iter().try_fold(0usize, |acc, &x| {
            acc.checked_add(count_blocks(x, message_modulus)?)
                .ok_or_else(|| {
                    crate::error!("Overflow while trying to compute total num blocks for list")
                })
        })
    }

    /// Kind and range of the ciphertexts used by the item at `index` in a list described by
    /// `info`, item is size counted with `count_blocks`
    fn locate_with(
        info: &[Self],
        index: usize,
        message_modulus: Option<MessageModulus>,
        count_blocks: BlocksCounter,
    ) -> crate::Result<Option<(Self, Range<usize>)>> {
        let Some(&kind) = info.get(index) else {
            // Index out of bound.
            return Ok(None);
        };

        let message_modulus =
            message_modulus.ok_or_else(|| crate::error!("Missing metadata for list"))?;

        let start = Self::total_count(&info[..index], message_modulus, count_blocks)?;
        let end = start
            .checked_add(count_blocks(kind, message_modulus)?)
            .ok_or_else(|| crate::error!("Overflow while trying to compute block range in list"))?;

        Ok(Some((kind, start..end)))
    }
}

/// Method used to count the number of ciphertexts in a list. Can be:
/// - DataKind::num_blocks
/// - DataKind::num_squashed_blocks
type BlocksCounter = fn(DataKind, MessageModulus) -> crate::Result<usize>;

pub trait Expandable: Sized {
    fn from_expanded_blocks(blocks: Vec<Ciphertext>, kind: DataKind) -> crate::Result<Self>;
}

impl<T> Expandable for T
where
    T: IntegerRadixCiphertext,
{
    fn from_expanded_blocks(blocks: Vec<Ciphertext>, kind: DataKind) -> crate::Result<Self> {
        match (kind, T::IS_SIGNED) {
            (DataKind::Unsigned(_), false) | (DataKind::Signed(_), true) => {
                Ok(T::from_blocks(blocks))
            }
            (DataKind::Boolean, _) => {
                let signed_or_unsigned_str = if T::IS_SIGNED { "signed" } else { "unsigned" };
                Err(crate::Error::new(format!(
                    "Tried to expand a {signed_or_unsigned_str} radix while boolean is stored"
                )))
            }
            (DataKind::Unsigned(_), true) => Err(crate::Error::new(
                "Tried to expand a signed radix while an unsigned radix is stored".to_string(),
            )),
            (DataKind::Signed(_), false) => Err(crate::Error::new(
                "Tried to expand an unsigned radix while a signed radix is stored".to_string(),
            )),
            (DataKind::String { .. }, _) => Err(crate::Error::new(
                "Tried to expand an unsigned radix while a string is stored".to_string(),
            )),
        }
    }
}

impl Expandable for BooleanBlock {
    fn from_expanded_blocks(blocks: Vec<Ciphertext>, kind: DataKind) -> crate::Result<Self> {
        match kind {
            DataKind::Unsigned(_) => Err(crate::Error::new(
                "Tried to expand a boolean block while an unsigned radix was stored".to_string(),
            )),
            DataKind::Signed(_) => Err(crate::Error::new(
                "Tried to expand a boolean block while a signed radix was stored".to_string(),
            )),
            DataKind::Boolean => Ok(Self::new_unchecked(blocks[0].clone())),
            DataKind::String { .. } => Err(crate::Error::new(
                "Tried to expand a boolean block while a string is stored".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Check that strings num_blocks does not panic
    #[test]
    fn test_string_num_blocks() {
        let kind = DataKind::String {
            n_chars: 10,
            padded: true,
        };

        // Unsupported parameters (possibly coming from untrusted data) must not panic
        assert!(kind.num_blocks(MessageModulus(0)).is_err());

        assert!(kind.num_blocks(MessageModulus(1)).is_err());

        assert!(kind.num_blocks(MessageModulus(8)).is_err());

        let kind = DataKind::String {
            n_chars: u32::MAX,
            padded: true,
        };

        assert_eq!(
            kind.num_blocks(MessageModulus(2)).unwrap(),
            (u32::MAX as usize) * 8
        );
    }
}
