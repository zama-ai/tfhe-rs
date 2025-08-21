use super::{BooleanBlock, IntegerRadixCiphertext};
use crate::integer::backward_compatibility::ciphertext::DataKindVersions;
use crate::shortint::{Ciphertext, MessageModulus};
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
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
    pub fn num_blocks(self, message_modulus: MessageModulus) -> usize {
        match self {
            Self::Unsigned(n) | Self::Signed(n) => n.get(),
            Self::Boolean => 1,
            Self::String { n_chars, .. } => {
                let blocks_per_char = 7u32.div_ceil(message_modulus.0.ilog2());
                (n_chars * blocks_per_char) as usize
            }
        }
    }
}

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
