use crate::high_level_api::integers::signed::FheIntId;
use crate::high_level_api::integers::unsigned::FheUintId;
use crate::high_level_api::re_randomization::ReRandomizationMetadata;
use crate::integer::ciphertext::{DataKind, Expandable};
use crate::integer::BooleanBlock;
use crate::shortint::{Ciphertext, MessageModulus};
use crate::{FheBool, FheInt, FheUint, Tag};

fn num_bits_of_blocks(blocks: &[Ciphertext]) -> u32 {
    blocks
        .iter()
        .map(|block| block.message_modulus.0.ilog2())
        .sum::<u32>()
}

fn data_kind_name(kind: DataKind, message_modulus: MessageModulus) -> String {
    let num_bits = kind.radix_num_bits(message_modulus);
    match kind {
        DataKind::Unsigned(_) => num_bits.map_or_else(
            || "FheUint of invalid size".to_owned(),
            |num_bits| format!("FheUint{num_bits}"),
        ),
        DataKind::Signed(_) => num_bits.map_or_else(
            || "FheInt of invalid size".to_owned(),
            |num_bits| format!("FheInt{num_bits}"),
        ),
        DataKind::Boolean => "FheBool".to_owned(),
        DataKind::String { .. } => "FheString".to_owned(),
    }
}

pub(crate) fn kind_mismatch_error(
    expected_type: &str,
    kind: DataKind,
    message_modulus: MessageModulus,
) -> crate::Error {
    crate::error!(
        "Tried to expand a {expected_type} while a {} is stored in this slot",
        data_kind_name(kind, message_modulus)
    )
}

impl<Id: FheUintId> Expandable for FheUint<Id> {
    fn check_kind(kind: DataKind, message_modulus: MessageModulus) -> crate::Result<()> {
        if kind.is_unsigned_radix(message_modulus, Id::num_bits()) {
            return Ok(());
        }
        Err(kind_mismatch_error(
            &format!("FheUint{}", Id::num_bits()),
            kind,
            message_modulus,
        ))
    }

    fn from_expanded_blocks(blocks: Vec<Ciphertext>, kind: DataKind) -> crate::Result<Self> {
        match kind {
            DataKind::Unsigned(_) => {
                let stored_num_bits = num_bits_of_blocks(&blocks) as usize;
                if stored_num_bits == Id::num_bits() {
                    // The expander will be responsible for setting the correct tag and metadata
                    Ok(Self::new(
                        crate::integer::RadixCiphertext::from(blocks),
                        Tag::default(),
                        ReRandomizationMetadata::default(),
                    ))
                } else {
                    Err(crate::error!(
                        "Tried to expand a FheUint{} while a FheUint{} is stored in this slot",
                        Id::num_bits(),
                        stored_num_bits
                    ))
                }
            }
            DataKind::Signed(_) => {
                let stored_num_bits = num_bits_of_blocks(&blocks) as usize;
                Err(crate::error!(
                    "Tried to expand a FheUint{} while a FheInt{} is stored in this slot",
                    Id::num_bits(),
                    stored_num_bits
                ))
            }
            DataKind::Boolean => Err(crate::error!(
                "Tried to expand a FheUint{} while a FheBool is stored in this slot",
                Id::num_bits(),
            )),
            DataKind::String { .. } => Err(crate::error!(
                "Tried to expand a FheUint{}  while a string is stored in this slot",
                Id::num_bits()
            )),
        }
    }
}

impl<Id: FheIntId> Expandable for FheInt<Id> {
    fn check_kind(kind: DataKind, message_modulus: MessageModulus) -> crate::Result<()> {
        if kind.is_signed_radix(message_modulus, Id::num_bits()) {
            return Ok(());
        }
        Err(kind_mismatch_error(
            &format!("FheInt{}", Id::num_bits()),
            kind,
            message_modulus,
        ))
    }

    fn from_expanded_blocks(blocks: Vec<Ciphertext>, kind: DataKind) -> crate::Result<Self> {
        match kind {
            DataKind::Unsigned(_) => {
                let stored_num_bits = num_bits_of_blocks(&blocks) as usize;
                Err(crate::error!(
                    "Tried to expand a FheInt{} while a FheUint{} is stored in this slot",
                    Id::num_bits(),
                    stored_num_bits
                ))
            }
            DataKind::Signed(_) => {
                let stored_num_bits = num_bits_of_blocks(&blocks) as usize;
                if stored_num_bits == Id::num_bits() {
                    // The expander will be responsible for setting the correct tag
                    Ok(Self::new(
                        crate::integer::SignedRadixCiphertext::from(blocks),
                        Tag::default(),
                        ReRandomizationMetadata::default(),
                    ))
                } else {
                    Err(crate::error!(
                        "Tried to expand a FheInt{} while a FheInt{} is stored in this slot",
                        Id::num_bits(),
                        stored_num_bits
                    ))
                }
            }
            DataKind::Boolean => Err(crate::error!(
                "Tried to expand a FheInt{} while a FheBool is stored in this slot",
                Id::num_bits(),
            )),
            DataKind::String { .. } => Err(crate::error!(
                "Tried to expand a FheInt{}  while a string is stored in this slot",
                Id::num_bits()
            )),
        }
    }
}

impl Expandable for FheBool {
    fn check_kind(kind: DataKind, message_modulus: MessageModulus) -> crate::Result<()> {
        if kind == DataKind::Boolean {
            return Ok(());
        }
        Err(kind_mismatch_error("FheBool", kind, message_modulus))
    }

    fn from_expanded_blocks(blocks: Vec<Ciphertext>, kind: DataKind) -> crate::Result<Self> {
        match kind {
            DataKind::Unsigned(_) => {
                let stored_num_bits = num_bits_of_blocks(&blocks) as usize;
                Err(crate::error!(
                    "Tried to expand a FheBool while a FheUint{stored_num_bits} is stored in this slot",
                ))
            }
            DataKind::Signed(_) => {
                let stored_num_bits = num_bits_of_blocks(&blocks) as usize;
                Err(crate::error!(
                    "Tried to expand a FheBool while a FheInt{stored_num_bits} is stored in this slot",
                ))
            }
            DataKind::Boolean => {
                let [block] = <[Ciphertext; 1]>::try_from(blocks).map_err(|blocks| {
                    crate::error!(
                        "Tried to expand a FheBool while {} blocks are stored in this slot",
                        blocks.len(),
                    )
                })?;

                let mut boolean_block = BooleanBlock::new_unchecked(block);
                // We know the value is a boolean one (via the data kind)
                boolean_block.0.degree = crate::shortint::ciphertext::Degree::new(1);

                // The expander will be responsible for setting the correct tag and metadata
                Ok(Self::new(
                    boolean_block,
                    Tag::default(),
                    ReRandomizationMetadata::default(),
                ))
            }
            DataKind::String { .. } => Err(crate::Error::new(
                "Tried to expand a FheBool while a string is stored in this slot".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "strings")]
    use crate::FheAsciiString;
    use crate::{FheInt8, FheUint8};
    use std::num::NonZeroUsize;

    #[test]
    fn test_check_kind() {
        let message_modulus = MessageModulus(4);
        let four_blocks = NonZeroUsize::new(4).unwrap();

        // Matching items
        assert!(FheUint8::check_kind(DataKind::Unsigned(four_blocks), message_modulus).is_ok());
        assert!(FheInt8::check_kind(DataKind::Signed(four_blocks), message_modulus).is_ok());
        assert!(FheBool::check_kind(DataKind::Boolean, message_modulus).is_ok());
        let string = DataKind::String {
            n_chars: 3,
            padded: false,
        };
        #[cfg(feature = "strings")]
        assert!(FheAsciiString::check_kind(string, message_modulus).is_ok());

        // Wrong size, as an attacker would send to trigger a big decompression
        let huge = DataKind::Unsigned(NonZeroUsize::new(100_000).unwrap());
        assert!(FheUint8::check_kind(huge, message_modulus).is_err());
        assert!(
            FheUint8::check_kind(DataKind::Unsigned(NonZeroUsize::MAX), message_modulus).is_err()
        );

        // Wrong kind
        assert!(FheUint8::check_kind(DataKind::Signed(four_blocks), message_modulus).is_err());
        assert!(FheInt8::check_kind(DataKind::Unsigned(four_blocks), message_modulus).is_err());
        assert!(FheBool::check_kind(DataKind::Unsigned(four_blocks), message_modulus).is_err());
        assert!(FheUint8::check_kind(string, message_modulus).is_err());
        #[cfg(feature = "strings")]
        assert!(FheAsciiString::check_kind(DataKind::Boolean, message_modulus).is_err());

        // Invalid modulus from untrusted metadata must not panic
        assert!(FheUint8::check_kind(DataKind::Unsigned(four_blocks), MessageModulus(0)).is_err());
    }
}
