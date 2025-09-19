use crate::high_level_api::integers::signed::FheIntId;
use crate::high_level_api::integers::unsigned::FheUintId;
use crate::high_level_api::re_randomization::ReRandomizationMetadata;
use crate::integer::ciphertext::{DataKind, Expandable};
use crate::integer::BooleanBlock;
use crate::shortint::Ciphertext;
use crate::{FheBool, FheInt, FheUint, Tag};

fn num_bits_of_blocks(blocks: &[Ciphertext]) -> u32 {
    blocks
        .iter()
        .map(|block| block.message_modulus.0.ilog2())
        .sum::<u32>()
}

impl<Id: FheUintId> Expandable for FheUint<Id> {
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
                let mut boolean_block = BooleanBlock::new_unchecked(blocks[0].clone());
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
