use super::{DataKind, Expandable, RadixCiphertext, SignedRadixCiphertext};
use crate::integer::backward_compatibility::ciphertext::CompressedCiphertextListVersions;
use crate::integer::BooleanBlock;
use crate::shortint::ciphertext::CompressedCiphertextList as ShortintCompressedCiphertextList;
use crate::shortint::list_compression::{CompressionKey, DecompressionKey};
use crate::shortint::Ciphertext;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

pub trait Compressible {
    fn compress_into(self, messages: &mut Vec<Ciphertext>) -> DataKind;
}

impl Compressible for BooleanBlock {
    fn compress_into(self, messages: &mut Vec<Ciphertext>) -> DataKind {
        messages.push(self.0);
        DataKind::Boolean
    }
}

impl Compressible for RadixCiphertext {
    fn compress_into(self, messages: &mut Vec<Ciphertext>) -> DataKind {
        let num_blocks = self.blocks.len();

        for block in self.blocks {
            messages.push(block);
        }

        DataKind::Unsigned(num_blocks)
    }
}

impl Compressible for SignedRadixCiphertext {
    fn compress_into(self, messages: &mut Vec<Ciphertext>) -> DataKind {
        let num_blocks = self.blocks.len();

        for block in self.blocks {
            messages.push(block);
        }

        DataKind::Signed(num_blocks)
    }
}

pub struct CompressedCiphertextListBuilder {
    pub(crate) ciphertexts: Vec<Ciphertext>,
    pub(crate) info: Vec<DataKind>,
}

impl CompressedCiphertextListBuilder {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            ciphertexts: vec![],
            info: vec![],
        }
    }

    pub fn push<T>(&mut self, data: T) -> &mut Self
    where
        T: Compressible,
    {
        let n = self.ciphertexts.len();
        let kind = data.compress_into(&mut self.ciphertexts);
        assert_eq!(n + kind.num_blocks(), self.ciphertexts.len());

        if kind.num_blocks() != 0 {
            self.info.push(kind);
        }

        self
    }

    pub fn extend<T>(&mut self, values: impl Iterator<Item = T>) -> &mut Self
    where
        T: Compressible,
    {
        for value in values {
            self.push(value);
        }
        self
    }

    pub fn build(&self, comp_key: &CompressionKey) -> CompressedCiphertextList {
        let packed_list = comp_key.compress_ciphertexts_into_list(&self.ciphertexts);

        CompressedCiphertextList {
            packed_list,
            info: self.info.clone(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(CompressedCiphertextListVersions)]
pub struct CompressedCiphertextList {
    pub(crate) packed_list: ShortintCompressedCiphertextList,
    info: Vec<DataKind>,
}

impl CompressedCiphertextList {
    pub fn len(&self) -> usize {
        self.info.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn blocks_of(
        &self,
        index: usize,
        decomp_key: &DecompressionKey,
    ) -> Option<(Vec<Ciphertext>, DataKind)> {
        let preceding_infos = self.info.get(..index)?;
        let current_info = self.info.get(index).copied()?;

        let start_block_index: usize = preceding_infos
            .iter()
            .copied()
            .map(DataKind::num_blocks)
            .sum();

        let end_block_index = start_block_index + current_info.num_blocks();

        Some((
            (start_block_index..end_block_index)
                .into_par_iter()
                .map(|i| decomp_key.unpack(&self.packed_list, i).unwrap())
                .collect(),
            current_info,
        ))
    }

    pub fn get_kind_of(&self, index: usize) -> Option<DataKind> {
        self.info.get(index).copied()
    }

    pub fn get<T>(&self, index: usize, decomp_key: &DecompressionKey) -> crate::Result<Option<T>>
    where
        T: Expandable,
    {
        self.blocks_of(index, decomp_key)
            .map(|(blocks, kind)| T::from_expanded_blocks(blocks, kind))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integer::{RadixCiphertext, RadixClientKey};
    use crate::shortint::parameters::list_compression::COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

    #[test]
    fn test_heterogeneous_ciphertext_compression_ci_run_filter() {
        let num_blocks = 2;

        let cks = RadixClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64, num_blocks);

        let private_compression_key =
            cks.new_compression_private_key(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);

        let (compression_key, decompression_key) =
            cks.new_compression_decompression_keys(&private_compression_key);

        let ct1 = cks.encrypt(3_u32);

        let ct2 = cks.encrypt_signed(-2);

        let ct3 = cks.encrypt_bool(true);

        let compressed = CompressedCiphertextListBuilder::new()
            .push(ct1)
            .push(ct2)
            .push(ct3)
            .build(&compression_key);

        let a = compressed.blocks_of(0, &decompression_key).unwrap();

        let decrypted: u32 = cks.decrypt(&RadixCiphertext::from_expanded_blocks(a.0, a.1).unwrap());
        assert_eq!(decrypted, 3_u32);

        let b = compressed.blocks_of(1, &decompression_key).unwrap();

        let decrypted: i32 =
            cks.decrypt_signed(&SignedRadixCiphertext::from_expanded_blocks(b.0, b.1).unwrap());

        assert_eq!(decrypted, -2);

        let c = compressed.blocks_of(2, &decompression_key).unwrap();

        assert!(cks.decrypt_bool(&BooleanBlock::from_expanded_blocks(c.0, c.1).unwrap()));
    }
}
