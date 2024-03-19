use super::super::parameters::RadixCompactCiphertextListConformanceParams;
use super::IntegerRadixCiphertext;
use crate::conformance::ParameterSetConformant;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct CompactCiphertextList {
    pub(crate) ct_list: crate::shortint::ciphertext::CompactCiphertextList,
    // Keep track of the num_blocks, as we allow
    // storing many integer that have the same num_blocks
    // into ct_list
    pub(crate) num_blocks_per_integer: usize,
}

impl ParameterSetConformant for CompactCiphertextList {
    type ParameterSet = RadixCompactCiphertextListConformanceParams;

    fn is_conformant(&self, params: &RadixCompactCiphertextListConformanceParams) -> bool {
        self.num_blocks_per_integer == params.num_blocks_per_integer
            && self
                .ct_list
                .is_conformant(&params.to_shortint_ct_list_conformance_parameters())
    }
}

impl CompactCiphertextList {
    pub fn expand_one<T: IntegerRadixCiphertext>(&self) -> T {
        let mut blocks = self.ct_list.expand();
        blocks.truncate(self.num_blocks_per_integer);
        T::from(blocks)
    }

    /// Deconstruct a [`CompactCiphertextList`] into its constituents.
    pub fn into_raw_parts(self) -> (crate::shortint::ciphertext::CompactCiphertextList, usize) {
        let Self {
            ct_list,
            num_blocks_per_integer,
        } = self;
        (ct_list, num_blocks_per_integer)
    }

    /// Construct a [`CompactCiphertextList`] from its constituents.
    ///
    /// # Panics
    ///
    /// Panics if the constituents are not compatible with each others.
    pub fn from_raw_parts(
        ct_list: crate::shortint::ciphertext::CompactCiphertextList,
        num_blocks_per_integer: usize,
    ) -> Self {
        assert_eq!(
            ct_list.ct_list.lwe_ciphertext_count().0 % num_blocks_per_integer,
            0,
            "CompactCiphertextList LweCiphertextCount is expected \
            to be a multiple of {num_blocks_per_integer}, got {:?}",
            ct_list.ct_list.lwe_ciphertext_count()
        );

        Self {
            ct_list,
            num_blocks_per_integer,
        }
    }

    pub fn ciphertext_count(&self) -> usize {
        self.ct_list.ct_list.lwe_ciphertext_count().0 / self.num_blocks_per_integer
    }

    pub fn expand<T: IntegerRadixCiphertext>(&self) -> Vec<T> {
        let mut all_block_iter = self.ct_list.expand().into_iter();
        let num_ct = self.ciphertext_count();
        let mut ciphertexts = Vec::with_capacity(num_ct);

        for _ in 0..num_ct {
            let ct_blocks = all_block_iter
                .by_ref()
                .take(self.num_blocks_per_integer)
                .collect::<Vec<_>>();
            if ct_blocks.len() < self.num_blocks_per_integer {
                break;
            }
            let ct = T::from(ct_blocks);
            ciphertexts.push(ct);
        }

        ciphertexts
    }

    pub fn size_elements(&self) -> usize {
        self.ct_list.size_elements()
    }

    pub fn size_bytes(&self) -> usize {
        self.ct_list.size_bytes()
    }
}
