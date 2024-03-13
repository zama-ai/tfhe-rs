use crate::integer::ciphertext::{
    BaseRadixCiphertext, BaseSignedRadixCiphertext, CompressedModulusSwitchedRadixCiphertext,
    CompressedModulusSwitchedSignedRadixCiphertext,
};
use crate::integer::{RadixCiphertext, ServerKey, SignedRadixCiphertext};
use rayon::prelude::*;

impl ServerKey {
    /// Compresses a ciphertext to have a smaller serialization size
    ///
    /// See [`CompressedModulusSwitchedRadixCiphertext#example`] for usage
    pub fn switch_modulus_and_compress_parallelized(
        &self,
        ct: &RadixCiphertext,
    ) -> CompressedModulusSwitchedRadixCiphertext {
        let blocks = ct
            .blocks
            .par_iter()
            .map(|a| self.key.switch_modulus_and_compress(a))
            .collect();

        BaseRadixCiphertext { blocks }
    }
    /// Decompresses a compressed ciphertext
    /// This operation costs a PBS
    ///
    /// See [`CompressedModulusSwitchedRadixCiphertext#example`] for usage
    pub fn decompress_parallelized(
        &self,
        compressed_ct: &CompressedModulusSwitchedRadixCiphertext,
    ) -> RadixCiphertext {
        let blocks = compressed_ct
            .blocks
            .par_iter()
            .map(|a| self.key.decompress(a))
            .collect();

        BaseRadixCiphertext { blocks }
    }

    /// Compresses a signed ciphertext to have a smaller serialization size
    ///
    /// See [`CompressedModulusSwitchedSignedRadixCiphertext#example`] for usage
    pub fn switch_modulus_and_compress_signed_parallelized(
        &self,
        ct: &SignedRadixCiphertext,
    ) -> CompressedModulusSwitchedSignedRadixCiphertext {
        let blocks = ct
            .blocks
            .par_iter()
            .map(|a| self.key.switch_modulus_and_compress(a))
            .collect();

        BaseSignedRadixCiphertext { blocks }
    }
    /// Decompresses a signed compressed ciphertext
    /// This operation costs a PBS
    ///     
    /// See [`CompressedModulusSwitchedSignedRadixCiphertext#example`] for usage
    pub fn decompress_signed_parallelized(
        &self,
        compressed_ct: &CompressedModulusSwitchedSignedRadixCiphertext,
    ) -> SignedRadixCiphertext {
        let blocks = compressed_ct
            .blocks
            .par_iter()
            .map(|a| self.key.decompress(a))
            .collect();

        BaseSignedRadixCiphertext { blocks }
    }
}
