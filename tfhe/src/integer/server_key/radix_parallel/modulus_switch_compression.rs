use crate::integer::ciphertext::{
    BaseRadixCiphertext, BaseSignedRadixCiphertext, CompressedModulusSwitchedRadixCiphertext,
    CompressedModulusSwitchedRadixCiphertextGeneric,
    CompressedModulusSwitchedSignedRadixCiphertext,
};
use crate::integer::{RadixCiphertext, ServerKey, SignedRadixCiphertext};
use crate::shortint::Ciphertext;
use rayon::prelude::*;

impl ServerKey {
    /// Compresses a ciphertext to have a smaller serialization size
    ///
    /// See [`CompressedModulusSwitchedRadixCiphertext#example`] for usage
    pub fn switch_modulus_and_compress_parallelized(
        &self,
        ct: &RadixCiphertext,
    ) -> CompressedModulusSwitchedRadixCiphertext {
        CompressedModulusSwitchedRadixCiphertext(
            self.switch_modulus_and_compress_generic_parallelized(&ct.blocks),
        )
    }
    /// Decompresses a compressed ciphertext
    /// This operation costs a PBS
    ///
    /// See [`CompressedModulusSwitchedRadixCiphertext#example`] for usage
    pub fn decompress_parallelized(
        &self,
        compressed_ct: &CompressedModulusSwitchedRadixCiphertext,
    ) -> RadixCiphertext {
        BaseRadixCiphertext {
            blocks: self.decompress_generic_parallelized(&compressed_ct.0),
        }
    }

    /// Compresses a signed ciphertext to have a smaller serialization size
    ///
    /// See [`CompressedModulusSwitchedSignedRadixCiphertext#example`] for usage
    pub fn switch_modulus_and_compress_signed_parallelized(
        &self,
        ct: &SignedRadixCiphertext,
    ) -> CompressedModulusSwitchedSignedRadixCiphertext {
        CompressedModulusSwitchedSignedRadixCiphertext(
            self.switch_modulus_and_compress_generic_parallelized(&ct.blocks),
        )
    }
    /// Decompresses a signed compressed ciphertext
    /// This operation costs a PBS
    ///
    /// See [`CompressedModulusSwitchedSignedRadixCiphertext#example`] for usage
    pub fn decompress_signed_parallelized(
        &self,
        compressed_ct: &CompressedModulusSwitchedSignedRadixCiphertext,
    ) -> SignedRadixCiphertext {
        BaseSignedRadixCiphertext {
            blocks: self.decompress_generic_parallelized(&compressed_ct.0),
        }
    }

    #[allow(clippy::int_plus_one)]
    fn switch_modulus_and_compress_generic_parallelized(
        &self,
        blocks: &[Ciphertext],
    ) -> CompressedModulusSwitchedRadixCiphertextGeneric {
        assert!(
            self.message_modulus().0 <= self.carry_modulus().0,
            "Compression does not support message_modulus > carry_modulus"
        );
        assert!(
            self.key.max_noise_level.get() >= self.message_modulus().0 + 1,
            "Compression does not support max_noise_level < message_modulus + 1"
        );

        let paired_blocks;

        let last_block;

        let len = blocks.len();

        if len % 2 == 0 {
            paired_blocks = blocks;
            last_block = None;
        } else {
            paired_blocks = &blocks[..len - 1];
            last_block = Some(blocks.last().unwrap());
        }

        let paired_blocks = paired_blocks
            .par_chunks_exact(2)
            .map(|pair| {
                let mut packed = pair[0].clone();

                let scaled = self
                    .key
                    .unchecked_scalar_mul(&pair[1], self.message_modulus().0 as u8);

                self.key.unchecked_add_assign(&mut packed, &scaled);

                self.key.switch_modulus_and_compress(&packed)
            })
            .collect();

        let last_block = last_block.map(|a| self.key.switch_modulus_and_compress(a));

        CompressedModulusSwitchedRadixCiphertextGeneric {
            paired_blocks,
            last_block,
        }
    }

    fn decompress_generic_parallelized(
        &self,
        compressed_ct: &CompressedModulusSwitchedRadixCiphertextGeneric,
    ) -> Vec<Ciphertext> {
        let message_extract = self
            .key
            .generate_lookup_table(|x| x % self.message_modulus().0);

        let carry_extract = self
            .key
            .generate_lookup_table(|x| x / self.message_modulus().0);

        let mut blocks: Vec<Ciphertext> = compressed_ct
            .paired_blocks
            .par_iter()
            .flat_map(|a| {
                [
                    self.key
                        .decompress_and_apply_lookup_table(a, &message_extract),
                    self.key
                        .decompress_and_apply_lookup_table(a, &carry_extract),
                ]
            })
            .collect();

        if let Some(last_block) = compressed_ct.last_block.as_ref() {
            blocks.push(
                self.key
                    .decompress_and_apply_lookup_table(last_block, &message_extract),
            );
        }

        blocks
    }
}
