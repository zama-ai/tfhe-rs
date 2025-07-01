use crate::conformance::ParameterSetConformant;
use crate::core_crypto::commons::numeric::UnsignedNumeric;
use crate::integer::backward_compatibility::noise_squashing::*;
use crate::integer::block_decomposition::{BlockRecomposer, RecomposableFrom, SignExtendable};
use crate::integer::ciphertext::{
    BooleanBlock, RadixCiphertext, SignedRadixCiphertext, SquashedNoiseBooleanBlock,
    SquashedNoiseRadixCiphertext, SquashedNoiseSignedRadixCiphertext,
};
use crate::integer::server_key::ServerKey;
use crate::integer::ClientKey;
use crate::named::Named;
use crate::shortint::noise_squashing::NoiseSquashingKeyConformanceParams;
use crate::shortint::parameters::NoiseSquashingParameters;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(NoiseSquashingPrivateKeyVersions)]
pub struct NoiseSquashingPrivateKey {
    pub(crate) key: crate::shortint::noise_squashing::NoiseSquashingPrivateKey,
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(NoiseSquashingKeyVersions)]
pub struct NoiseSquashingKey {
    pub(crate) key: crate::shortint::noise_squashing::NoiseSquashingKey,
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(CompressedNoiseSquashingKeyVersions)]
pub struct CompressedNoiseSquashingKey {
    pub(crate) key: crate::shortint::noise_squashing::CompressedNoiseSquashingKey,
}

impl Named for NoiseSquashingPrivateKey {
    const NAME: &'static str = "integer::NoiseSquashingPrivateKey";
}

impl Named for NoiseSquashingKey {
    const NAME: &'static str = "integer::NoiseSquashingKey";
}

impl Named for CompressedNoiseSquashingKey {
    const NAME: &'static str = "integer::CompressedNoiseSquashingKey";
}

impl NoiseSquashingPrivateKey {
    pub fn noise_squashing_parameters(&self) -> NoiseSquashingParameters {
        self.key.noise_squashing_parameters()
    }
}

impl CompressedNoiseSquashingKey {
    pub fn decompress(&self) -> NoiseSquashingKey {
        NoiseSquashingKey {
            key: self.key.decompress(),
        }
    }

    pub fn into_raw_parts(self) -> crate::shortint::noise_squashing::CompressedNoiseSquashingKey {
        let Self { key } = self;
        key
    }

    pub fn from_raw_parts(
        key: crate::shortint::noise_squashing::CompressedNoiseSquashingKey,
    ) -> Self {
        Self { key }
    }
}

impl NoiseSquashingPrivateKey {
    pub fn new_compressed_noise_squashing_key(
        &self,
        client_key: &ClientKey,
    ) -> CompressedNoiseSquashingKey {
        client_key.new_compressed_noise_squashing_key(self)
    }

    pub fn new(params: NoiseSquashingParameters) -> Self {
        assert!(
            params.carry_modulus.0 >= params.message_modulus.0,
            "NoiseSquashingPrivateKey requires its CarryModulus {:?} to be greater \
            or equal to its MessageModulus {:?}",
            params.carry_modulus.0,
            params.message_modulus.0,
        );

        Self {
            key: crate::shortint::noise_squashing::NoiseSquashingPrivateKey::new(params),
        }
    }

    pub fn decrypt_radix<T>(&self, ct: &SquashedNoiseRadixCiphertext) -> crate::Result<T>
    where
        T: RecomposableFrom<u128> + UnsignedNumeric,
    {
        let SquashedNoiseRadixCiphertext {
            packed_blocks,
            original_block_count,
        } = ct;

        if packed_blocks.is_empty() {
            return Ok(T::ZERO);
        }

        let packed_blocks_msg_mod = packed_blocks[0].message_modulus();
        let packed_blocks_carry_mod = packed_blocks[0].carry_modulus();

        if packed_blocks_carry_mod.0 < packed_blocks_msg_mod.0 {
            return Err(crate::error!(
                "Input blocks cannot hold properly packed data and cannot be decrypted. \
                CarryModulus ({packed_blocks_carry_mod:?}) should be greater or equal to \
                the MessageModulus ({packed_blocks_msg_mod:?})",
            ));
        }

        if !packed_blocks.iter().all(|block| {
            block.message_modulus() == packed_blocks_msg_mod
                && block.carry_modulus() == packed_blocks_carry_mod
        }) {
            return Err(crate::error!(
                "Inconsistent message and carry moduli in provided SquashedNoiseRadixCiphertext."
            ));
        }

        let key_msg_mod = self.key.noise_squashing_parameters().message_modulus;
        let key_carry_mod = self.key.noise_squashing_parameters().carry_modulus;

        if packed_blocks_msg_mod != key_msg_mod || packed_blocks_carry_mod != key_carry_mod {
            return Err(crate::error!(
                "Input SquashedNoiseRadixCiphertext has incompatible \
                message modulus {packed_blocks_msg_mod:?} or \
                carry modulus {packed_blocks_carry_mod:?} with the current \
                NoiseSquashingPrivateKey message modulus {key_msg_mod:?}, \
                carry modulus {key_carry_mod:?}."
            ));
        }

        // We pack messages together so the number of bits per block is related to the msg_mod
        // squared, we only require the carry to be big enough to hold a message
        let bits_in_packed_block = (packed_blocks_msg_mod.0 * packed_blocks_msg_mod.0).ilog2();
        // Packed block has a message modulus with 2x the number of bits vs. the original
        let bits_in_original_block = bits_in_packed_block / 2;
        let original_block_count = *original_block_count as u32;
        let original_bit_size = bits_in_original_block * original_block_count;
        let decrypted_packed_block_iter = packed_blocks
            .iter()
            .map(|block| self.key.decrypt_squashed_noise_ciphertext(block));

        Ok(BlockRecomposer::recompose_unsigned_with_size(
            decrypted_packed_block_iter,
            bits_in_packed_block,
            original_bit_size,
        ))
    }

    pub fn decrypt_signed_radix<T>(
        &self,
        ct: &SquashedNoiseSignedRadixCiphertext,
    ) -> crate::Result<T>
    where
        T: RecomposableFrom<u128> + SignExtendable,
    {
        let SquashedNoiseSignedRadixCiphertext {
            packed_blocks,
            original_block_count,
        } = ct;

        if packed_blocks.is_empty() {
            return Ok(T::ZERO);
        }

        let packed_blocks_msg_mod = packed_blocks[0].message_modulus();
        let packed_blocks_carry_mod = packed_blocks[0].carry_modulus();

        if packed_blocks_carry_mod.0 < packed_blocks_msg_mod.0 {
            return Err(crate::error!(
                "Input blocks cannot hold properly packed data and cannot be decrypted. \
                CarryModulus ({packed_blocks_carry_mod:?}) should be greater or equal to \
                the MessageModulus ({packed_blocks_msg_mod:?})",
            ));
        }

        if !packed_blocks.iter().all(|block| {
            block.message_modulus() == packed_blocks_msg_mod
                && block.carry_modulus() == packed_blocks_carry_mod
        }) {
            return Err(crate::error!(
                "Inconsistent message and carry moduli in provided \
                SquashedNoiseSignedRadixCiphertext"
            ));
        }

        let key_msg_mod = self.key.noise_squashing_parameters().message_modulus;
        let key_carry_mod = self.key.noise_squashing_parameters().carry_modulus;

        if packed_blocks_msg_mod != key_msg_mod || packed_blocks_carry_mod != key_carry_mod {
            return Err(crate::error!(
                "Input SquashedNoiseSignedRadixCiphertext has incompatible \
                message modulus {packed_blocks_msg_mod:?} or \
                carry modulus {packed_blocks_carry_mod:?} with the current \
                NoiseSquashingPrivateKey message modulus {key_msg_mod:?}, \
                carry modulus {key_carry_mod:?}."
            ));
        }

        // We pack messages together so the number of bits per block is related to the msg_mod
        // squared, we only require the carry to be big enough to hold a message
        let bits_in_packed_block = (packed_blocks_msg_mod.0 * packed_blocks_msg_mod.0).ilog2();
        // Packed block has a message modulus with 2x the number of bits vs. the original
        let bits_in_original_block = bits_in_packed_block / 2;
        let original_block_count = *original_block_count as u32;
        let original_bit_size = bits_in_original_block * original_block_count;
        let decrypted_packed_block_iter = packed_blocks
            .iter()
            .map(|block| self.key.decrypt_squashed_noise_ciphertext(block));

        Ok(BlockRecomposer::recompose_signed_with_size(
            decrypted_packed_block_iter,
            bits_in_packed_block,
            original_bit_size,
        ))
    }

    pub fn decrypt_bool(&self, ct: &SquashedNoiseBooleanBlock) -> crate::Result<bool> {
        let SquashedNoiseBooleanBlock { ciphertext } = ct;

        let boolean_block_msg_mod = ciphertext.message_modulus();
        let boolean_block_carry_mod = ciphertext.carry_modulus();

        let key_msg_mod = self.key.noise_squashing_parameters().message_modulus;
        let key_carry_mod = self.key.noise_squashing_parameters().carry_modulus;

        if boolean_block_msg_mod != key_msg_mod || boolean_block_carry_mod != key_carry_mod {
            return Err(crate::error!(
                "Input SquashedNoiseBooleanBlock has incompatible \
                message modulus {boolean_block_msg_mod:?} or \
                carry modulus {boolean_block_carry_mod:?} with the current \
                NoiseSquashingPrivateKey message modulus {key_msg_mod:?}, \
                carry modulus {key_carry_mod:?}."
            ));
        }

        let decrypted = self.key.decrypt_squashed_noise_ciphertext(ciphertext);

        Ok(decrypted != 0)
    }

    pub fn into_raw_parts(self) -> crate::shortint::noise_squashing::NoiseSquashingPrivateKey {
        let Self { key } = self;
        key
    }

    pub fn from_raw_parts(key: crate::shortint::noise_squashing::NoiseSquashingPrivateKey) -> Self {
        Self { key }
    }
}

impl NoiseSquashingKey {
    pub fn into_raw_parts(self) -> crate::shortint::noise_squashing::NoiseSquashingKey {
        let Self { key } = self;
        key
    }

    pub fn from_raw_parts(key: crate::shortint::noise_squashing::NoiseSquashingKey) -> Self {
        Self { key }
    }

    pub fn squash_radix_ciphertext_noise(
        &self,
        src_server_key: &ServerKey,
        ciphertext: &RadixCiphertext,
    ) -> crate::Result<SquashedNoiseRadixCiphertext> {
        let original_block_count = ciphertext.blocks.len();

        let packed_blocks = ciphertext
            .blocks
            .par_chunks(2)
            .map(|two_values| {
                let packed = src_server_key.pack_block_chunk(two_values);

                self.key
                    .checked_squash_ciphertext_noise(&packed, &src_server_key.key)
            })
            .collect::<crate::Result<Vec<_>>>()?;

        Ok(SquashedNoiseRadixCiphertext {
            packed_blocks,
            original_block_count,
        })
    }

    pub fn squash_signed_radix_ciphertext_noise(
        &self,
        src_server_key: &ServerKey,
        ciphertext: &SignedRadixCiphertext,
    ) -> crate::Result<SquashedNoiseSignedRadixCiphertext> {
        let original_block_count = ciphertext.blocks.len();

        let packed_blocks = ciphertext
            .blocks
            .par_chunks(2)
            .map(|two_values| {
                let packed = src_server_key.pack_block_chunk(two_values);

                self.key
                    .checked_squash_ciphertext_noise(&packed, &src_server_key.key)
            })
            .collect::<crate::Result<Vec<_>>>()?;

        Ok(SquashedNoiseSignedRadixCiphertext {
            packed_blocks,
            original_block_count,
        })
    }

    pub fn squash_boolean_block_noise(
        &self,
        src_server_key: &ServerKey,
        boolean_block: &BooleanBlock,
    ) -> crate::Result<SquashedNoiseBooleanBlock> {
        Ok(SquashedNoiseBooleanBlock {
            ciphertext: self
                .key
                .checked_squash_ciphertext_noise(&boolean_block.0, &src_server_key.key)?,
        })
    }
}

impl ClientKey {
    pub fn new_compressed_noise_squashing_key(
        &self,
        noise_squashing_private_key: &NoiseSquashingPrivateKey,
    ) -> CompressedNoiseSquashingKey {
        CompressedNoiseSquashingKey {
            key: self
                .key
                .new_compressed_noise_squashing_key(&noise_squashing_private_key.key),
        }
    }

    pub fn new_noise_squashing_key(
        &self,
        noise_squashing_private_key: &NoiseSquashingPrivateKey,
    ) -> NoiseSquashingKey {
        NoiseSquashingKey {
            key: self
                .key
                .new_noise_squashing_key(&noise_squashing_private_key.key),
        }
    }
}

impl CompressedNoiseSquashingKey {
    pub fn new(
        client_key: &ClientKey,
        noise_squashing_private_key: &NoiseSquashingPrivateKey,
    ) -> Self {
        client_key.new_compressed_noise_squashing_key(noise_squashing_private_key)
    }
}

impl NoiseSquashingKey {
    pub fn new(
        client_key: &ClientKey,
        noise_squashing_private_key: &NoiseSquashingPrivateKey,
    ) -> Self {
        client_key.new_noise_squashing_key(noise_squashing_private_key)
    }
}

impl ParameterSetConformant for NoiseSquashingKey {
    type ParameterSet = NoiseSquashingKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self { key } = self;

        // The atomic pattern we support requires packing
        if key.carry_modulus().0 < key.message_modulus().0 {
            return false;
        }

        key.is_conformant(parameter_set)
    }
}

impl ParameterSetConformant for CompressedNoiseSquashingKey {
    type ParameterSet = NoiseSquashingKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self { key } = self;

        // The atomic pattern we support requires packing
        if key.carry_modulus().0 < key.message_modulus().0 {
            return false;
        }

        key.is_conformant(parameter_set)
    }
}
