use crate::conformance::ParameterSetConformant;
use crate::core_crypto::commons::numeric::UnsignedNumeric;
use crate::integer::backward_compatibility::noise_squashing::*;
use crate::integer::block_decomposition::{BlockRecomposer, RecomposableFrom, SignExtendable};
use crate::integer::ciphertext::{
    BooleanBlock, IntegerRadixCiphertext, SquashedNoiseIntegerCiphertext,
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
    pub fn new(params: NoiseSquashingParameters) -> Self {
        Self {
            key: crate::shortint::noise_squashing::NoiseSquashingPrivateKey::new(params),
        }
    }

    pub fn decrypt_radix<T>(&self, ct: &SquashedNoiseIntegerCiphertext) -> crate::Result<T>
    where
        T: RecomposableFrom<u128> + UnsignedNumeric,
    {
        if !matches!(ct, SquashedNoiseIntegerCiphertext::RadixCiphertext { .. }) {
            return Err(crate::error!(
                "Tried to decrypt the wrong kind of \
                SquashedNoiseIntegerCiphertext with decrypt_radix, \
                expected SquashedNoiseIntegerCiphertext::RadixCiphertext."
            ));
        }

        match ct {
            SquashedNoiseIntegerCiphertext::RadixCiphertext {
                packed_blocks,
                original_block_count: _,
            } => {
                let bits_in_packed_block = (packed_blocks[0].message_modulus().0
                    * packed_blocks[0].carry_modulus().0)
                    .ilog2();
                let decrypted_packed_block_iter = packed_blocks
                    .iter()
                    .map(|block| self.key.decrypt_squashed_noise_ciphertext(block));

                Ok(BlockRecomposer::recompose_unsigned(
                    decrypted_packed_block_iter,
                    bits_in_packed_block,
                ))
            }
            _ => unreachable!(),
        }
    }

    pub fn decrypt_signed_radix<T>(&self, ct: &SquashedNoiseIntegerCiphertext) -> crate::Result<T>
    where
        T: RecomposableFrom<u128> + SignExtendable,
    {
        if !matches!(
            ct,
            SquashedNoiseIntegerCiphertext::SignedRadixCiphertext { .. }
        ) {
            return Err(crate::error!(
                "Tried to decrypt the wrong kind of \
                SquashedNoiseIntegerCiphertext with decrypt_signed_radix, \
                expected SquashedNoiseIntegerCiphertext::SignedRadixCiphertext."
            ));
        }

        match ct {
            SquashedNoiseIntegerCiphertext::SignedRadixCiphertext {
                packed_blocks,
                original_block_count,
            } => {
                let bits_in_packed_block = (packed_blocks[0].message_modulus().0
                    * packed_blocks[0].carry_modulus().0)
                    .ilog2();
                // Packed block has a message modulus with 2x the number of bits vs. the original
                let bits_in_original_block = bits_in_packed_block / 2;
                let original_block_count: u32 = (*original_block_count)
                    .try_into()
                    .map_err(|e| crate::error!("{e:?}"))?;
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
            _ => unreachable!(),
        }
    }

    pub fn decrypt_bool(&self, ct: &SquashedNoiseIntegerCiphertext) -> crate::Result<bool> {
        if !matches!(ct, SquashedNoiseIntegerCiphertext::BooleanBlock { .. }) {
            return Err(crate::error!(
                "Tried to decrypt the wrong kind of \
                SquashedNoiseIntegerCiphertext with decrypt_bool, \
                expected SquashedNoiseIntegerCiphertext::BooleanBlock."
            ));
        }

        match ct {
            SquashedNoiseIntegerCiphertext::BooleanBlock { ciphertext } => {
                let decrypted = self.key.decrypt_squashed_noise_ciphertext(ciphertext);

                Ok(decrypted != 0)
            }
            _ => unreachable!(),
        }
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

    pub fn squash_radix_ciphertext_noise<Ct: IntegerRadixCiphertext>(
        &self,
        src_server_key: &ServerKey,
        ciphertext: &Ct,
    ) -> SquashedNoiseIntegerCiphertext {
        let msg_mod = src_server_key.message_modulus().0;
        let original_block_count = ciphertext.blocks().len();

        let packed_blocks: Vec<_> = ciphertext
            .blocks()
            .par_chunks(2)
            .map(|two_values| {
                let first_block = &two_values[0];
                let second_block = two_values.get(1).map_or_else(
                    || src_server_key.key.create_trivial(0),
                    |ct| {
                        src_server_key
                            .key
                            .unchecked_scalar_mul(ct, msg_mod.try_into().unwrap())
                    },
                );

                self.key.squash_ciphertext_noise(
                    &src_server_key.key.unchecked_add(first_block, &second_block),
                    &src_server_key.key,
                )
            })
            .collect();

        if Ct::IS_SIGNED {
            SquashedNoiseIntegerCiphertext::SignedRadixCiphertext {
                packed_blocks,
                original_block_count,
            }
        } else {
            SquashedNoiseIntegerCiphertext::RadixCiphertext {
                packed_blocks,
                original_block_count,
            }
        }
    }

    pub fn squash_boolean_block_noise(
        &self,
        src_server_key: &ServerKey,
        boolean_block: &BooleanBlock,
    ) -> SquashedNoiseIntegerCiphertext {
        SquashedNoiseIntegerCiphertext::BooleanBlock {
            ciphertext: self
                .key
                .squash_ciphertext_noise(&boolean_block.0, &src_server_key.key),
        }
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

        key.is_conformant(parameter_set)
    }
}

impl ParameterSetConformant for CompressedNoiseSquashingKey {
    type ParameterSet = NoiseSquashingKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self { key } = self;

        key.is_conformant(parameter_set)
    }
}
