mod internal;
#[cfg(test)]
mod test;

use crate::shortint::client_key::atomic_pattern::EncryptionAtomicPattern;

use crate::backward_compatibility::xof_key_set::CompressedXofKeySetVersions;
use crate::core_crypto::commons::generators::MaskRandomGenerator;

use crate::core_crypto::commons::math::random::RandomGenerator;
use crate::core_crypto::prelude::*;

use crate::integer::ciphertext::CompressedNoiseSquashingCompressionKey;
use crate::integer::noise_squashing::CompressedNoiseSquashingKey;

use crate::named::Named;

use crate::{
    integer, shortint, ClientKey, CompactPublicKey, CompressedCompactPublicKey,
    CompressedReRandomizationKeySwitchingKey, CompressedServerKey, Config, ServerKey, Tag,
};
use serde::{Deserialize, Serialize};

use crate::core_crypto::commons::generators::NoiseRandomGenerator;
use crate::shortint::atomic_pattern::compressed::CompressedAtomicPatternServerKey;
use crate::shortint::ciphertext::MaxDegree;
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::ShortintParameterSet;
use tfhe_csprng::seeders::XofSeed;
use tfhe_versionable::Versionize;

use crate::high_level_api::backward_compatibility::xof_key_set::XofKeySetVersions;
use crate::integer::key_switching_key::CompressedKeySwitchingKeyMaterial;

use crate::high_level_api::keys::expanded::IntegerExpandedServerKey;

// Generation order:
//
// 1) Public key (enc params)
// 2) Compression key
// 3) Decompression key
// 4) KSK (compute params)
// 5) BSK (compute params)
// 6) Mod Switch Key (compute params)
// 7) BSK (SnS params)
// 8) Mod Switch Key (SnS params)
// 9) KSK (encryption params to compute params)
// 10) Re-Rand KSK
// 11) SNS Compression Key

/// Compressed KeySet which respects the [Threshold (Fully) Homomorphic Encryption]
/// regarding the random generator used, and the order of key generation
///
/// [Threshold (Fully) Homomorphic Encryption]: https://eprint.iacr.org/2025/699
#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(CompressedXofKeySetVersions)]
pub struct CompressedXofKeySet {
    seed: XofSeed,
    compressed_public_key: CompressedCompactPublicKey,
    compressed_server_key: CompressedServerKey,
}

impl Named for CompressedXofKeySet {
    const NAME: &'static str = "high_level_api::CompressedXofKeySet";
}

impl CompressedXofKeySet {
    /// Generates a pair of ClientKey and CompressedXofKeySet
    ///
    /// This uses the domain separators as they are defined in the original paper.
    ///
    /// * `config` must use a dedicated public key
    pub fn generate(
        config: Config,
        private_seed_bytes: Vec<u8>,
        security_bits: u32,
        max_norm_hwt: NormalizedHammingWeightBound,
        tag: Tag,
    ) -> crate::Result<(ClientKey, Self)> {
        let private_separator = *b"TFHEKGen";
        let public_separator = *b"TFHE_GEN";
        let private_seed = XofSeed::new(private_seed_bytes, private_separator);

        Self::generate_with_separators(
            config,
            private_seed,
            public_separator,
            security_bits,
            max_norm_hwt,
            tag,
        )
    }

    /// Generates a pair of ClientKey and CompressedXofKeySet
    ///
    /// This function allows to use different domain separators than
    /// the ones defined in the original paper.
    ///
    /// * `config` must use a dedicated public key
    pub fn generate_with_separators(
        config: Config,
        private_seed: XofSeed,
        public_seed_separator: [u8; XofSeed::DOMAIN_SEP_LEN],
        security_bits: u32,
        max_norm_hwt: NormalizedHammingWeightBound,
        tag: Tag,
    ) -> crate::Result<(ClientKey, Self)> {
        let mut private_generator = RandomGenerator::<DefaultRandomGenerator>::new(private_seed);

        let mut public_seed_bytes = vec![0u8; security_bits as usize / 8];
        private_generator.fill_slice_with_random_uniform(&mut public_seed_bytes);
        let public_seed = XofSeed::new(public_seed_bytes, public_seed_separator);

        let mut secret_generator = SecretRandomGenerator::from_raw_parts(private_generator);

        let client_key = ClientKey::generate_with_pre_seeded_generator(
            config,
            max_norm_hwt,
            tag,
            &mut secret_generator,
        )?;

        let xof_key_set = Self::generate_with_pre_seeded_generator(
            public_seed,
            &client_key,
            secret_generator.into_raw_parts(),
        )?;

        Ok((client_key, xof_key_set))
    }

    fn generate_with_pre_seeded_generator<G>(
        pub_seed: XofSeed,
        ck: &ClientKey,
        private_generator: RandomGenerator<G>,
    ) -> crate::Result<Self>
    where
        G: ByteRandomGenerator + ParallelByteRandomGenerator,
    {
        let Some(dedicated_pk_key) = ck.key.dedicated_compact_private_key.as_ref() else {
            return Err(crate::error!("Dedicated compact private key is required"));
        };

        let mask_random_generator = MaskRandomGenerator::<G>::new(pub_seed.clone());
        let noise_random_generator = NoiseRandomGenerator::from_raw_parts(private_generator);
        let mut encryption_rand_gen = EncryptionRandomGenerator::from_raw_parts(
            mask_random_generator,
            noise_random_generator,
        );

        let computation_parameters: ShortintParameterSet = ck.key.key.parameters().into();
        let shortint_client_key = &ck.key.key.key;

        // First, the public key used to encrypt
        // It uses separate parameters from the computation ones
        let compressed_public_key = CompressedCompactPublicKey::generate_with_pre_seeded_generator(
            dedicated_pk_key,
            ck.tag.clone(),
            &mut encryption_rand_gen,
        );

        let glwe_secret_key = match &shortint_client_key.atomic_pattern {
            AtomicPatternClientKey::Standard(ap) => &ap.glwe_secret_key,
            AtomicPatternClientKey::KeySwitch32(ks32_ap) => &ks32_ap.glwe_secret_key,
        };

        let compression_key = ck
                .key
                .compression_key
                .as_ref()
                .map(|private_compression_key| {
                    // Compression requires EncryptionKey::Big, but if that was not the case,
                    // the private_compression_key would not have been generated
                    integer::compression_keys::CompressedCompressionKey::generate_with_pre_seeded_generator(
                        private_compression_key,
                        glwe_secret_key,
                        computation_parameters.ciphertext_modulus(),
                        &mut encryption_rand_gen,
                    )
                });

        let decompression_key = ck
                .key
                .compression_key
                .as_ref()
                .map(|private_compression_key| {
                    integer::compression_keys::CompressedDecompressionKey::generate_with_pre_seeded_generator(
                        private_compression_key,
                        glwe_secret_key,
                        computation_parameters,
                        &mut encryption_rand_gen,
                    )
                });

        // Now, we generate the server key (ksk, then bsk)
        let integer_compressed_server_key = {
            let compressed_ap_server_key =
                CompressedAtomicPatternServerKey::generate_with_pre_seeded_generator(
                    &shortint_client_key.atomic_pattern,
                    &mut encryption_rand_gen,
                );

            let max_degree = MaxDegree::integer_radix_server_key(
                computation_parameters.message_modulus(),
                computation_parameters.carry_modulus(),
            );

            integer::CompressedServerKey::from_raw_parts(
                shortint::CompressedServerKey::from_raw_parts(
                    compressed_ap_server_key,
                    computation_parameters.message_modulus(),
                    computation_parameters.carry_modulus(),
                    max_degree,
                    computation_parameters.max_noise_level(),
                ),
            )
        };

        let noise_squashing_bs_key =
            ck.key
                .noise_squashing_private_key
                .as_ref()
                .map(|noise_squashing_key| {
                    CompressedNoiseSquashingKey::generate_with_pre_seeded_generator(
                        noise_squashing_key,
                        &shortint_client_key.atomic_pattern,
                        &mut encryption_rand_gen,
                    )
                });

        // Generate the key switching material that will allow going from
        // the public key's dedicated parameters to the computation parameters
        let pk_to_sk_ksk_params = dedicated_pk_key.1;

        let integer_ksk_material = {
            let noise_distrib = computation_parameters
                .noise_distribution_for_key_choice(pk_to_sk_ksk_params.destination_key);

            let key_switching_key = match &ck.key.key.key.atomic_pattern {
                AtomicPatternClientKey::Standard(std_ap) => {
                    let target_private_key = match pk_to_sk_ksk_params.destination_key {
                        EncryptionKeyChoice::Big => std_ap.glwe_secret_key.as_lwe_secret_key(),
                        EncryptionKeyChoice::Small => std_ap.lwe_secret_key.as_view(),
                    };

                    allocate_and_generate_new_seeded_lwe_key_switching_key_with_pre_seeded_generator(
                        &dedicated_pk_key.0.key.key(),
                        &target_private_key,
                        pk_to_sk_ksk_params.ks_base_log,
                        pk_to_sk_ksk_params.ks_level,
                        noise_distrib,
                        computation_parameters.ciphertext_modulus(),
                        &mut encryption_rand_gen,
                    )
                }
                AtomicPatternClientKey::KeySwitch32(ks32_ap) => ks32_ap
                    .generate_seeded_key_switching_key_with_pre_seeded_generator(
                        &dedicated_pk_key.0.key.key(),
                        &pk_to_sk_ksk_params,
                        &mut encryption_rand_gen,
                    ),
            };

            CompressedKeySwitchingKeyMaterial {
                material: shortint::key_switching_key::CompressedKeySwitchingKeyMaterial {
                    key_switching_key,
                    cast_rshift: 0,
                    destination_key: dedicated_pk_key.1.destination_key,
                    destination_atomic_pattern: ck.key.key.key.atomic_pattern.kind().into(),
                },
            }
        };

        // Generate the key switching material that will allow going from
        // the public key's dedicated parameters to the re-rand
        let cpk_re_randomization_key_switching_key_material = ck
            .key
            .re_randomization_ksk_gen_info()?
            .as_ref()
            .map(|key_gen_info| {
                CompressedReRandomizationKeySwitchingKey::generate_with_pre_seeded_generator(
                    glwe_secret_key,
                    computation_parameters.glwe_noise_distribution(),
                    computation_parameters.ciphertext_modulus(),
                    computation_parameters.atomic_pattern().into(),
                    key_gen_info,
                    &mut encryption_rand_gen,
                )
            });

        let noise_squashing_compression_key =
            ck.key.noise_squashing_compression_private_key.as_ref().map(
                |ns_compression_priv_key| {
                    CompressedNoiseSquashingCompressionKey::generate_with_pre_seeded_generator(
                        ns_compression_priv_key,
                        ck.key.noise_squashing_private_key.as_ref().unwrap(),
                        &mut encryption_rand_gen,
                    )
                },
            );

        let compressed_server_key = CompressedServerKey::from_raw_parts(
            integer_compressed_server_key,
            Some(integer_ksk_material),
            compression_key,
            decompression_key,
            noise_squashing_bs_key,
            noise_squashing_compression_key,
            cpk_re_randomization_key_switching_key_material,
            ck.tag.clone(),
        );

        Ok(Self {
            seed: pub_seed,
            compressed_public_key,
            compressed_server_key,
        })
    }

    /// Decompress the KeySet
    pub fn decompress(self) -> crate::Result<XofKeySet> {
        let tag = self.compressed_server_key.tag.clone();
        let (public_key, expanded_server_key) = self.expand();
        let integer_server_key = expanded_server_key.convert_to_cpu();
        let server_key = ServerKey {
            key: std::sync::Arc::new(integer_server_key),
            tag,
        };

        Ok(XofKeySet {
            public_key,
            server_key,
        })
    }

    fn expand(self) -> (CompactPublicKey, IntegerExpandedServerKey) {
        let mut mask_generator = MaskRandomGenerator::<DefaultRandomGenerator>::new(self.seed);

        let public_key = self
            .compressed_public_key
            .decompress_with_pre_seeded_generator(&mut mask_generator);

        let expanded_server_key = self
            .compressed_server_key
            .decompress_with_pre_seeded_generator(&mut mask_generator);

        (public_key, expanded_server_key)
    }

    pub fn from_raw_parts(
        pub_seed: XofSeed,
        compressed_public_key: CompressedCompactPublicKey,
        compressed_server_key: CompressedServerKey,
    ) -> Self {
        Self {
            seed: pub_seed,
            compressed_public_key,
            compressed_server_key,
        }
    }

    pub fn into_raw_parts(self) -> (XofSeed, CompressedCompactPublicKey, CompressedServerKey) {
        let Self {
            seed,
            compressed_public_key,
            compressed_server_key,
        } = self;

        (seed, compressed_public_key, compressed_server_key)
    }
}

/// KeySet which contains the public material (public key and server key)
/// of the [Threshold (Fully) Homomorphic Encryption]
///
/// To create such key set, first create a [CompressedXofKeySet] then decompress it
///
/// [Threshold (Fully) Homomorphic Encryption]: https://eprint.iacr.org/2025/699
#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(XofKeySetVersions)]
pub struct XofKeySet {
    public_key: CompactPublicKey,
    server_key: ServerKey,
}

impl Named for XofKeySet {
    const NAME: &'static str = "high_level_api::XofKeySet";
}

impl XofKeySet {
    pub fn into_raw_parts(self) -> (CompactPublicKey, ServerKey) {
        (self.public_key, self.server_key)
    }
}
