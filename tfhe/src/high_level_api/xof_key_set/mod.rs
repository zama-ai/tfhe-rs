mod internal;
mod parts;
#[cfg(test)]
mod test;

pub use parts::XofParts;

use crate::backward_compatibility::xof_key_set::{
    CompressedXofKeySetVersions, XofSeedStartVersions,
};
use crate::core_crypto::commons::generators::MaskRandomGenerator;
use crate::integer::oprf::CompressedOprfServerKey;
use crate::keys::{
    CompressedReRandomizationKey, IntegerServerKeyConformanceParams, ReRandomizationKeyGenInfo,
};
use crate::prelude::{ParameterSetConformant, Tagged};
use crate::shortint::client_key::atomic_pattern::EncryptionAtomicPattern;

use crate::core_crypto::commons::math::random::RandomGenerator;
use crate::core_crypto::prelude::*;

use crate::integer::ciphertext::CompressedNoiseSquashingCompressionKey;
use crate::integer::noise_squashing::CompressedNoiseSquashingKey;

use crate::named::Named;

use crate::shortint::parameters::CompactPublicKeyEncryptionParameters;
use crate::{
    integer, shortint, ClientKey, CompactPublicKey, CompressedCompactPublicKey,
    CompressedReRandomizationKeySwitchingKey, CompressedServerKey, Config, ServerKey, Tag,
};
use serde::{Deserialize, Serialize};
use tfhe_csprng::generators::aes_ctr::{AesCtrParams, TableIndex};
use tfhe_csprng::seeders::SeedKind;

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
// 10) If in the Re-Rand legacy case (network Public key + KSK) then:
//        - Re-Rand KSK
//     else:
//        - Re-Rand Public Key (stored in ServerKey) derived from compute params
// 11) SNS Compression Key
// 12) OPRF Key

/// Holds a [XofSeed] and everything needed to rebuild the generator that was seeded with it: the
/// byte it starts at, and which Aes variant derives the stream.
///
/// Which Aes variant was used has to be recorded: key sets serialized by tfhe-rs 1.6 and earlier
/// were derived with Aes-128 and must keep decompressing that way, while newly generated ones use
/// Aes-256.
///
/// Default conversion [From] a [XofSeed] selects the first byte and Aes-128, matching the legacy
/// behaviour; use [`XofSeedStart::new_aes256`] for the current default.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(XofSeedStartVersions)]
pub enum XofSeedStart {
    /// Generator starts at the first byte, stream derived with Aes-128.
    FirstByte(XofSeed),
    /// Replicates the tfhe-rs=1.5.4 csprng off by one. Aes-128 only.
    SecondByte(XofSeed),
    /// Generator starts at the first byte, stream derived with Aes-256.
    FirstByteAes256(XofSeed),
}

impl XofSeedStart {
    /// Starts at the first byte, deriving the stream with Aes-256.
    pub fn new_aes256(seed: XofSeed) -> Self {
        Self::FirstByteAes256(seed)
    }
}

impl From<XofSeed> for XofSeedStart {
    fn from(seed: XofSeed) -> Self {
        Self::FirstByte(seed)
    }
}

impl From<XofSeedStart> for AesCtrParams {
    fn from(val: XofSeedStart) -> Self {
        // Each arm names its Aes variant explicitly. Do NOT collapse these into `seed.into()`:
        // that would route through the `From<XofSeed> for SeedKind` default and silently give
        // every variant the same cipher, making key sets decompress against the wrong schedule.
        match val {
            XofSeedStart::FirstByte(seed) => Self {
                seed: SeedKind::xof_aes128(seed),
                first_index: TableIndex::FIRST,
            },
            XofSeedStart::SecondByte(seed) => Self {
                seed: SeedKind::xof_aes128(seed),
                first_index: TableIndex::SECOND,
            },
            XofSeedStart::FirstByteAes256(seed) => Self {
                seed: SeedKind::xof_aes256(seed),
                first_index: TableIndex::FIRST,
            },
        }
    }
}

/// Compressed KeySet which respects the [Threshold (Fully) Homomorphic Encryption]
/// regarding the random generator used, and the order of key generation
///
/// [Threshold (Fully) Homomorphic Encryption]: https://eprint.iacr.org/2025/699
#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(CompressedXofKeySetVersions)]
pub struct CompressedXofKeySet {
    seed: XofSeedStart,
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
        if security_bits == 0 {
            return Err(crate::error!("security_bits must be non-zero"));
        }
        // Relies on the `From<XofSeed>` default, which is Aes-256. Note that the private seed is
        // never serialized, so regenerating a key set from the same `private_seed_bytes` with a
        // version that used a different Aes variant yields a different ClientKey.
        let mut private_generator = RandomGenerator::<DefaultRandomGenerator>::new(private_seed);

        let mut public_seed_bytes = vec![0u8; security_bits.div_ceil(8) as usize];
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

    pub fn generate_with_pre_seeded_generator<G>(
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

        // Legacy: Generate the key switching material that will allow going from
        // the public key's dedicated parameters to the re-rand
        // New: Generate a derived CPK which does not need a keyswitching key
        let cpk_re_randomization_key = ck.key.re_randomization_key_gen_info()?.as_ref().map(
            |key_gen_info| match key_gen_info {
                ReRandomizationKeyGenInfo::LegacyDedicatedCPKWithKeySwitch { ksk_gen_info } => {
                    use CompressedReRandomizationKeySwitchingKey as CRRDKSK;
                    let ksk = CRRDKSK::generate_with_pre_seeded_generator(
                        glwe_secret_key,
                        computation_parameters.glwe_noise_distribution(),
                        computation_parameters.ciphertext_modulus(),
                        computation_parameters.atomic_pattern().into(),
                        ksk_gen_info,
                        &mut encryption_rand_gen,
                    );
                    CompressedReRandomizationKey::LegacyDedicatedCPK { ksk }
                }
                ReRandomizationKeyGenInfo::DerivedCPKWithoutKeySwitch {
                    derived_compact_private_key,
                } => {
                    use integer::CompressedCompactPublicKey;
                    CompressedReRandomizationKey::DerivedCPKWithoutKeySwitch {
                        cpk: CompressedCompactPublicKey::generate_with_pre_seeded_generator(
                            derived_compact_private_key,
                            &mut encryption_rand_gen,
                        ),
                    }
                }
            },
        );

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

        let oprf_key = ck.key.dedicated_oprf_private_key.as_ref().map(|sk| {
            CompressedOprfServerKey::generate_with_pre_seeded_generator(
                sk,
                &ck.key.key,
                &mut encryption_rand_gen,
            )
        });

        let compressed_server_key = CompressedServerKey::from_raw_parts(
            integer_compressed_server_key,
            Some(integer_ksk_material),
            compression_key,
            decompression_key,
            noise_squashing_bs_key,
            noise_squashing_compression_key,
            cpk_re_randomization_key,
            oprf_key,
            ck.tag.clone(),
        );

        Ok(Self {
            // Must match how `pub_seed` was consumed above, i.e. the `From<XofSeed>` default of
            // Aes-256 at the first byte, otherwise the key set decompresses against a different
            // stream than the one it was generated with.
            seed: XofSeedStart::new_aes256(pub_seed),
            compressed_public_key,
            compressed_server_key,
        })
    }

    /// Decompress the KeySet
    pub fn decompress(&self) -> XofKeySet {
        let tag = self.compressed_server_key.tag.clone();
        let (mut public_key, expanded_server_key) = self.expand();
        // Server key tag is the source of truth; sync public key
        public_key.tag_mut().set_data(tag.data());
        let integer_server_key = expanded_server_key.convert_to_cpu();
        let server_key = ServerKey {
            key: std::sync::Arc::new(integer_server_key),
            tag,
        };

        XofKeySet {
            public_key,
            server_key,
        }
    }

    fn expand(&self) -> (CompactPublicKey, IntegerExpandedServerKey) {
        let mut mask_generator =
            MaskRandomGenerator::<DefaultRandomGenerator>::new(self.seed.clone());

        let public_key = self
            .compressed_public_key
            .decompress_with_pre_seeded_generator(&mut mask_generator);

        let expanded_server_key = self
            .compressed_server_key
            .decompress_with_pre_seeded_generator(&mut mask_generator);

        (public_key, expanded_server_key)
    }

    pub fn from_raw_parts(
        pub_seed: impl Into<XofSeedStart>,
        mut compressed_public_key: CompressedCompactPublicKey,
        compressed_server_key: CompressedServerKey,
    ) -> Self {
        // Server key tag is the source of truth for Tagged impl
        compressed_public_key
            .tag_mut()
            .set_data(compressed_server_key.tag.data());
        Self {
            seed: pub_seed.into(),
            compressed_public_key,
            compressed_server_key,
        }
    }

    pub fn into_raw_parts(
        self,
    ) -> (
        XofSeedStart,
        CompressedCompactPublicKey,
        CompressedServerKey,
    ) {
        let Self {
            seed,
            mut compressed_public_key,
            compressed_server_key,
        } = self;

        // Server key tag is the source of truth for Tagged impl
        compressed_public_key
            .tag_mut()
            .set_data(compressed_server_key.tag.data());

        (seed, compressed_public_key, compressed_server_key)
    }

    /// Returns whether the inner [`CompressedServerKey`] carries a dedicated
    /// key-switching key material for the [`CompactPublicKey`].
    pub fn has_cpk_key_switching_key_material(&self) -> bool {
        self.compressed_server_key
            .has_cpk_key_switching_key_material()
    }

    /// Returns whether the inner [`CompressedServerKey`] carries a compression key.
    pub fn has_compression_key(&self) -> bool {
        self.compressed_server_key.has_compression_key()
    }

    /// Returns whether the inner [`CompressedServerKey`] carries a decompression key.
    pub fn has_decompression_key(&self) -> bool {
        self.compressed_server_key.has_decompression_key()
    }

    /// Returns whether the inner [`CompressedServerKey`] carries a noise squashing key.
    pub fn has_noise_squashing_key(&self) -> bool {
        self.compressed_server_key.has_noise_squashing_key()
    }

    /// Returns whether the inner [`CompressedServerKey`] carries a noise squashing
    /// compression key.
    pub fn has_noise_squashing_compression_key(&self) -> bool {
        self.compressed_server_key
            .has_noise_squashing_compression_key()
    }

    /// Returns whether the inner [`CompressedServerKey`] carries a re-randomization key.
    pub fn has_re_randomization_key(&self) -> bool {
        self.compressed_server_key.has_re_randomization_key()
    }

    /// Returns whether the inner [`CompressedServerKey`] carries a dedicated OPRF key.
    pub fn has_oprf_key(&self) -> bool {
        self.compressed_server_key.has_oprf_key()
    }
}

impl ParameterSetConformant for CompressedXofKeySet {
    type ParameterSet = Config;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let config = *parameter_set;
        if let Some((pke_params, _)) = &config.inner.dedicated_compact_public_key_parameters {
            if !self.compressed_public_key.is_conformant(pke_params) {
                return false;
            }
        } else {
            let shortint_param_set: ShortintParameterSet = config.inner.block_parameters.into();

            let Ok(compact_pk_params): Result<CompactPublicKeyEncryptionParameters, _> =
                shortint_param_set.try_into()
            else {
                return false;
            };

            if !self.compressed_public_key.is_conformant(&compact_pk_params) {
                return false;
            }
        }

        let sk_conformance_params = IntegerServerKeyConformanceParams::from(config);
        if !self
            .compressed_server_key
            .is_conformant(&sk_conformance_params)
        {
            return false;
        }

        true
    }
}

impl Tagged for CompressedXofKeySet {
    fn tag(&self) -> &Tag {
        &self.compressed_server_key.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.compressed_server_key.tag
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
    pub fn into_raw_parts(mut self) -> (CompactPublicKey, ServerKey) {
        // Server key tag is the source of truth for Tagged impl
        self.public_key
            .tag_mut()
            .set_data(self.server_key.tag.data());
        (self.public_key, self.server_key)
    }

    /// Returns whether the inner [`ServerKey`] carries a dedicated key-switching
    /// key material for the [`CompactPublicKey`].
    pub fn has_cpk_key_switching_key_material(&self) -> bool {
        self.server_key.has_cpk_key_switching_key_material()
    }

    /// Returns whether the inner [`ServerKey`] carries a compression key.
    pub fn has_compression_key(&self) -> bool {
        self.server_key.has_compression_key()
    }

    /// Returns whether the inner [`ServerKey`] carries a decompression key.
    pub fn has_decompression_key(&self) -> bool {
        self.server_key.has_decompression_key()
    }

    /// Returns whether the inner [`ServerKey`] carries a noise squashing key.
    pub fn has_noise_squashing_key(&self) -> bool {
        self.server_key.has_noise_squashing_key()
    }

    /// Returns whether the inner [`ServerKey`] carries a noise squashing
    /// compression key.
    pub fn has_noise_squashing_compression_key(&self) -> bool {
        self.server_key.has_noise_squashing_compression_key()
    }

    /// Returns whether the inner [`ServerKey`] carries a re-randomization key.
    pub fn has_re_randomization_key(&self) -> bool {
        self.server_key.has_re_randomization_key()
    }

    /// Returns whether the inner [`ServerKey`] carries a dedicated OPRF key.
    pub fn has_oprf_key(&self) -> bool {
        self.server_key.has_oprf_key()
    }
}

impl Tagged for XofKeySet {
    fn tag(&self) -> &Tag {
        &self.server_key.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.server_key.tag
    }
}

#[cfg(feature = "gpu")]
pub use gpu::CudaXofKeySet;

#[cfg(feature = "gpu")]
mod gpu {
    use super::{Tag, Tagged};
    use std::sync::Arc;

    use crate::{CompactPublicKey, CudaServerKey};

    /// Same KeySet as [XofKeySet](super::XofKeySet) but on GPU
    pub struct CudaXofKeySet {
        public_key: CompactPublicKey,
        server_key: CudaServerKey,
    }

    impl CudaXofKeySet {
        pub fn into_raw_parts(mut self) -> (CompactPublicKey, CudaServerKey) {
            // Server key tag is the source of truth for Tagged impl
            self.public_key
                .tag_mut()
                .set_data(self.server_key.tag.data());
            (self.public_key, self.server_key)
        }
    }

    impl Tagged for CudaXofKeySet {
        fn tag(&self) -> &Tag {
            &self.server_key.tag
        }

        fn tag_mut(&mut self) -> &mut Tag {
            &mut self.server_key.tag
        }
    }

    impl super::CompressedXofKeySet {
        pub fn decompress_to_gpu(&self) -> crate::Result<CudaXofKeySet> {
            self.decompress_to_specific_gpu(crate::CudaGpuChoice::default())
        }

        pub fn decompress_to_specific_gpu(
            &self,
            gpu_choice: impl Into<crate::CudaGpuChoice>,
        ) -> crate::Result<CudaXofKeySet> {
            let streams = gpu_choice.into().build_streams();
            let tag = self.compressed_server_key.tag.clone();

            let (mut public_key, expanded_server_key) = self.expand();
            // Server key tag is the source of truth; sync public key
            public_key.tag_mut().set_data(tag.data());
            let key = expanded_server_key.convert_to_gpu(&streams)?;

            let server_key = CudaServerKey {
                key: Arc::new(key),
                tag,
                streams,
            };

            Ok(CudaXofKeySet {
                public_key,
                server_key,
            })
        }
    }
}
