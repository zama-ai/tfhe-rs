use crate::conformance::ParameterSetConformant;
use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::prelude::{ActivatedRandomGenerator, KeyswitchKeyConformanceParams};
use crate::high_level_api::backward_compatibility::keys::*;
use crate::integer::compression_keys::{
    CompressedCompressionKey, CompressedDecompressionKey, CompressionKey, CompressionPrivateKeys,
    DecompressionKey,
};
use crate::integer::public_key::CompactPublicKey;
use crate::integer::CompressedCompactPublicKey;
use crate::shortint::key_switching_key::KeySwitchingKeyConformanceParams;
use crate::shortint::parameters::list_compression::CompressionParameters;
use crate::shortint::parameters::{
    CompactPublicKeyEncryptionParameters, ShortintKeySwitchingParameters,
};
use crate::shortint::{EncryptionKeyChoice, MessageModulus, PBSParameters};
use crate::{Config, Error};
use concrete_csprng::seeders::Seed;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

// Clippy complained that fields end in _parameters, :roll_eyes:
#[derive(Copy, Clone, Debug, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(IntegerConfigVersions)]
#[allow(clippy::struct_field_names)]
pub(crate) struct IntegerConfig {
    pub(crate) block_parameters: crate::shortint::PBSParameters,
    pub(crate) dedicated_compact_public_key_parameters: Option<(
        crate::shortint::parameters::CompactPublicKeyEncryptionParameters,
        crate::shortint::parameters::ShortintKeySwitchingParameters,
    )>,
    pub(crate) compression_parameters: Option<CompressionParameters>,
}

impl IntegerConfig {
    pub(crate) fn new(
        block_parameters: crate::shortint::PBSParameters,
        dedicated_compact_public_key_parameters: Option<(
            crate::shortint::parameters::CompactPublicKeyEncryptionParameters,
            crate::shortint::parameters::ShortintKeySwitchingParameters,
        )>,
    ) -> Self {
        Self {
            block_parameters,
            dedicated_compact_public_key_parameters,
            compression_parameters: None,
        }
    }

    pub(in crate::high_level_api) fn default_big() -> Self {
        #[cfg(not(feature = "gpu"))]
        let params =
            crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64.into();
        #[cfg(feature = "gpu")]
        let params =
            crate::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64
                .into();
        Self {
            block_parameters: params,
            dedicated_compact_public_key_parameters: None,
            compression_parameters: None,
        }
    }

    pub(in crate::high_level_api) fn default_small() -> Self {
        Self {
            block_parameters:
                crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64.into(),
            dedicated_compact_public_key_parameters: None,
            compression_parameters: None,
        }
    }

    pub fn enable_compression(&mut self, compression_parameters: CompressionParameters) {
        self.compression_parameters = Some(compression_parameters);
    }

    pub fn public_key_encryption_parameters(
        &self,
    ) -> Result<crate::shortint::parameters::CompactPublicKeyEncryptionParameters, crate::Error>
    {
        if let Some(p) = self.dedicated_compact_public_key_parameters {
            Ok(p.0)
        } else {
            Ok(self.block_parameters.try_into()?)
        }
    }
}

pub type CompactPrivateKey = (
    crate::integer::CompactPrivateKey<Vec<u64>>,
    crate::shortint::parameters::key_switching::ShortintKeySwitchingParameters,
);

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(IntegerClientKeyVersions)]
pub(crate) struct IntegerClientKey {
    pub(crate) key: crate::integer::ClientKey,
    pub(crate) dedicated_compact_private_key: Option<CompactPrivateKey>,
    pub(crate) compression_key: Option<CompressionPrivateKeys>,
}

impl IntegerClientKey {
    pub(crate) fn with_seed(config: IntegerConfig, seed: Seed) -> Self {
        assert!(
            (config.block_parameters.message_modulus().0) == 2 || config.block_parameters.message_modulus().0 == 4,
            "This API only supports parameters for which the MessageModulus is 2 or 4 (1 or 2 bits per block)",
        );
        let mut seeder = DeterministicSeeder::<ActivatedRandomGenerator>::new(seed);
        let cks = crate::shortint::engine::ShortintEngine::new_from_seeder(&mut seeder)
            .new_client_key(config.block_parameters.into());

        let key = crate::integer::ClientKey::from(cks);

        let compression_key = config
            .compression_parameters
            .map(|params| key.new_compression_private_key(params));

        let dedicated_compact_private_key = config
            .dedicated_compact_public_key_parameters
            .map(|p| (crate::integer::CompactPrivateKey::new(p.0), p.1));
        Self {
            key,
            dedicated_compact_private_key,
            compression_key,
        }
    }

    /// Deconstruct an [`IntegerClientKey`] into its constituents.
    pub fn into_raw_parts(
        self,
    ) -> (
        crate::integer::ClientKey,
        Option<CompactPrivateKey>,
        Option<CompressionPrivateKeys>,
    ) {
        let Self {
            key,
            dedicated_compact_private_key,
            compression_key,
        } = self;
        (key, dedicated_compact_private_key, compression_key)
    }

    /// Construct a, [`IntegerClientKey`] from its constituents.
    ///
    /// # Panics
    ///
    /// Panics if the provided raw parts are not compatible with the provided parameters.
    pub fn from_raw_parts(
        key: crate::integer::ClientKey,
        dedicated_compact_private_key: Option<CompactPrivateKey>,
        compression_key: Option<CompressionPrivateKeys>,
    ) -> Self {
        let shortint_cks: &crate::shortint::ClientKey = key.as_ref();

        if let Some(dedicated_compact_private_key) = dedicated_compact_private_key.as_ref() {
            assert_eq!(
                shortint_cks.parameters.message_modulus(),
                dedicated_compact_private_key
                    .0
                    .key
                    .parameters()
                    .message_modulus,
            );
            assert_eq!(
                shortint_cks.parameters.carry_modulus(),
                dedicated_compact_private_key
                    .0
                    .key
                    .parameters()
                    .carry_modulus,
            );
        }

        Self {
            key,
            dedicated_compact_private_key,
            compression_key,
        }
    }

    pub(crate) fn block_parameters(&self) -> crate::shortint::parameters::PBSParameters {
        self.key.parameters()
    }
}

impl From<IntegerConfig> for IntegerClientKey {
    fn from(config: IntegerConfig) -> Self {
        assert!(
            (config.block_parameters.message_modulus().0) == 2 || config.block_parameters.message_modulus().0 == 4,
            "This API only supports parameters for which the MessageModulus is 2 or 4 (1 or 2 bits per block)",
        );

        let key = crate::integer::ClientKey::new(config.block_parameters);

        let dedicated_compact_private_key = config
            .dedicated_compact_public_key_parameters
            .map(|p| (crate::integer::CompactPrivateKey::new(p.0), p.1));

        let compression_key = config
            .compression_parameters
            .map(|params| key.new_compression_private_key(params));

        Self {
            key,
            dedicated_compact_private_key,
            compression_key,
        }
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(IntegerServerKeyVersions)]
pub struct IntegerServerKey {
    pub(crate) key: crate::integer::ServerKey,
    // Storing a KeySwitchingKeyView would require a self reference -> nightmare
    // Storing a KeySwitchingKey would mean cloning the ServerKey and means more memory traffic to
    // fetch the exact same key, so we store the part of the key that are not ServerKeys and we
    // will create views when required
    pub(crate) cpk_key_switching_key_material:
        Option<crate::integer::key_switching_key::KeySwitchingKeyMaterial>,
    pub(crate) compression_key: Option<CompressionKey>,
    pub(crate) decompression_key: Option<DecompressionKey>,
}

impl IntegerServerKey {
    pub(in crate::high_level_api) fn new(client_key: &IntegerClientKey) -> Self {
        let cks = &client_key.key;

        let (compression_key, decompression_key) = client_key.compression_key.as_ref().map_or_else(
            || (None, None),
            |a| {
                let (compression_key, decompression_key) =
                    cks.new_compression_decompression_keys(a);
                (Some(compression_key), Some(decompression_key))
            },
        );

        let base_integer_key = crate::integer::ServerKey::new_radix_server_key(cks);

        let cpk_key_switching_key_material =
            client_key
                .dedicated_compact_private_key
                .as_ref()
                .map(|(private_key, ksk_params)| {
                    let build_helper =
                        crate::integer::key_switching_key::KeySwitchingKeyBuildHelper::new(
                            (private_key, None),
                            (cks, &base_integer_key),
                            *ksk_params,
                        );

                    build_helper.into()
                });
        Self {
            key: base_integer_key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
        }
    }

    pub(in crate::high_level_api) fn pbs_key(&self) -> &crate::integer::ServerKey {
        &self.key
    }

    pub(in crate::high_level_api) fn cpk_casting_key(
        &self,
    ) -> Option<crate::integer::key_switching_key::KeySwitchingKeyView> {
        self.cpk_key_switching_key_material.as_ref().map(|k| {
            crate::integer::key_switching_key::KeySwitchingKeyView::from_keyswitching_key_material(
                k.as_view(),
                self.pbs_key(),
                None,
            )
        })
    }

    pub(in crate::high_level_api) fn message_modulus(&self) -> MessageModulus {
        self.key.message_modulus()
    }
}

#[cfg(feature = "gpu")]
pub struct IntegerCudaServerKey {
    pub(crate) key: crate::integer::gpu::CudaServerKey,
    pub(crate) compression_key:
        Option<crate::integer::gpu::list_compression::server_keys::CudaCompressionKey>,
    pub(crate) decompression_key:
        Option<crate::integer::gpu::list_compression::server_keys::CudaDecompressionKey>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(IntegerCompressedServerKeyVersions)]
pub struct IntegerCompressedServerKey {
    pub(crate) key: crate::integer::CompressedServerKey,
    pub(crate) cpk_key_switching_key_material:
        Option<crate::integer::key_switching_key::CompressedKeySwitchingKeyMaterial>,
    pub(crate) compression_key: Option<CompressedCompressionKey>,
    pub(crate) decompression_key: Option<CompressedDecompressionKey>,
}

impl IntegerCompressedServerKey {
    pub(in crate::high_level_api) fn new(client_key: &IntegerClientKey) -> Self {
        let cks = &client_key.key;

        let key = crate::integer::CompressedServerKey::new_radix_compressed_server_key(cks);

        let cpk_key_switching_key_material =
            client_key
                .dedicated_compact_private_key
                .as_ref()
                .map(|(private_key, ksk_params)| {
                    let build_helper =
                    crate::integer::key_switching_key::CompressedKeySwitchingKeyBuildHelper::new(
                        (private_key, None),
                        (cks, &key),
                        *ksk_params,
                    );

                    build_helper.into()
                });

        let (compression_key, decompression_key) =
            client_key
                .compression_key
                .as_ref()
                .map_or((None, None), |compression_private_key| {
                    let (compression_keys, decompression_keys) = client_key
                        .key
                        .new_compressed_compression_decompression_keys(compression_private_key);

                    (Some(compression_keys), Some(decompression_keys))
                });

        Self {
            key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
        }
    }

    pub fn into_raw_parts(
        self,
    ) -> (
        crate::integer::CompressedServerKey,
        Option<crate::integer::key_switching_key::CompressedKeySwitchingKeyMaterial>,
        Option<CompressedCompressionKey>,
        Option<CompressedDecompressionKey>,
    ) {
        (
            self.key,
            self.cpk_key_switching_key_material,
            self.compression_key,
            self.decompression_key,
        )
    }

    pub fn from_raw_parts(
        key: crate::integer::CompressedServerKey,
        cpk_key_switching_key_material: Option<
            crate::integer::key_switching_key::CompressedKeySwitchingKeyMaterial,
        >,
        compression_key: Option<CompressedCompressionKey>,
        decompression_key: Option<CompressedDecompressionKey>,
    ) -> Self {
        Self {
            key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
        }
    }

    pub(in crate::high_level_api) fn decompress(&self) -> IntegerServerKey {
        let compression_key = self
            .compression_key
            .as_ref()
            .map(CompressedCompressionKey::decompress);

        let decompression_key = self
            .decompression_key
            .as_ref()
            .map(CompressedDecompressionKey::decompress);

        IntegerServerKey {
            key: self.key.decompress(),
            cpk_key_switching_key_material: self.cpk_key_switching_key_material.as_ref().map(
                crate::integer::key_switching_key::CompressedKeySwitchingKeyMaterial::decompress,
            ),
            compression_key,
            decompression_key,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(IntegerCompactPublicKeyVersions)]
pub(in crate::high_level_api) struct IntegerCompactPublicKey {
    pub(in crate::high_level_api) key: CompactPublicKey,
}

impl IntegerCompactPublicKey {
    pub(in crate::high_level_api) fn new(client_key: &IntegerClientKey) -> Self {
        Self::try_new(client_key).expect("Incompatible parameters")
    }

    pub(in crate::high_level_api) fn try_new(client_key: &IntegerClientKey) -> Result<Self, Error> {
        let key = match &client_key.dedicated_compact_private_key {
            Some(compact_private_key) => CompactPublicKey::try_new(&compact_private_key.0)?,
            None => CompactPublicKey::try_new(&client_key.key)?,
        };

        Ok(Self { key })
    }

    pub fn into_raw_parts(self) -> CompactPublicKey {
        self.key
    }

    pub fn from_raw_parts(key: CompactPublicKey) -> Self {
        Self { key }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(IntegerCompressedCompactPublicKeyVersions)]
pub(in crate::high_level_api) struct IntegerCompressedCompactPublicKey {
    pub(in crate::high_level_api) key: CompressedCompactPublicKey,
}

impl IntegerCompressedCompactPublicKey {
    pub(in crate::high_level_api) fn new(client_key: &IntegerClientKey) -> Self {
        Self::try_new(client_key).expect("Incompatible parameters")
    }

    pub(in crate::high_level_api) fn try_new(client_key: &IntegerClientKey) -> Result<Self, Error> {
        let key = match &client_key.dedicated_compact_private_key {
            Some(compact_private_key) => {
                CompressedCompactPublicKey::try_new(&compact_private_key.0)?
            }
            None => CompressedCompactPublicKey::try_new(&client_key.key)?,
        };

        Ok(Self { key })
    }

    /// Deconstruct a [`IntegerCompressedCompactPublicKey`] into its constituents.
    pub fn into_raw_parts(self) -> CompressedCompactPublicKey {
        self.key
    }

    /// Construct a [`IntegerCompressedCompactPublicKey`] from its constituents.
    pub fn from_raw_parts(key: CompressedCompactPublicKey) -> Self {
        Self { key }
    }

    pub(in crate::high_level_api) fn decompress(&self) -> IntegerCompactPublicKey {
        IntegerCompactPublicKey {
            key: CompressedCompactPublicKey::decompress(&self.key),
        }
    }
}

#[allow(clippy::struct_field_names)]
pub struct IntegerServerKeyConformanceParams {
    pub sk_param: PBSParameters,
    pub cpk_param: Option<(
        CompactPublicKeyEncryptionParameters,
        ShortintKeySwitchingParameters,
    )>,
    pub compression_param: Option<CompressionParameters>,
}

impl From<Config> for IntegerServerKeyConformanceParams {
    fn from(value: Config) -> Self {
        Self {
            sk_param: value.inner.block_parameters,
            cpk_param: value.inner.dedicated_compact_public_key_parameters,
            compression_param: value.inner.compression_parameters,
        }
    }
}

impl
    TryFrom<(
        PBSParameters,
        CompactPublicKeyEncryptionParameters,
        ShortintKeySwitchingParameters,
    )> for KeySwitchingKeyConformanceParams
{
    type Error = std::num::TryFromIntError;

    fn try_from(
        (sk_params, cpk_params, ks_params): (
            PBSParameters,
            CompactPublicKeyEncryptionParameters,
            ShortintKeySwitchingParameters,
        ),
    ) -> Result<Self, std::num::TryFromIntError> {
        let output_lwe_size = match ks_params.destination_key {
            EncryptionKeyChoice::Big => sk_params
                .glwe_dimension()
                .to_equivalent_lwe_dimension(sk_params.polynomial_size()),

            EncryptionKeyChoice::Small => sk_params.lwe_dimension(),
        }
        .to_lwe_size();

        let cast_rshift = (sk_params.carry_modulus().0.ilog2()
            + sk_params.message_modulus().0.ilog2()
            - cpk_params.carry_modulus.0.ilog2()
            - cpk_params.message_modulus.0.ilog2())
        .try_into()?;

        Ok(Self {
            keyswitch_key_conformance_params: KeyswitchKeyConformanceParams {
                decomp_base_log: ks_params.ks_base_log,
                decomp_level_count: ks_params.ks_level,
                output_lwe_size,
                input_lwe_dimension: cpk_params.encryption_lwe_dimension,
                ciphertext_modulus: sk_params.ciphertext_modulus(),
            },
            cast_rshift,
            destination_key: ks_params.destination_key,
        })
    }
}

impl ParameterSetConformant for IntegerServerKey {
    type ParameterSet = IntegerServerKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
        } = self;

        let cpk_key_switching_key_material_is_ok = match (
            parameter_set.cpk_param.as_ref(),
            cpk_key_switching_key_material.as_ref(),
        ) {
            (None, None) => true,
            (Some((cpk_params, ks_params)), Some(cpk_key_switching_key_material)) => {
                let cpk_param = (parameter_set.sk_param, *cpk_params, *ks_params)
                    .try_into()
                    .unwrap();
                cpk_key_switching_key_material.is_conformant(&cpk_param)
            }
            _ => return false,
        };

        let compression_is_ok = match (
            compression_key.as_ref(),
            decompression_key.as_ref(),
            parameter_set.compression_param.as_ref(),
        ) {
            (None, None, None) => true,
            (Some(compression_key), Some(decompression_key), Some(compression_param)) => {
                let compression_param = (parameter_set.sk_param, *compression_param).into();

                compression_key.is_conformant(&compression_param)
                    && decompression_key.is_conformant(&compression_param)
            }
            _ => return false,
        };

        key.is_conformant(&parameter_set.sk_param)
            && cpk_key_switching_key_material_is_ok
            && compression_is_ok
    }
}

impl ParameterSetConformant for IntegerCompressedServerKey {
    type ParameterSet = IntegerServerKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
        } = self;

        let cpk_key_switching_key_material_is_ok = match (
            parameter_set.cpk_param.as_ref(),
            cpk_key_switching_key_material.as_ref(),
        ) {
            (None, None) => true,
            (Some((cpk_params, ks_params)), Some(cpk_key_switching_key_material)) => {
                let cpk_param = (parameter_set.sk_param, *cpk_params, *ks_params)
                    .try_into()
                    .unwrap();
                cpk_key_switching_key_material.is_conformant(&cpk_param)
            }
            _ => return false,
        };

        let compression_is_ok = match (
            compression_key.as_ref(),
            decompression_key.as_ref(),
            parameter_set.compression_param.as_ref(),
        ) {
            (None, None, None) => true,
            (Some(compression_key), Some(decompression_key), Some(compression_param)) => {
                let compression_param = (parameter_set.sk_param, *compression_param).into();

                compression_key.is_conformant(&compression_param)
                    && decompression_key.is_conformant(&compression_param)
            }
            _ => return false,
        };

        key.is_conformant(&parameter_set.sk_param)
            && cpk_key_switching_key_material_is_ok
            && compression_is_ok
    }
}

impl ParameterSetConformant for IntegerCompactPublicKey {
    type ParameterSet = CompactPublicKeyEncryptionParameters;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self { key } = self;

        key.is_conformant(parameter_set)
    }
}

impl ParameterSetConformant for IntegerCompressedCompactPublicKey {
    type ParameterSet = CompactPublicKeyEncryptionParameters;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self { key } = self;

        key.is_conformant(parameter_set)
    }
}
