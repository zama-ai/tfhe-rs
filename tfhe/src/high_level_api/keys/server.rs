use super::ClientKey;
use crate::backward_compatibility::keys::{CompressedServerKeyVersions, ServerKeyVersions};
use crate::conformance::ParameterSetConformant;
#[cfg(feature = "gpu")]
use crate::core_crypto::gpu::CudaStreams;
#[cfg(feature = "gpu")]
use crate::high_level_api::keys::inner::IntegerCudaServerKey;
use crate::high_level_api::keys::{
    CompressedReRandomizationKey, IntegerCompressedServerKey, IntegerServerKey, ReRandomizationKey,
};
use crate::integer::ciphertext::{
    CompressedNoiseSquashingCompressionKey, NoiseSquashingCompressionKey,
};
use crate::integer::compression_keys::{
    CompressedCompressionKey, CompressedDecompressionKey, CompressionKey, DecompressionKey,
};
use crate::integer::noise_squashing::{CompressedNoiseSquashingKey, NoiseSquashingKey};
use crate::integer::parameters::IntegerCompactCiphertextListExpansionMode;
use crate::integer::public_key::compact::CompactPublicKey;
use crate::named::Named;
use crate::prelude::Tagged;
use crate::shortint::MessageModulus;
#[cfg(feature = "gpu")]
use crate::GpuIndex;
use crate::{Device, Tag};
#[cfg(feature = "hpu")]
pub(in crate::high_level_api) use hpu::HpuTaggedDevice;
use std::sync::Arc;
#[cfg(feature = "hpu")]
use tfhe_hpu_backend::prelude::HpuDevice;
use tfhe_versionable::Versionize;

/// Key of the server
///
/// This key contains the different keys needed to be able to do computations for
/// each data type.
///
/// For a server to be able to do some FHE computations, the client needs to send this key
/// beforehand.
///
/// Keys are stored in an Arc, so that cloning them is cheap
/// (compared to an actual clone hundreds of MB / GB), and cheap cloning is needed for
/// multithreading with less overhead)
#[derive(Clone, Versionize)]
#[versionize(ServerKeyVersions)]
pub struct ServerKey {
    pub(crate) key: Arc<IntegerServerKey>,
    pub(crate) tag: Tag,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReRandomizationSupport {
    NoSupport,
    LegacyDedicatedCPKWithKeySwitch,
    DerivedCPKWithoutKeySwitch,
}

impl ServerKey {
    pub fn new(keys: &ClientKey) -> Self {
        Self {
            key: Arc::new(IntegerServerKey::new(&keys.key)),
            tag: keys.tag.clone(),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn into_raw_parts(
        self,
    ) -> (
        crate::integer::ServerKey,
        Option<crate::integer::key_switching_key::KeySwitchingKeyMaterial>,
        Option<CompressionKey>,
        Option<DecompressionKey>,
        Option<NoiseSquashingKey>,
        Option<NoiseSquashingCompressionKey>,
        Option<ReRandomizationKey>,
        Tag,
    ) {
        let IntegerServerKey {
            key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
            noise_squashing_key,
            noise_squashing_compression_key,
            cpk_re_randomization_key,
        } = (*self.key).clone();

        (
            key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
            noise_squashing_key,
            noise_squashing_compression_key,
            cpk_re_randomization_key,
            self.tag,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_raw_parts(
        key: crate::integer::ServerKey,
        cpk_key_switching_key_material: Option<
            crate::integer::key_switching_key::KeySwitchingKeyMaterial,
        >,
        compression_key: Option<CompressionKey>,
        decompression_key: Option<DecompressionKey>,
        noise_squashing_key: Option<NoiseSquashingKey>,
        noise_squashing_compression_key: Option<NoiseSquashingCompressionKey>,
        cpk_re_randomization_key: Option<ReRandomizationKey>,
        tag: Tag,
    ) -> Self {
        Self {
            key: Arc::new(IntegerServerKey {
                key,
                cpk_key_switching_key_material,
                compression_key,
                decompression_key,
                noise_squashing_key,
                noise_squashing_compression_key,
                cpk_re_randomization_key,
            }),
            tag,
        }
    }

    pub(in crate::high_level_api) fn pbs_key(&self) -> &crate::integer::ServerKey {
        self.key.pbs_key()
    }

    #[cfg(feature = "strings")]
    pub(in crate::high_level_api) fn string_key(&self) -> crate::strings::ServerKeyRef<'_> {
        crate::strings::ServerKeyRef::new(self.key.pbs_key())
    }

    pub(in crate::high_level_api) fn cpk_casting_key(
        &self,
    ) -> Option<crate::integer::key_switching_key::KeySwitchingKeyView<'_>> {
        self.key.cpk_casting_key()
    }

    pub(in crate::high_level_api) fn legacy_re_randomization_cpk_casting_key(
        &self,
    ) -> crate::Result<Option<crate::integer::key_switching_key::KeySwitchingKeyMaterialView<'_>>>
    {
        self.key.legacy_re_randomization_cpk_casting_key()
    }

    pub(in crate::high_level_api) fn cpk_for_re_randomization_without_keyswitch(
        &self,
    ) -> crate::Result<&CompactPublicKey> {
        let re_randomization_key = self
            .key
            .cpk_re_randomization_key
            .as_ref()
            .ok_or(crate::high_level_api::errors::UninitializedReRandKey)?;

        match re_randomization_key {
            ReRandomizationKey::LegacyDedicatedCPK { .. } => Err(crate::error!(
                "Found legacy ReRandomizationKey while requesting \
                a ReRandomizationKey without keyswitch."
            )),
            ReRandomizationKey::DerivedCPK { cpk } => Ok(cpk),
        }
    }

    #[deprecated(
        since = "1.6.0",
        note = "prefer ServerKey::current_server_key_re_randomization_support"
    )]
    pub fn supports_ciphertext_re_randomization(&self) -> bool {
        // Legacy case: do we get a result containing the required keyswitching key?
        self.legacy_re_randomization_cpk_casting_key()
            .is_ok_and(|r| r.is_some())
        // New case, we don't need a KSK, do we have the CPK to encrypt 0s?
            || self.key.cpk_re_randomization_key.is_some()
    }

    pub fn current_server_key_re_randomization_support() -> crate::Result<ReRandomizationSupport> {
        use crate::high_level_api::errors::UninitializedServerKey;
        use crate::high_level_api::global_state;

        global_state::try_with_internal_keys(|key| {
            key.map_or_else(
                || Err(UninitializedServerKey.into()),
                |key| match key {
                    InternalServerKey::Cpu(key) => key
                        .key
                        .cpk_re_randomization_key
                        .as_ref()
                        .map_or(Ok(ReRandomizationSupport::NoSupport), |k| match k {
                            ReRandomizationKey::LegacyDedicatedCPK { .. } => {
                                Ok(ReRandomizationSupport::LegacyDedicatedCPKWithKeySwitch)
                            }
                            ReRandomizationKey::DerivedCPK { .. } => {
                                Ok(ReRandomizationSupport::DerivedCPKWithoutKeySwitch)
                            }
                        }),
                    #[cfg(feature = "gpu")]
                    InternalServerKey::Cuda(cuda_key) => {
                        if cuda_key
                            .key
                            .cpk_re_randomization_key_switching_key_material
                            .is_some()
                        {
                            Ok(ReRandomizationSupport::LegacyDedicatedCPKWithKeySwitch)
                        } else {
                            Ok(ReRandomizationSupport::NoSupport)
                        }
                    }
                    #[cfg(feature = "hpu")]
                    InternalServerKey::Hpu(_device) => Ok(ReRandomizationSupport::NoSupport),
                },
            )
        })
    }

    pub fn noise_squashing_key(
        &self,
    ) -> Option<&crate::integer::noise_squashing::NoiseSquashingKey> {
        self.key.noise_squashing_key.as_ref()
    }

    pub fn supports_noise_squashing(&self) -> bool {
        self.noise_squashing_key().is_some()
    }

    pub fn supports_noise_squashing_compression(&self) -> bool {
        self.key.noise_squashing_compression_key.is_some()
    }

    pub fn supports_compression(&self) -> bool {
        self.key.compression_key.is_some()
    }

    pub(in crate::high_level_api) fn message_modulus(&self) -> MessageModulus {
        self.key.message_modulus()
    }

    pub(in crate::high_level_api) fn integer_compact_ciphertext_list_expansion_mode(
        &self,
    ) -> IntegerCompactCiphertextListExpansionMode<'_> {
        self.cpk_casting_key().map_or_else(
            || {
                IntegerCompactCiphertextListExpansionMode::UnpackAndSanitizeIfNecessary(
                    self.pbs_key(),
                )
            },
            IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary,
        )
    }
}

impl Tagged for ServerKey {
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.tag
    }
}

impl Named for ServerKey {
    const NAME: &'static str = "high_level_api::ServerKey";
}

impl AsRef<crate::integer::ServerKey> for ServerKey {
    fn as_ref(&self) -> &crate::integer::ServerKey {
        &self.key.key
    }
}

// By default, serde does not derives Serialize/Deserialize for `Rc` and `Arc` types
// as they can result in multiple copies, since serializing has to serialize the actual data
// not the pointer.
//
// serde has a `rc` feature to allow deriving on Arc and Rc types
// but activating it in our lib would mean also activate it for all the dependency stack,
// so tfhe-rs users would have this feature enabled on our behalf and we don't want that
// so we implement the serialization / deserialization ourselves.
//
// In the case of our ServerKey, this is fine, we expect programs to only
// serialize and deserialize the same server key only once.
// The inner `Arc` are used to make copying a server key more performant before a `set_server_key`
// in multi-threading scenarios.
#[derive(serde::Serialize)]
// We directly versionize the `ServerKey` without having to use this intermediate type.
#[cfg_attr(dylint_lib = "tfhe_lints", allow(serialize_without_versionize))]
struct SerializableServerKey<'a> {
    pub(crate) integer_key: &'a IntegerServerKey,
    pub(crate) tag: &'a Tag,
}

impl serde::Serialize for ServerKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        SerializableServerKey {
            integer_key: &self.key,
            tag: &self.tag,
        }
        .serialize(serializer)
    }
}

#[derive(serde::Deserialize)]
struct DeserializableServerKey {
    pub(crate) integer_key: IntegerServerKey,
    pub(crate) tag: Tag,
}

impl<'de> serde::Deserialize<'de> for ServerKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        DeserializableServerKey::deserialize(deserializer).map(|deserialized| Self {
            key: Arc::new(deserialized.integer_key),
            tag: deserialized.tag,
        })
    }
}

/// Compressed ServerKey
///
/// A CompressedServerKey takes much less disk space / memory space than a
/// ServerKey.
///
/// It has to be decompressed into a ServerKey in order to be usable.
///
/// Once decompressed, it is not possible to recompress the key.
#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedServerKeyVersions)]
pub struct CompressedServerKey {
    pub(crate) integer_key: IntegerCompressedServerKey,
    pub(crate) tag: Tag,
}

impl CompressedServerKey {
    pub fn new(keys: &ClientKey) -> Self {
        Self {
            integer_key: IntegerCompressedServerKey::new(&keys.key),
            tag: keys.tag.clone(),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn into_raw_parts(
        self,
    ) -> (
        crate::integer::CompressedServerKey,
        Option<crate::integer::key_switching_key::CompressedKeySwitchingKeyMaterial>,
        Option<CompressedCompressionKey>,
        Option<CompressedDecompressionKey>,
        Option<CompressedNoiseSquashingKey>,
        Option<CompressedNoiseSquashingCompressionKey>,
        Option<CompressedReRandomizationKey>,
        Tag,
    ) {
        let (a, b, c, d, e, f, g) = self.integer_key.into_raw_parts();
        (a, b, c, d, e, f, g, self.tag)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_raw_parts(
        integer_key: crate::integer::CompressedServerKey,
        cpk_key_switching_key_material: Option<
            crate::integer::key_switching_key::CompressedKeySwitchingKeyMaterial,
        >,
        compression_key: Option<CompressedCompressionKey>,
        decompression_key: Option<CompressedDecompressionKey>,
        noise_squashing_key: Option<CompressedNoiseSquashingKey>,
        noise_squashing_compression_key: Option<CompressedNoiseSquashingCompressionKey>,
        cpk_re_randomization_key: Option<CompressedReRandomizationKey>,
        tag: Tag,
    ) -> Self {
        Self {
            integer_key: IntegerCompressedServerKey::from_raw_parts(
                integer_key,
                cpk_key_switching_key_material,
                compression_key,
                decompression_key,
                noise_squashing_key,
                noise_squashing_compression_key,
                cpk_re_randomization_key,
            ),
            tag,
        }
    }

    pub fn decompress(&self) -> ServerKey {
        ServerKey {
            key: Arc::new(self.integer_key.decompress()),
            tag: self.tag.clone(),
        }
    }

    #[cfg(feature = "gpu")]
    pub fn decompress_to_gpu(&self) -> CudaServerKey {
        self.decompress_to_specific_gpu(crate::CudaGpuChoice::default())
    }

    #[cfg(feature = "gpu")]
    pub fn decompress_to_specific_gpu(
        &self,
        gpu_choice: impl Into<crate::CudaGpuChoice>,
    ) -> CudaServerKey {
        let streams = gpu_choice.into().build_streams();
        let key = self
            .integer_key
            .expand()
            .convert_to_gpu(&streams)
            .expect("Unsupported configuration");
        CudaServerKey {
            key: Arc::new(key),
            tag: self.tag.clone(),
            streams,
        }
    }
}

impl Tagged for CompressedServerKey {
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.tag
    }
}

impl Named for CompressedServerKey {
    const NAME: &'static str = "high_level_api::CompressedServerKey";
}

#[cfg(feature = "gpu")]
#[derive(Clone)]
pub struct CudaServerKey {
    pub(crate) key: Arc<IntegerCudaServerKey>,
    pub(crate) tag: Tag,
    pub(crate) streams: CudaStreams,
}

#[cfg(feature = "gpu")]
impl CudaServerKey {
    pub(crate) fn message_modulus(&self) -> crate::shortint::MessageModulus {
        self.key.key.message_modulus
    }

    pub(crate) fn pbs_key(&self) -> &crate::integer::gpu::CudaServerKey {
        &self.key.key
    }

    pub fn gpu_indexes(&self) -> &[GpuIndex] {
        match &self.key.key.key_switching_key {
            CudaDynamicKeyswitchingKey::KeySwitch32(ksk_32) => ksk_32.d_vec.gpu_indexes.as_slice(),
            CudaDynamicKeyswitchingKey::Standard(std_key) => std_key.d_vec.gpu_indexes.as_slice(),
        }
    }
    pub(in crate::high_level_api) fn re_randomization_cpk_casting_key(
        &self,
    ) -> Option<&CudaKeySwitchingKeyMaterial> {
        self.key.re_randomization_cpk_casting_key()
    }
}

#[cfg(feature = "gpu")]
impl Tagged for CudaServerKey {
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.tag
    }
}

pub enum InternalServerKey {
    Cpu(ServerKey),
    #[cfg(feature = "gpu")]
    Cuda(CudaServerKey),
    #[cfg(feature = "hpu")]
    Hpu(HpuTaggedDevice),
}

pub enum InternalServerKeyRef<'a> {
    Cpu(&'a ServerKey),
    #[cfg(feature = "gpu")]
    Cuda(&'a CudaServerKey),
    #[cfg(feature = "hpu")]
    Hpu(&'a HpuTaggedDevice),
}

impl<'a> From<&'a InternalServerKey> for InternalServerKeyRef<'a> {
    fn from(value: &'a InternalServerKey) -> Self {
        match value {
            InternalServerKey::Cpu(sk) => InternalServerKeyRef::Cpu(sk),
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(sk) => InternalServerKeyRef::Cuda(sk),
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(sk) => InternalServerKeyRef::Hpu(sk),
        }
    }
}

impl<'a> From<&'a ServerKey> for InternalServerKeyRef<'a> {
    fn from(key: &'a ServerKey) -> Self {
        Self::Cpu(key)
    }
}

#[cfg(feature = "gpu")]
impl<'a> From<&'a CudaServerKey> for InternalServerKeyRef<'a> {
    fn from(key: &'a CudaServerKey) -> Self {
        Self::Cuda(key)
    }
}

impl InternalServerKey {
    pub(crate) fn device(&self) -> Device {
        match self {
            Self::Cpu(_) => Device::Cpu,
            #[cfg(feature = "gpu")]
            Self::Cuda(_) => Device::CudaGpu,
            #[cfg(feature = "hpu")]
            Self::Hpu(_) => Device::Hpu,
        }
    }
}

impl std::fmt::Debug for InternalServerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cpu(_) => f.debug_tuple("Cpu").finish(),
            #[cfg(feature = "gpu")]
            Self::Cuda(_) => f.debug_tuple("Cuda").finish(),
            #[cfg(feature = "hpu")]
            Self::Hpu(_) => f.debug_tuple("Hpu").finish(),
        }
    }
}

impl From<ServerKey> for InternalServerKey {
    fn from(value: ServerKey) -> Self {
        Self::Cpu(value)
    }
}
#[cfg(feature = "gpu")]
impl From<CudaServerKey> for InternalServerKey {
    fn from(value: CudaServerKey) -> Self {
        Self::Cuda(value)
    }
}

#[cfg(feature = "hpu")]
mod hpu {
    use super::*;

    pub struct HpuTaggedDevice {
        // The device holds the keys (there can only be one set of keys)
        // So we attach the tag to it instead of the key
        pub(in crate::high_level_api) device: Box<HpuDevice>,
        pub(in crate::high_level_api) tag: Tag,
    }

    impl From<(HpuDevice, CompressedServerKey)> for InternalServerKey {
        fn from((device, csks): (HpuDevice, CompressedServerKey)) -> Self {
            let CompressedServerKey { integer_key, tag } = csks;
            crate::integer::hpu::init_device(&device, integer_key.key).expect("Invalid key");
            Self::Hpu(HpuTaggedDevice {
                device: Box::new(device),
                tag,
            })
        }
    }
}

use crate::high_level_api::keys::inner::IntegerServerKeyConformanceParams;

#[cfg(feature = "gpu")]
use crate::integer::gpu::key_switching_key::CudaKeySwitchingKeyMaterial;
#[cfg(feature = "gpu")]
use crate::integer::gpu::server_key::CudaDynamicKeyswitchingKey;

impl ParameterSetConformant for ServerKey {
    type ParameterSet = IntegerServerKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self { key, tag: _ } = self;

        key.is_conformant(parameter_set)
    }
}

impl ParameterSetConformant for CompressedServerKey {
    type ParameterSet = IntegerServerKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            integer_key,
            tag: _,
        } = self;

        integer_key.is_conformant(parameter_set)
    }
}

#[cfg(test)]
mod test {
    use crate::high_level_api::keys::inner::IntegerServerKeyConformanceParams;
    use crate::prelude::ParameterSetConformant;
    use crate::shortint::parameters::{
        COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PARAM_KEYSWITCH_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    };
    use crate::shortint::ClassicPBSParameters;
    use crate::{ClientKey, CompressedServerKey, ConfigBuilder, ServerKey};

    #[test]
    fn conformance_hl_key() {
        {
            let config = ConfigBuilder::with_custom_parameters(
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            )
            .build();

            let ck = ClientKey::generate(config);
            let sk = ServerKey::new(&ck);

            let conformance_params = config.into();

            assert!(sk.is_conformant(&conformance_params));
        }
        {
            let config = ConfigBuilder::with_custom_parameters(
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            )
            .enable_compression(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .build();

            let ck = ClientKey::generate(config);
            let sk = ServerKey::new(&ck);

            let conformance_params = config.into();

            assert!(sk.is_conformant(&conformance_params));
        }
        {
            let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let cpk_params = PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let casting_params = PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let config = ConfigBuilder::with_custom_parameters(params)
                .use_dedicated_compact_public_key_parameters((cpk_params, casting_params))
                .build();

            let ck = ClientKey::generate(config);
            let sk = ServerKey::new(&ck);

            let conformance_params = config.into();

            assert!(sk.is_conformant(&conformance_params));
        }
        {
            let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let noise_squashing_params =
                NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let config = ConfigBuilder::with_custom_parameters(params)
                .enable_noise_squashing(noise_squashing_params)
                .build();

            let ck = ClientKey::generate(config);
            let sk = ServerKey::new(&ck);

            let conformance_params = config.into();

            assert!(sk.is_conformant(&conformance_params));
        }
        // Full blockchain configuration
        {
            let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let cpk_params = PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let casting_params = PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let comp_params = COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let noise_squashing_params =
                NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let noise_squashing_compression_params =
                NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let cpk_re_randomization_ksk_params =
                PARAM_KEYSWITCH_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let config = ConfigBuilder::with_custom_parameters(params)
                .use_dedicated_compact_public_key_parameters((cpk_params, casting_params))
                .enable_compression(comp_params)
                .enable_noise_squashing(noise_squashing_params)
                .enable_noise_squashing_compression(noise_squashing_compression_params)
                .enable_ciphertext_re_randomization(cpk_re_randomization_ksk_params)
                .build();

            let ck = ClientKey::generate(config);
            let sk = ServerKey::new(&ck);

            let conformance_params = config.into();

            assert!(sk.is_conformant(&conformance_params));
        }
    }

    #[test]
    fn broken_conformance_hl_key() {
        {
            let config = ConfigBuilder::with_custom_parameters(
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            )
            .build();

            let ck = ClientKey::generate(config);
            let sk = ServerKey::new(&ck);

            for modifier in [
                |sk_param: &mut ClassicPBSParameters| {
                    sk_param.lwe_dimension.0 += 1;
                },
                |sk_param: &mut ClassicPBSParameters| {
                    sk_param.polynomial_size.0 += 1;
                },
            ] {
                let mut sk_param = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

                modifier(&mut sk_param);

                let sk_param = sk_param.into();

                let conformance_params = IntegerServerKeyConformanceParams {
                    sk_param,
                    cpk_param: None,
                    compression_param: None,
                    noise_squashing_param: None,
                    noise_squashing_compression_param: None,
                    cpk_re_randomization_params: None,
                };

                assert!(!sk.is_conformant(&conformance_params));
            }
        }
        {
            let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let mut cpk_params = PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let casting_params = PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let config = ConfigBuilder::with_custom_parameters(params)
                .use_dedicated_compact_public_key_parameters((cpk_params, casting_params))
                .build();

            let ck = ClientKey::generate(config);
            let sk = ServerKey::new(&ck);

            let sk_param = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into();

            cpk_params.encryption_lwe_dimension.0 += 1;

            let conformance_params = IntegerServerKeyConformanceParams {
                sk_param,
                cpk_param: Some((cpk_params, casting_params)),
                compression_param: None,
                noise_squashing_param: None,
                noise_squashing_compression_param: None,
                cpk_re_randomization_params: None,
            };

            assert!(!sk.is_conformant(&conformance_params));
        }
    }

    #[test]
    fn conformance_compressed_hl_key() {
        {
            let config = ConfigBuilder::with_custom_parameters(
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            )
            .build();

            let ck = ClientKey::generate(config);
            let sk = CompressedServerKey::new(&ck);

            let conformance_params = config.into();

            assert!(sk.is_conformant(&conformance_params));
        }
        {
            let config = crate::ConfigBuilder::with_custom_parameters(
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            )
            .enable_compression(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .build();

            let ck = ClientKey::generate(config);
            let sk = CompressedServerKey::new(&ck);

            let conformance_params = config.into();
            assert!(sk.is_conformant(&conformance_params));
        }
        {
            let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let cpk_params = PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let casting_params = PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let config = ConfigBuilder::with_custom_parameters(params)
                .use_dedicated_compact_public_key_parameters((cpk_params, casting_params))
                .build();

            let ck = ClientKey::generate(config);
            let sk = CompressedServerKey::new(&ck);

            let conformance_params = config.into();

            assert!(sk.is_conformant(&conformance_params));
        }
        {
            let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let noise_squashing_params =
                NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let config = ConfigBuilder::with_custom_parameters(params)
                .enable_noise_squashing(noise_squashing_params)
                .build();

            let ck = ClientKey::generate(config);
            let sk = CompressedServerKey::new(&ck);

            let conformance_params = config.into();

            assert!(sk.is_conformant(&conformance_params));
        }
        // Full blockchain configuration
        {
            let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let cpk_params = PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let casting_params = PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let comp_params = COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let noise_squashing_params =
                NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let noise_squashing_compression_params =
                NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let cpk_re_randomization_ksk_params =
                PARAM_KEYSWITCH_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let config = ConfigBuilder::with_custom_parameters(params)
                .use_dedicated_compact_public_key_parameters((cpk_params, casting_params))
                .enable_compression(comp_params)
                .enable_noise_squashing(noise_squashing_params)
                .enable_noise_squashing_compression(noise_squashing_compression_params)
                .enable_ciphertext_re_randomization(cpk_re_randomization_ksk_params)
                .build();

            let ck = ClientKey::generate(config);
            let sk = CompressedServerKey::new(&ck);

            let conformance_params = config.into();

            assert!(sk.is_conformant(&conformance_params));
        }
    }

    #[test]
    fn broken_conformance_compressed_hl_key() {
        {
            let config = ConfigBuilder::with_custom_parameters(
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            )
            .build();

            let ck = ClientKey::generate(config);
            let sk = CompressedServerKey::new(&ck);

            for modifier in [
                |sk_param: &mut ClassicPBSParameters| {
                    sk_param.lwe_dimension.0 += 1;
                },
                |sk_param: &mut ClassicPBSParameters| {
                    sk_param.polynomial_size.0 += 1;
                },
            ] {
                let mut sk_param = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

                modifier(&mut sk_param);

                let sk_param = sk_param.into();

                let conformance_params = IntegerServerKeyConformanceParams {
                    sk_param,
                    cpk_param: None,
                    compression_param: None,
                    noise_squashing_param: None,
                    noise_squashing_compression_param: None,
                    cpk_re_randomization_params: None,
                };

                assert!(!sk.is_conformant(&conformance_params));
            }
        }
        {
            let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let mut cpk_params = PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let casting_params = PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let config = ConfigBuilder::with_custom_parameters(params)
                .use_dedicated_compact_public_key_parameters((cpk_params, casting_params))
                .build();

            let ck = ClientKey::generate(config);
            let sk = CompressedServerKey::new(&ck);

            let sk_param = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into();

            cpk_params.encryption_lwe_dimension.0 += 1;

            let conformance_params = IntegerServerKeyConformanceParams {
                sk_param,
                cpk_param: Some((cpk_params, casting_params)),
                compression_param: None,
                noise_squashing_param: None,
                noise_squashing_compression_param: None,
                cpk_re_randomization_params: None,
            };

            assert!(!sk.is_conformant(&conformance_params));
        }
    }
}
