use tfhe_versionable::Versionize;

use super::ClientKey;
use crate::backward_compatibility::keys::{CompressedServerKeyVersions, ServerKeyVersions};
use crate::conformance::ParameterSetConformant;
#[cfg(feature = "gpu")]
use crate::core_crypto::gpu::{synchronize_devices, CudaStreams};
#[cfg(feature = "gpu")]
use crate::high_level_api::keys::inner::IntegerCudaServerKey;
use crate::high_level_api::keys::{IntegerCompressedServerKey, IntegerServerKey};
use crate::integer::compression_keys::{
    CompressedCompressionKey, CompressedDecompressionKey, CompressionKey, DecompressionKey,
};
use crate::integer::parameters::IntegerCompactCiphertextListExpansionMode;
use crate::named::Named;
use crate::prelude::Tagged;
use crate::shortint::MessageModulus;
use crate::Tag;
use std::sync::Arc;

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

impl ServerKey {
    pub fn new(keys: &ClientKey) -> Self {
        Self {
            key: Arc::new(IntegerServerKey::new(&keys.key)),
            tag: keys.tag.clone(),
        }
    }

    pub fn into_raw_parts(
        self,
    ) -> (
        crate::integer::ServerKey,
        Option<crate::integer::key_switching_key::KeySwitchingKeyMaterial>,
        Option<CompressionKey>,
        Option<DecompressionKey>,
        Tag,
    ) {
        let IntegerServerKey {
            key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
        } = (*self.key).clone();

        (
            key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
            self.tag,
        )
    }

    pub fn from_raw_parts(
        key: crate::integer::ServerKey,
        cpk_key_switching_key_material: Option<
            crate::integer::key_switching_key::KeySwitchingKeyMaterial,
        >,
        compression_key: Option<CompressionKey>,
        decompression_key: Option<DecompressionKey>,
        tag: Tag,
    ) -> Self {
        Self {
            key: Arc::new(IntegerServerKey {
                key,
                cpk_key_switching_key_material,
                compression_key,
                decompression_key,
            }),
            tag,
        }
    }

    pub(in crate::high_level_api) fn pbs_key(&self) -> &crate::integer::ServerKey {
        self.key.pbs_key()
    }

    pub(in crate::high_level_api) fn cpk_casting_key(
        &self,
    ) -> Option<crate::integer::key_switching_key::KeySwitchingKeyView> {
        self.key.cpk_casting_key()
    }

    pub(in crate::high_level_api) fn message_modulus(&self) -> MessageModulus {
        self.key.message_modulus()
    }

    pub(in crate::high_level_api) fn integer_compact_ciphertext_list_expansion_mode(
        &self,
    ) -> IntegerCompactCiphertextListExpansionMode {
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
#[cfg_attr(tfhe_lints, allow(tfhe_lints::serialize_without_versionize))]
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

    pub fn into_raw_parts(
        self,
    ) -> (
        crate::integer::CompressedServerKey,
        Option<crate::integer::key_switching_key::CompressedKeySwitchingKeyMaterial>,
        Option<CompressedCompressionKey>,
        Option<CompressedDecompressionKey>,
        Tag,
    ) {
        let (a, b, c, d) = self.integer_key.into_raw_parts();
        (a, b, c, d, self.tag)
    }

    pub fn from_raw_parts(
        integer_key: crate::integer::CompressedServerKey,
        cpk_key_switching_key_material: Option<
            crate::integer::key_switching_key::CompressedKeySwitchingKeyMaterial,
        >,
        compression_key: Option<CompressedCompressionKey>,
        decompression_key: Option<CompressedDecompressionKey>,
        tag: Tag,
    ) -> Self {
        Self {
            integer_key: IntegerCompressedServerKey::from_raw_parts(
                integer_key,
                cpk_key_switching_key_material,
                compression_key,
                decompression_key,
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
        let streams = CudaStreams::new_multi_gpu();
        let key = crate::integer::gpu::CudaServerKey::decompress_from_cpu(
            &self.integer_key.key,
            &streams,
        );
        let compression_key: Option<
            crate::integer::gpu::list_compression::server_keys::CudaCompressionKey,
        > = self
            .integer_key
            .compression_key
            .as_ref()
            .map(|compression_key| compression_key.decompress_to_cuda(&streams));
        let decompression_key: Option<
            crate::integer::gpu::list_compression::server_keys::CudaDecompressionKey,
        > = match &self.integer_key.decompression_key {
            Some(decompression_key) => {
                let polynomial_size = decompression_key.key.blind_rotate_key.polynomial_size();
                let glwe_dimension = decompression_key
                    .key
                    .blind_rotate_key
                    .glwe_size()
                    .to_glwe_dimension();
                let message_modulus = key.message_modulus;
                let carry_modulus = key.carry_modulus;
                let ciphertext_modulus =
                    decompression_key.key.blind_rotate_key.ciphertext_modulus();
                Some(decompression_key.decompress_to_cuda(
                    glwe_dimension,
                    polynomial_size,
                    message_modulus,
                    carry_modulus,
                    ciphertext_modulus,
                    &streams,
                ))
            }
            None => None,
        };
        synchronize_devices(streams.len() as u32);
        CudaServerKey {
            key: Arc::new(IntegerCudaServerKey {
                key,
                compression_key,
                decompression_key,
            }),
            tag: self.tag.clone(),
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
}

#[cfg(feature = "gpu")]
impl CudaServerKey {
    pub(crate) fn message_modulus(&self) -> crate::shortint::MessageModulus {
        self.key.key.message_modulus
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

use crate::high_level_api::keys::inner::IntegerServerKeyConformanceParams;

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
    use crate::shortint::parameters::compact_public_key_only::p_fail_2_minus_64::ks_pbs;
    use crate::shortint::parameters::list_compression::COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    use crate::shortint::{ClassicPBSParameters, PBSParameters};
    use crate::{ClientKey, CompressedServerKey, ConfigBuilder, ServerKey};

    #[test]
    fn conformance_hl_key() {
        {
            let config =
                ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64)
                    .build();

            let ck = ClientKey::generate(config);
            let sk = ServerKey::new(&ck);

            let sk_param = PBSParameters::PBS(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);

            let conformance_params = IntegerServerKeyConformanceParams {
                sk_param,
                cpk_param: None,
                compression_param: None,
            };

            assert!(sk.is_conformant(&conformance_params));
        }
        {
            let config =
                ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64)
                    .enable_compression(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64)
                    .build();

            let ck = ClientKey::generate(config);
            let sk = ServerKey::new(&ck);

            let sk_param = PBSParameters::PBS(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);

            let conformance_params = IntegerServerKeyConformanceParams {
                sk_param,
                cpk_param: None,
                compression_param: Some(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64),
            };

            assert!(sk.is_conformant(&conformance_params));
        }
        {
            let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

            let cpk_params = ks_pbs::PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

            let casting_params = crate::shortint::parameters::key_switching::p_fail_2_minus_64::ks_pbs::PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

            let config = ConfigBuilder::with_custom_parameters(params)
                .use_dedicated_compact_public_key_parameters((cpk_params, casting_params));

            let ck = ClientKey::generate(config);
            let sk = ServerKey::new(&ck);

            let sk_param = PBSParameters::PBS(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);

            let conformance_params = IntegerServerKeyConformanceParams {
                sk_param,
                cpk_param: Some((cpk_params, casting_params)),
                compression_param: None,
            };

            assert!(sk.is_conformant(&conformance_params));
        }
    }

    #[test]
    fn broken_conformance_hl_key() {
        {
            let config =
                ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64)
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
                let mut sk_param = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

                modifier(&mut sk_param);

                let sk_param = PBSParameters::PBS(sk_param);

                let conformance_params = IntegerServerKeyConformanceParams {
                    sk_param,
                    cpk_param: None,
                    compression_param: None,
                };

                assert!(!sk.is_conformant(&conformance_params));
            }
        }
        {
            let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

            let mut cpk_params = ks_pbs::PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

            let casting_params = crate::shortint::parameters::key_switching::p_fail_2_minus_64::ks_pbs::PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

            let config = ConfigBuilder::with_custom_parameters(params)
                .use_dedicated_compact_public_key_parameters((cpk_params, casting_params));

            let ck = ClientKey::generate(config);
            let sk = ServerKey::new(&ck);

            let sk_param = PBSParameters::PBS(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);

            cpk_params.encryption_lwe_dimension.0 += 1;

            let conformance_params = IntegerServerKeyConformanceParams {
                sk_param,
                cpk_param: Some((cpk_params, casting_params)),
                compression_param: None,
            };

            assert!(!sk.is_conformant(&conformance_params));
        }
    }

    #[test]
    fn conformance_compressed_hl_key() {
        {
            let config =
                ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64)
                    .build();

            let ck = ClientKey::generate(config);
            let sk = CompressedServerKey::new(&ck);

            let sk_param = PBSParameters::PBS(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);

            let conformance_params = IntegerServerKeyConformanceParams {
                sk_param,
                cpk_param: None,
                compression_param: None,
            };

            assert!(sk.is_conformant(&conformance_params));
        }
        {
            let config = crate::ConfigBuilder::with_custom_parameters(
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
            )
            .enable_compression(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64)
            .build();

            let ck = ClientKey::generate(config);
            let sk = CompressedServerKey::new(&ck);

            let sk_param = PBSParameters::PBS(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);

            let conformance_params = IntegerServerKeyConformanceParams {
                sk_param,
                cpk_param: None,
                compression_param: Some(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64),
            };

            assert!(sk.is_conformant(&conformance_params));
        }
        {
            let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

            let cpk_params = ks_pbs::PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

            let casting_params = crate::shortint::parameters::key_switching::p_fail_2_minus_64::ks_pbs::PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

            let config = ConfigBuilder::with_custom_parameters(params)
                .use_dedicated_compact_public_key_parameters((cpk_params, casting_params));

            let ck = ClientKey::generate(config);
            let sk = CompressedServerKey::new(&ck);

            let sk_param = PBSParameters::PBS(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);

            let conformance_params = IntegerServerKeyConformanceParams {
                sk_param,
                cpk_param: Some((cpk_params, casting_params)),
                compression_param: None,
            };

            assert!(sk.is_conformant(&conformance_params));
        }
    }

    #[test]
    fn broken_conformance_compressed_hl_key() {
        {
            let config =
                ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64)
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
                let mut sk_param = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

                modifier(&mut sk_param);

                let sk_param = PBSParameters::PBS(sk_param);

                let conformance_params = IntegerServerKeyConformanceParams {
                    sk_param,
                    cpk_param: None,
                    compression_param: None,
                };

                assert!(!sk.is_conformant(&conformance_params));
            }
        }
        {
            let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

            let mut cpk_params = ks_pbs::PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

            let casting_params = crate::shortint::parameters::key_switching::p_fail_2_minus_64::ks_pbs::PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

            let config = ConfigBuilder::with_custom_parameters(params)
                .use_dedicated_compact_public_key_parameters((cpk_params, casting_params));

            let ck = ClientKey::generate(config);
            let sk = CompressedServerKey::new(&ck);

            let sk_param = PBSParameters::PBS(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);

            cpk_params.encryption_lwe_dimension.0 += 1;

            let conformance_params = IntegerServerKeyConformanceParams {
                sk_param,
                cpk_param: Some((cpk_params, casting_params)),
                compression_param: None,
            };

            assert!(!sk.is_conformant(&conformance_params));
        }
    }
}
