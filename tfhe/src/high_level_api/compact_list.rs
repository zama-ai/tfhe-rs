use crate::backward_compatibility::compact_list::CompactCiphertextListVersions;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::commons::math::random::{Deserialize, Serialize};
use crate::core_crypto::prelude::Numeric;
use crate::high_level_api::global_state;
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::traits::Tagged;
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::ciphertext::{Compactable, DataKind};
use crate::integer::encryption::KnowsMessageModulus;
use crate::integer::parameters::{
    CompactCiphertextListConformanceParams, IntegerCompactCiphertextListExpansionMode,
};
use crate::named::Named;
use crate::prelude::CiphertextList;
use crate::shortint::MessageModulus;
use crate::HlExpandable;
use tfhe_versionable::Versionize;
#[cfg(feature = "zk-pok")]
pub use zk::ProvenCompactCiphertextList;

#[cfg(feature = "gpu")]
use crate::high_level_api::global_state::with_cuda_internal_keys;

#[cfg(feature = "zk-pok")]
use crate::zk::{CompactPkeCrs, ZkComputeLoad};
use crate::{CompactPublicKey, Tag};

#[cfg(feature = "strings")]
use super::ClearString;

impl crate::FheTypes {
    pub(crate) fn from_data_kind(
        data_kind: DataKind,
        message_modulus: MessageModulus,
    ) -> Option<Self> {
        Some(match data_kind {
            DataKind::Unsigned(n) => {
                let num_bits_per_block = message_modulus.0.ilog2() as usize;
                let num_bits = n * num_bits_per_block;
                match num_bits {
                    2 => Self::Uint2,
                    4 => Self::Uint4,
                    6 => Self::Uint6,
                    8 => Self::Uint8,
                    10 => Self::Uint10,
                    12 => Self::Uint12,
                    14 => Self::Uint14,
                    16 => Self::Uint16,
                    24 => Self::Uint24,
                    32 => Self::Uint32,
                    40 => Self::Uint40,
                    48 => Self::Uint48,
                    56 => Self::Uint56,
                    64 => Self::Uint64,
                    72 => Self::Uint72,
                    80 => Self::Uint80,
                    88 => Self::Uint88,
                    96 => Self::Uint96,
                    104 => Self::Uint104,
                    112 => Self::Uint112,
                    120 => Self::Uint120,
                    128 => Self::Uint128,
                    136 => Self::Uint136,
                    144 => Self::Uint144,
                    152 => Self::Uint152,
                    160 => Self::Uint160,
                    168 => Self::Uint168,
                    176 => Self::Uint176,
                    184 => Self::Uint184,
                    192 => Self::Uint192,
                    200 => Self::Uint200,
                    208 => Self::Uint208,
                    216 => Self::Uint216,
                    224 => Self::Uint224,
                    232 => Self::Uint232,
                    240 => Self::Uint240,
                    248 => Self::Uint248,
                    256 => Self::Uint256,
                    512 => Self::Uint512,
                    1024 => Self::Uint1024,
                    2048 => Self::Uint2048,
                    _ => return None,
                }
            }
            DataKind::Signed(n) => {
                let num_bits_per_block = message_modulus.0.ilog2() as usize;
                let num_bits = n * num_bits_per_block;
                match num_bits {
                    2 => Self::Int2,
                    4 => Self::Int4,
                    6 => Self::Int6,
                    8 => Self::Int8,
                    10 => Self::Int10,
                    12 => Self::Int12,
                    14 => Self::Int14,
                    16 => Self::Int16,
                    24 => Self::Int24,
                    32 => Self::Int32,
                    40 => Self::Int40,
                    48 => Self::Int48,
                    56 => Self::Int56,
                    64 => Self::Int64,
                    72 => Self::Int72,
                    80 => Self::Int80,
                    88 => Self::Int88,
                    96 => Self::Int96,
                    104 => Self::Int104,
                    112 => Self::Int112,
                    120 => Self::Int120,
                    128 => Self::Int128,
                    136 => Self::Int136,
                    144 => Self::Int144,
                    152 => Self::Int152,
                    160 => Self::Int160,
                    168 => Self::Int168,
                    176 => Self::Int176,
                    184 => Self::Int184,
                    192 => Self::Int192,
                    200 => Self::Int200,
                    208 => Self::Int208,
                    216 => Self::Int216,
                    224 => Self::Int224,
                    232 => Self::Int232,
                    240 => Self::Int240,
                    248 => Self::Int248,
                    256 => Self::Int256,
                    512 => Self::Int512,
                    1024 => Self::Int1024,
                    2048 => Self::Int2048,
                    _ => return None,
                }
            }
            DataKind::Boolean => Self::Bool,
            DataKind::String { .. } => Self::AsciiString,
        })
    }
}

#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(CompactCiphertextListVersions)]
pub struct CompactCiphertextList {
    pub(crate) inner: crate::integer::ciphertext::CompactCiphertextList,
    pub(crate) tag: Tag,
}

impl Named for CompactCiphertextList {
    const NAME: &'static str = "high_level_api::CompactCiphertextList";
}

impl CompactCiphertextList {
    pub fn builder(pk: &CompactPublicKey) -> CompactCiphertextListBuilder {
        CompactCiphertextListBuilder::new(pk)
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get_kind_of(&self, index: usize) -> Option<crate::FheTypes> {
        self.inner.get_kind_of(index).and_then(|data_kind| {
            crate::FheTypes::from_data_kind(data_kind, self.inner.ct_list.message_modulus)
        })
    }

    pub fn expand_with_key(
        &self,
        sks: &crate::ServerKey,
    ) -> crate::Result<CompactCiphertextListExpander> {
        self.inner
            .expand(sks.integer_compact_ciphertext_list_expansion_mode())
            .map(|inner| CompactCiphertextListExpander {
                inner: InnerCompactCiphertextListExpander::Cpu(inner),
                tag: self.tag.clone(),
            })
    }

    pub fn expand(&self) -> crate::Result<CompactCiphertextListExpander> {
        // For WASM
        if !self.inner.is_packed() && !self.inner.needs_casting() {
            // No ServerKey required, short-circuit to avoid the global state call
            return Ok(CompactCiphertextListExpander {
                inner: InnerCompactCiphertextListExpander::Cpu(
                    self.inner.expand(
                        IntegerCompactCiphertextListExpansionMode::NoCastingAndNoUnpacking,
                    )?,
                ),
                tag: self.tag.clone(),
            });
        }

        global_state::try_with_internal_keys(|maybe_keys| match maybe_keys {
            None => Err(crate::high_level_api::errors::UninitializedServerKey.into()),
            Some(InternalServerKey::Cpu(cpu_key)) => self
                .inner
                .expand(cpu_key.integer_compact_ciphertext_list_expansion_mode())
                .map(|inner| CompactCiphertextListExpander {
                    inner: InnerCompactCiphertextListExpander::Cpu(inner),
                    tag: self.tag.clone(),
                }),
            #[cfg(any(feature = "gpu", feature = "hpu"))]
            Some(_) => Err(crate::Error::new("Expected a CPU server key".to_string())),
        })
    }
}

impl Tagged for CompactCiphertextList {
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.tag
    }
}

impl ParameterSetConformant for CompactCiphertextList {
    type ParameterSet = CompactCiphertextListConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self { inner, tag: _ } = self;

        inner.is_conformant(parameter_set)
    }
}

#[cfg(feature = "zk-pok")]
mod zk {
    use super::*;
    use crate::backward_compatibility::compact_list::ProvenCompactCiphertextListVersions;
    use crate::conformance::ParameterSetConformant;
    use crate::high_level_api::global_state::device_of_internal_keys;
    use crate::integer::ciphertext::IntegerProvenCompactCiphertextListConformanceParams;
    #[cfg(feature = "gpu")]
    use crate::integer::gpu::key_switching_key::CudaKeySwitchingKey;
    #[cfg(feature = "gpu")]
    use crate::integer::gpu::zk::CudaProvenCompactCiphertextList;
    use serde::Serializer;

    pub enum InnerProvenCompactCiphertextList {
        Cpu(crate::integer::ciphertext::ProvenCompactCiphertextList),
        #[cfg(feature = "gpu")]
        Cuda(crate::integer::gpu::zk::CudaProvenCompactCiphertextList),
    }

    impl Clone for InnerProvenCompactCiphertextList {
        fn clone(&self) -> Self {
            match self {
                Self::Cpu(inner) => Self::Cpu(inner.clone()),
                #[cfg(feature = "gpu")]
                Self::Cuda(inner) => with_cuda_internal_keys(|keys| {
                    let streams = &keys.streams;
                    Self::Cuda(inner.duplicate(streams))
                }),
            }
        }
    }

    #[derive(Clone, Serialize, Deserialize, Versionize)]
    #[versionize(ProvenCompactCiphertextListVersions)]
    pub struct ProvenCompactCiphertextList {
        pub(crate) inner: InnerProvenCompactCiphertextList,
        pub(crate) tag: Tag,
    }

    impl InnerProvenCompactCiphertextList {
        pub(crate) fn on_cpu(&self) -> &crate::integer::ciphertext::ProvenCompactCiphertextList {
            match self {
                Self::Cpu(inner) => inner,
                #[cfg(feature = "gpu")]
                Self::Cuda(inner) => &inner.h_proved_lists,
            }
        }

        #[allow(clippy::unnecessary_wraps)] // Method can return an error if hpu is enabled
        fn move_to_device(&mut self, device: crate::Device) -> Result<(), crate::Error> {
            let new_value = match (&self, device) {
                (Self::Cpu(_), crate::Device::Cpu) => None,
                #[cfg(feature = "gpu")]
                (Self::Cuda(cuda_ct), crate::Device::CudaGpu) => with_cuda_internal_keys(|keys| {
                    let streams = &keys.streams;
                    if cuda_ct.gpu_indexes() == streams.gpu_indexes() {
                        None
                    } else {
                        Some(Self::Cuda(cuda_ct.duplicate(streams)))
                    }
                }),
                #[cfg(feature = "gpu")]
                (Self::Cuda(cuda_ct), crate::Device::Cpu) => {
                    let cpu_ct = cuda_ct.h_proved_lists.clone();
                    Some(Self::Cpu(cpu_ct))
                }
                #[cfg(feature = "gpu")]
                (Self::Cpu(cpu_ct), crate::Device::CudaGpu) => {
                    let cuda_ct = with_cuda_internal_keys(|keys| {
                        let streams = &keys.streams;
                        CudaProvenCompactCiphertextList::from_proven_compact_ciphertext_list(
                            cpu_ct, streams,
                        )
                    });
                    Some(Self::Cuda(cuda_ct))
                }
                #[cfg(feature = "hpu")]
                (_, crate::Device::Hpu) => {
                    return Err(crate::error!(
                        "Hpu does not support ProvenCompactCiphertextList"
                    ))
                }
            };

            if let Some(v) = new_value {
                *self = v;
            }
            Ok(())
        }
    }

    impl serde::Serialize for InnerProvenCompactCiphertextList {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            self.on_cpu().serialize(serializer)
        }
    }

    impl<'de> serde::Deserialize<'de> for InnerProvenCompactCiphertextList {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let mut new =
                crate::integer::ciphertext::ProvenCompactCiphertextList::deserialize(deserializer)
                    .map(Self::Cpu)?;

            if let Some(device) = device_of_internal_keys() {
                new.move_to_device(device)
                    .map_err(serde::de::Error::custom)?;
            }

            Ok(new)
        }
    }
    use tfhe_versionable::{Unversionize, UnversionizeError, VersionizeOwned};
    impl Versionize for InnerProvenCompactCiphertextList {
        type Versioned<'vers> =
        <crate::integer::ciphertext::ProvenCompactCiphertextList as VersionizeOwned>::VersionedOwned;
        fn versionize(&self) -> Self::Versioned<'_> {
            self.on_cpu().clone().versionize_owned()
        }
    }
    impl VersionizeOwned for InnerProvenCompactCiphertextList {
        type VersionedOwned =
        <crate::integer::ciphertext::ProvenCompactCiphertextList as VersionizeOwned>::VersionedOwned;
        fn versionize_owned(self) -> Self::VersionedOwned {
            self.on_cpu().clone().versionize_owned()
        }
    }

    impl Unversionize for InnerProvenCompactCiphertextList {
        fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
            Ok(Self::Cpu(
                crate::integer::ciphertext::ProvenCompactCiphertextList::unversionize(versioned)?,
            ))
        }
    }

    impl Tagged for ProvenCompactCiphertextList {
        fn tag(&self) -> &Tag {
            &self.tag
        }

        fn tag_mut(&mut self) -> &mut Tag {
            &mut self.tag
        }
    }
    impl Named for ProvenCompactCiphertextList {
        const NAME: &'static str = "high_level_api::ProvenCompactCiphertextList";
    }

    impl ProvenCompactCiphertextList {
        pub fn builder(pk: &CompactPublicKey) -> CompactCiphertextListBuilder {
            CompactCiphertextListBuilder::new(pk)
        }

        pub fn len(&self) -> usize {
            self.inner.on_cpu().len()
        }

        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }

        pub fn get_kind_of(&self, index: usize) -> Option<crate::FheTypes> {
            let inner_cpu = self.inner.on_cpu();
            inner_cpu.get_kind_of(index).and_then(|data_kind| {
                crate::FheTypes::from_data_kind(data_kind, inner_cpu.ct_list.message_modulus())
            })
        }

        pub fn verify(
            &self,
            crs: &CompactPkeCrs,
            pk: &CompactPublicKey,
            metadata: &[u8],
        ) -> crate::zk::ZkVerificationOutcome {
            self.inner.on_cpu().verify(crs, &pk.key.key, metadata)
        }

        pub fn verify_and_expand(
            &self,
            crs: &CompactPkeCrs,
            pk: &CompactPublicKey,
            metadata: &[u8],
        ) -> crate::Result<CompactCiphertextListExpander> {
            #[allow(irrefutable_let_patterns)]
            if let InnerProvenCompactCiphertextList::Cpu(inner) = &self.inner {
                // For WASM
                if !inner.is_packed() && !inner.needs_casting() {
                    let expander = inner.verify_and_expand(
                        crs,
                        &pk.key.key,
                        metadata,
                        IntegerCompactCiphertextListExpansionMode::NoCastingAndNoUnpacking,
                    )?;
                    // No ServerKey required, short circuit to avoid the global state call
                    return Ok(CompactCiphertextListExpander {
                        inner: InnerCompactCiphertextListExpander::Cpu(expander),
                        tag: self.tag.clone(),
                    });
                }
            }

            global_state::try_with_internal_keys(|maybe_keys| match maybe_keys {
                None => Err(crate::high_level_api::errors::UninitializedServerKey.into()),
                Some(InternalServerKey::Cpu(cpu_key)) => match &self.inner {
                    InnerProvenCompactCiphertextList::Cpu(inner) => inner
                        .verify_and_expand(
                            crs,
                            &pk.key.key,
                            metadata,
                            cpu_key.integer_compact_ciphertext_list_expansion_mode(),
                        )
                        .map(|expander| CompactCiphertextListExpander {
                            inner: InnerCompactCiphertextListExpander::Cpu(expander),
                            tag: self.tag.clone(),
                        }),
                    #[cfg(feature = "gpu")]
                    InnerProvenCompactCiphertextList::Cuda(inner) => inner
                        .h_proved_lists
                        .verify_and_expand(
                            crs,
                            &pk.key.key,
                            metadata,
                            cpu_key.integer_compact_ciphertext_list_expansion_mode(),
                        )
                        .map(|expander| CompactCiphertextListExpander {
                            inner: InnerCompactCiphertextListExpander::Cpu(expander),
                            tag: self.tag.clone(),
                        }),
                },
                #[cfg(feature = "gpu")]
                Some(InternalServerKey::Cuda(gpu_key)) => match &self.inner {
                    InnerProvenCompactCiphertextList::Cuda(inner) => {
                        with_cuda_internal_keys(|keys| {
                            let streams = &keys.streams;
                            let ksk = CudaKeySwitchingKey {
                                key_switching_key_material: gpu_key
                                    .key
                                    .cpk_key_switching_key_material
                                    .as_ref()
                                    .unwrap(),
                                dest_server_key: &gpu_key.key.key,
                            };
                            let expander = inner.verify_and_expand(
                                crs,
                                &pk.key.key,
                                metadata,
                                &ksk,
                                streams,
                            )?;

                            Ok(CompactCiphertextListExpander {
                                inner: InnerCompactCiphertextListExpander::Cuda(expander),
                                tag: self.tag.clone(),
                            })
                        })
                    }
                    InnerProvenCompactCiphertextList::Cpu(cpu_inner) => {
                        with_cuda_internal_keys(|keys| {
                            let streams = &keys.streams;
                            let gpu_proven_ct = CudaProvenCompactCiphertextList::from_proven_compact_ciphertext_list(
                                    cpu_inner, streams,
                                );
                            let ksk = CudaKeySwitchingKey {
                                key_switching_key_material: gpu_key
                                    .key
                                    .cpk_key_switching_key_material
                                    .as_ref()
                                    .unwrap(),
                                dest_server_key: &gpu_key.key.key,
                            };
                            let expander = gpu_proven_ct.verify_and_expand(
                                crs,
                                &pk.key.key,
                                metadata,
                                &ksk,
                                streams,
                            )?;

                            Ok(CompactCiphertextListExpander {
                                inner: InnerCompactCiphertextListExpander::Cuda(expander),
                                tag: self.tag.clone(),
                            })
                        })
                    }
                },
                #[cfg(feature = "hpu")]
                Some(InternalServerKey::Hpu(_)) => Err(crate::error!(
                    "Hpu does not support ProvenCompactCiphertextList"
                )),
            })
        }

        #[doc(hidden)]
        /// This function allows to expand a ciphertext without verifying the associated proof.
        ///
        /// If you are here you were probably looking for it: use at your own risks.
        pub fn expand_without_verification(&self) -> crate::Result<CompactCiphertextListExpander> {
            #[allow(irrefutable_let_patterns)]
            if let InnerProvenCompactCiphertextList::Cpu(inner) = &self.inner {
                // For WASM
                if !inner.is_packed() && !inner.needs_casting() {
                    // No ServerKey required, short circuit to avoid the global state call
                    return Ok(CompactCiphertextListExpander {
                        inner: InnerCompactCiphertextListExpander::Cpu(
                            inner.expand_without_verification(
                                IntegerCompactCiphertextListExpansionMode::NoCastingAndNoUnpacking,
                            )?,
                        ),
                        tag: self.tag.clone(),
                    });
                }
            }

            global_state::try_with_internal_keys(|maybe_keys| {
                match maybe_keys {
                None => Err(crate::high_level_api::errors::UninitializedServerKey.into()),
                    Some(InternalServerKey::Cpu(cpu_key)) => match &self.inner {
                        InnerProvenCompactCiphertextList::Cpu(inner) => inner
                            .expand_without_verification(
                                cpu_key.integer_compact_ciphertext_list_expansion_mode(),
                            )
                            .map(|expander| CompactCiphertextListExpander {
                                inner: InnerCompactCiphertextListExpander::Cpu(expander),
                                tag: self.tag.clone(),
                            }),
                        #[cfg(feature = "gpu")]
                        InnerProvenCompactCiphertextList::Cuda(_) => {
                            Err(crate::Error::new("Tried expanding a ProvenCompactCiphertextList on the GPU, but the set ServerKey is a ServerKey".to_string()))
                        }
                    },
                    #[cfg(feature = "gpu")]
                    Some(InternalServerKey::Cuda(gpu_key)) => match &self.inner {
                        InnerProvenCompactCiphertextList::Cuda(inner) => {
                            with_cuda_internal_keys(|keys| {
                                let streams = &keys.streams;
                                let ksk = CudaKeySwitchingKey {
                                    key_switching_key_material: gpu_key
                                        .key
                                        .cpk_key_switching_key_material
                                        .as_ref()
                                        .unwrap(),
                                    dest_server_key: &gpu_key.key.key,
                                };
                                let expander = inner.expand_without_verification(&ksk, streams)?;

                                Ok(CompactCiphertextListExpander {
                                    inner: InnerCompactCiphertextListExpander::Cuda(expander),
                                    tag: self.tag.clone(),
                                })
                            })
                        }
                        InnerProvenCompactCiphertextList::Cpu(inner) => {
                            with_cuda_internal_keys(|keys| {
                               let streams = &keys.streams;
                               let gpu_proven_ct = CudaProvenCompactCiphertextList::from_proven_compact_ciphertext_list(
                                    inner, streams,
                                );
                                let ksk = CudaKeySwitchingKey {
                                    key_switching_key_material: gpu_key
                                        .key
                                        .cpk_key_switching_key_material
                                        .as_ref()
                                        .unwrap(),
                                    dest_server_key: &gpu_key.key.key,
                                };
                                let expander = gpu_proven_ct.expand_without_verification(&ksk, streams)?;

                                Ok(CompactCiphertextListExpander {
                                    inner: InnerCompactCiphertextListExpander::Cuda(expander),
                                    tag: self.tag.clone(),
                                })
                            })
                        }
                    },
                #[cfg(feature = "hpu")]
                Some(InternalServerKey::Hpu(_)) => Err(crate::error!("Hpu does not support ProvenCompactCiphertextList")),
                }
            })
        }
    }

    impl ParameterSetConformant for ProvenCompactCiphertextList {
        type ParameterSet = IntegerProvenCompactCiphertextListConformanceParams;

        fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
            self.inner.on_cpu().is_conformant(parameter_set)
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use crate::integer::ciphertext::IntegerProvenCompactCiphertextListConformanceParams;
        use crate::shortint::parameters::*;

        use rand::{thread_rng, Rng};

        #[test]
        fn conformance_zk_compact_ciphertext_list() {
            let mut rng = thread_rng();

            let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let cpk_params = PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let casting_params = PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let config = crate::ConfigBuilder::with_custom_parameters(params)
                .use_dedicated_compact_public_key_parameters((cpk_params, casting_params));

            let client_key = crate::ClientKey::generate(config.clone());

            let crs = CompactPkeCrs::from_config(config.into(), 64).unwrap();
            let public_key = crate::CompactPublicKey::try_new(&client_key).unwrap();

            let metadata = [b'T', b'F', b'H', b'E', b'-', b'r', b's'];

            let clear_a = rng.gen::<u64>();
            let clear_b = rng.gen::<bool>();

            let proven_compact_list = crate::ProvenCompactCiphertextList::builder(&public_key)
                .push(clear_a)
                .push(clear_b)
                .build_with_proof_packed(&crs, &metadata, ZkComputeLoad::Proof)
                .unwrap();

            let params =
                IntegerProvenCompactCiphertextListConformanceParams::from_crs_and_parameters(
                    cpk_params, &crs,
                );

            assert!(proven_compact_list.is_conformant(&params));
        }
    }
}

pub enum InnerCompactCiphertextListExpander {
    Cpu(crate::integer::ciphertext::CompactCiphertextListExpander),
    #[cfg(feature = "gpu")]
    Cuda(crate::integer::gpu::ciphertext::compact_list::CudaCompactCiphertextListExpander),
}

pub struct CompactCiphertextListExpander {
    pub inner: InnerCompactCiphertextListExpander,
    tag: Tag,
}

impl CiphertextList for CompactCiphertextListExpander {
    fn len(&self) -> usize {
        match &self.inner {
            InnerCompactCiphertextListExpander::Cpu(inner) => inner.len(),
            #[cfg(feature = "gpu")]
            InnerCompactCiphertextListExpander::Cuda(inner) => inner.len(),
        }
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn get_kind_of(&self, index: usize) -> Option<crate::FheTypes> {
        match &self.inner {
            InnerCompactCiphertextListExpander::Cpu(inner) => {
                inner.get_kind_of(index).and_then(|data_kind| {
                    crate::FheTypes::from_data_kind(data_kind, inner.message_modulus())
                })
            }
            #[cfg(feature = "gpu")]
            InnerCompactCiphertextListExpander::Cuda(inner) => {
                inner.get_kind_of(index).and_then(|data_kind| {
                    crate::FheTypes::from_data_kind(data_kind, inner.message_modulus(index)?)
                })
            }
        }
    }

    fn get<T>(&self, index: usize) -> crate::Result<Option<T>>
    where
        T: HlExpandable + Tagged,
    {
        let mut expanded = match &self.inner {
            InnerCompactCiphertextListExpander::Cpu(inner) => inner.get::<T>(index),
            #[cfg(feature = "gpu")]
            InnerCompactCiphertextListExpander::Cuda(inner) => with_cuda_internal_keys(|keys| {
                let streams = &keys.streams;
                inner.get::<T>(index, streams)
            }),
        };

        if let Ok(Some(inner)) = &mut expanded {
            inner.tag_mut().set_data(self.tag.data());
        }
        expanded
    }
}

fn num_bits_to_strict_num_blocks(
    num_bits: usize,
    message_modulus: MessageModulus,
) -> crate::Result<usize> {
    let bits_per_block = message_modulus.0.ilog2();
    if num_bits as u32 % bits_per_block != 0 {
        let message = format!("Number of bits must be a multiple of the parameter's MessageModulus.ilog2 ({bits_per_block} here)");
        return Err(crate::Error::new(message));
    }
    Ok(num_bits.div_ceil(bits_per_block as usize))
}

pub trait HlCompactable: Compactable {}

impl HlCompactable for bool {}

impl<T> HlCompactable for T where
    T: Numeric + DecomposableInto<u64> + std::ops::Shl<usize, Output = T>
{
}

pub struct CompactCiphertextListBuilder {
    inner: crate::integer::ciphertext::CompactCiphertextListBuilder,
    tag: Tag,
}

impl CompactCiphertextListBuilder {
    pub fn new(pk: &CompactPublicKey) -> Self {
        Self {
            inner: crate::integer::ciphertext::CompactCiphertextListBuilder::new(&pk.key.key),
            tag: pk.tag.clone(),
        }
    }

    pub fn push<T>(&mut self, value: T) -> &mut Self
    where
        T: HlCompactable,
    {
        self.inner.push(value);
        self
    }

    pub fn extend<T>(&mut self, values: impl Iterator<Item = T>) -> &mut Self
    where
        T: HlCompactable,
    {
        self.inner.extend(values);
        self
    }

    pub fn push_with_num_bits<T>(&mut self, number: T, num_bits: usize) -> crate::Result<&mut Self>
    where
        T: HlCompactable + Numeric,
    {
        let num_blocks =
            num_bits_to_strict_num_blocks(num_bits, self.inner.pk.key.message_modulus())?;
        self.inner.push_with_num_blocks(number, num_blocks);
        Ok(self)
    }

    pub fn extend_with_num_bits<T>(
        &mut self,
        values: impl Iterator<Item = T>,
        num_bits: usize,
    ) -> crate::Result<&mut Self>
    where
        T: HlCompactable + Numeric,
    {
        let num_blocks =
            num_bits_to_strict_num_blocks(num_bits, self.inner.pk.key.message_modulus())?;
        self.inner.extend_with_num_blocks(values, num_blocks);
        Ok(self)
    }

    pub fn build(&self) -> CompactCiphertextList {
        CompactCiphertextList {
            inner: self.inner.build(),
            tag: self.tag.clone(),
        }
    }

    pub fn build_packed(&self) -> CompactCiphertextList {
        self.inner
            .build_packed()
            .map(|list| CompactCiphertextList {
                inner: list,
                tag: self.tag.clone(),
            })
            .expect("Internal error, invalid parameters should not have been allowed")
    }
    #[cfg(feature = "zk-pok")]
    pub fn build_with_proof_packed(
        &self,
        crs: &CompactPkeCrs,
        metadata: &[u8],
        compute_load: ZkComputeLoad,
    ) -> crate::Result<ProvenCompactCiphertextList> {
        self.inner
            .build_with_proof_packed(crs, metadata, compute_load)
            .map(|proved_list| ProvenCompactCiphertextList {
                inner:
                    crate::high_level_api::compact_list::zk::InnerProvenCompactCiphertextList::Cpu(
                        proved_list,
                    ),
                tag: self.tag.clone(),
            })
    }
}

#[cfg(feature = "strings")]
impl CompactCiphertextListBuilder {
    pub fn push_string(&mut self, string: &ClearString) -> &mut Self {
        self.push(string)
    }

    pub fn push_string_with_padding(
        &mut self,
        clear_string: &ClearString,
        padding_count: u32,
    ) -> &mut Self {
        self.inner
            .push_string_with_padding(clear_string, padding_count);
        self
    }

    pub fn push_string_with_fixed_size(
        &mut self,
        clear_string: &ClearString,
        size: u32,
    ) -> &mut Self {
        self.inner.push_string_with_fixed_size(clear_string, size);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::*;
    use crate::shortint::parameters::*;
    use crate::{set_server_key, FheBool, FheInt64, FheUint16, FheUint2, FheUint32};

    #[cfg(all(feature = "zk-pok", feature = "gpu"))]
    use crate::CompressedServerKey;

    #[test]
    fn test_compact_list() {
        let config = crate::ConfigBuilder::default().build();

        let ck = crate::ClientKey::generate(config);
        let sk = crate::ServerKey::new(&ck);
        let pk = crate::CompactPublicKey::new(&ck);

        set_server_key(sk);

        let compact_list = CompactCiphertextList::builder(&pk)
            .push(17u32)
            .push(-1i64)
            .push(false)
            .push(true)
            .push_with_num_bits(3u8, 2)
            .unwrap()
            .build_packed();

        let serialized = bincode::serialize(&compact_list).unwrap();
        let compact_list: CompactCiphertextList = bincode::deserialize(&serialized).unwrap();
        let expander = compact_list.expand().unwrap();

        {
            let a: FheUint32 = expander.get(0).unwrap().unwrap();
            let b: FheInt64 = expander.get(1).unwrap().unwrap();
            let c: FheBool = expander.get(2).unwrap().unwrap();
            let d: FheBool = expander.get(3).unwrap().unwrap();
            let e: FheUint2 = expander.get(4).unwrap().unwrap();

            let a: u32 = a.decrypt(&ck);
            assert_eq!(a, 17);
            let b: i64 = b.decrypt(&ck);
            assert_eq!(b, -1);
            let c = c.decrypt(&ck);
            assert!(!c);
            let d = d.decrypt(&ck);
            assert!(d);
            let e: u8 = e.decrypt(&ck);
            assert_eq!(e, 3);

            assert!(expander.get::<FheBool>(5).unwrap().is_none());
        }

        {
            // Incorrect type
            assert!(expander.get::<FheInt64>(0).is_err());

            // Correct type but wrong number of bits
            assert!(expander.get::<FheUint16>(0).is_err());
        }
    }

    #[cfg(feature = "extended-types")]
    #[test]
    fn test_compact_list_extended_types() {
        let config = crate::ConfigBuilder::default().build();

        let ck = crate::ClientKey::generate(config);
        let sk = crate::ServerKey::new(&ck);
        let pk = crate::CompactPublicKey::new(&ck);

        set_server_key(sk);

        let compact_list = CompactCiphertextList::builder(&pk)
            .push_with_num_bits(-17i64, 40)
            .unwrap()
            .push_with_num_bits(3u8, 24)
            .unwrap()
            .build_packed();

        let serialized = bincode::serialize(&compact_list).unwrap();
        let compact_list: CompactCiphertextList = bincode::deserialize(&serialized).unwrap();
        let expander = compact_list.expand().unwrap();

        {
            let a: crate::FheInt40 = expander.get(0).unwrap().unwrap();
            let b: crate::FheUint24 = expander.get(1).unwrap().unwrap();

            let a: i64 = a.decrypt(&ck);
            assert_eq!(a, -17);
            let b: u8 = b.decrypt(&ck);
            assert_eq!(b, 3);
        }

        {
            // Incorrect type
            assert!(expander.get::<FheUint32>(0).is_err());

            // Correct type but wrong number of bits
            assert!(expander.get::<FheInt64>(0).is_err());
        }
    }

    #[test]
    fn test_compact_list_with_casting() {
        let config = crate::ConfigBuilder::with_custom_parameters(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )
        .use_dedicated_compact_public_key_parameters((
            PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        ))
        .build();

        let ck = crate::ClientKey::generate(config);
        let sk = crate::ServerKey::new(&ck);
        let pk = crate::CompactPublicKey::new(&ck);

        let compact_list = CompactCiphertextList::builder(&pk)
            .push(17u32)
            .push(-1i64)
            .push(false)
            .push(true)
            .push_with_num_bits(3u8, 2)
            .unwrap()
            .build_packed();

        let serialized = bincode::serialize(&compact_list).unwrap();
        let compact_list: CompactCiphertextList = bincode::deserialize(&serialized).unwrap();
        let expander = compact_list.expand_with_key(&sk).unwrap();

        {
            let a: FheUint32 = expander.get(0).unwrap().unwrap();
            let b: FheInt64 = expander.get(1).unwrap().unwrap();
            let c: FheBool = expander.get(2).unwrap().unwrap();
            let d: FheBool = expander.get(3).unwrap().unwrap();
            let e: FheUint2 = expander.get(4).unwrap().unwrap();

            let a: u32 = a.decrypt(&ck);
            assert_eq!(a, 17);
            let b: i64 = b.decrypt(&ck);
            assert_eq!(b, -1);
            let c = c.decrypt(&ck);
            assert!(!c);
            let d = d.decrypt(&ck);
            assert!(d);
            let e: u8 = e.decrypt(&ck);
            assert_eq!(e, 3);

            assert!(expander.get::<FheBool>(5).unwrap().is_none());
        }

        {
            // Incorrect type
            assert!(expander.get::<FheInt64>(0).is_err());

            // Correct type but wrong number of bits
            assert!(expander.get::<FheUint16>(0).is_err());
        }
    }

    #[cfg(feature = "zk-pok")]
    #[test]
    fn test_proven_compact_list() {
        let config = crate::ConfigBuilder::with_custom_parameters(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )
        .use_dedicated_compact_public_key_parameters((
            PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        ))
        .build();

        let ck = crate::ClientKey::generate(config);
        let pk = crate::CompactPublicKey::new(&ck);
        let sks = crate::ServerKey::new(&ck);

        set_server_key(sks);

        // Intentionally low so that we test when multiple lists and proofs are needed
        let crs = CompactPkeCrs::from_config(config, 32).unwrap();

        let metadata = [b'h', b'l', b'a', b'p', b'i'];

        let compact_list = ProvenCompactCiphertextList::builder(&pk)
            .push(17u32)
            .push(-1i64)
            .push(false)
            .push_with_num_bits(3u32, 2)
            .unwrap()
            .build_with_proof_packed(&crs, &metadata, ZkComputeLoad::Proof)
            .unwrap();

        let serialized = bincode::serialize(&compact_list).unwrap();
        let compact_list: ProvenCompactCiphertextList = bincode::deserialize(&serialized).unwrap();
        let expander = compact_list
            .verify_and_expand(&crs, &pk, &metadata)
            .unwrap();

        {
            let a: FheUint32 = expander.get(0).unwrap().unwrap();
            let b: FheInt64 = expander.get(1).unwrap().unwrap();
            let c: FheBool = expander.get(2).unwrap().unwrap();
            let d: FheUint2 = expander.get(3).unwrap().unwrap();

            let a: u32 = a.decrypt(&ck);
            assert_eq!(a, 17);
            let b: i64 = b.decrypt(&ck);
            assert_eq!(b, -1);
            let c = c.decrypt(&ck);
            assert!(!c);
            let d: u8 = d.decrypt(&ck);
            assert_eq!(d, 3);

            assert!(expander.get::<FheBool>(4).unwrap().is_none());
        }

        {
            // Incorrect type
            assert!(expander.get::<FheInt64>(0).is_err());

            // Correct type but wrong number of bits
            assert!(expander.get::<FheUint16>(0).is_err());
        }

        let unverified_expander = compact_list.expand_without_verification().unwrap();

        {
            let a: FheUint32 = unverified_expander.get(0).unwrap().unwrap();
            let b: FheInt64 = unverified_expander.get(1).unwrap().unwrap();
            let c: FheBool = unverified_expander.get(2).unwrap().unwrap();
            let d: FheUint2 = unverified_expander.get(3).unwrap().unwrap();

            let a: u32 = a.decrypt(&ck);
            assert_eq!(a, 17);
            let b: i64 = b.decrypt(&ck);
            assert_eq!(b, -1);
            let c = c.decrypt(&ck);
            assert!(!c);
            let d: u8 = d.decrypt(&ck);
            assert_eq!(d, 3);

            assert!(unverified_expander.get::<FheBool>(4).unwrap().is_none());
        }
    }

    #[cfg(all(feature = "zk-pok", feature = "gpu"))]
    #[test]
    fn test_gpu_proven_compact_list() {
        let config = crate::ConfigBuilder::with_custom_parameters(
            PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )
        .use_dedicated_compact_public_key_parameters((
            PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        ))
        .build();

        let ck = crate::ClientKey::generate(config);
        let compressed_server_key = CompressedServerKey::new(&ck);
        let gpu_sk = compressed_server_key.decompress_to_gpu();
        let pk = crate::CompactPublicKey::new(&ck);

        set_server_key(gpu_sk);

        // Intentionally low so that we test when multiple lists and proofs are needed
        let crs = CompactPkeCrs::from_config(config, 32).unwrap();

        let metadata = [b'h', b'l', b'a', b'p', b'i'];

        let compact_list = ProvenCompactCiphertextList::builder(&pk)
            .push(17u32)
            .push(-1i64)
            .push(false)
            .push_with_num_bits(3u32, 2)
            .unwrap()
            .build_with_proof_packed(&crs, &metadata, ZkComputeLoad::Proof)
            .unwrap();

        let serialized = bincode::serialize(&compact_list).unwrap();
        let compact_list: ProvenCompactCiphertextList = bincode::deserialize(&serialized).unwrap();
        let expander = compact_list
            .verify_and_expand(&crs, &pk, &metadata)
            .unwrap();

        {
            let a: FheUint32 = expander.get(0).unwrap().unwrap();
            let b: FheInt64 = expander.get(1).unwrap().unwrap();
            let c: FheBool = expander.get(2).unwrap().unwrap();
            let d: FheUint2 = expander.get(3).unwrap().unwrap();

            let a: u32 = a.decrypt(&ck);
            assert_eq!(a, 17);
            let b: i64 = b.decrypt(&ck);
            assert_eq!(b, -1);
            let c = c.decrypt(&ck);
            assert!(!c);
            let d: u8 = d.decrypt(&ck);
            assert_eq!(d, 3);

            assert!(expander.get::<FheBool>(4).unwrap().is_none());
        }

        {
            // Incorrect type
            assert!(expander.get::<FheInt64>(0).is_err());

            // Correct type but wrong number of bits
            assert!(expander.get::<FheUint16>(0).is_err());
        }

        let unverified_expander = compact_list.expand_without_verification().unwrap();

        {
            let a: FheUint32 = unverified_expander.get(0).unwrap().unwrap();
            let b: FheInt64 = unverified_expander.get(1).unwrap().unwrap();
            let c: FheBool = unverified_expander.get(2).unwrap().unwrap();
            let d: FheUint2 = unverified_expander.get(3).unwrap().unwrap();

            let a: u32 = a.decrypt(&ck);
            assert_eq!(a, 17);
            let b: i64 = b.decrypt(&ck);
            assert_eq!(b, -1);
            let c = c.decrypt(&ck);
            assert!(!c);
            let d: u8 = d.decrypt(&ck);
            assert_eq!(d, 3);

            assert!(unverified_expander.get::<FheBool>(4).unwrap().is_none());
        }
    }

    #[cfg(feature = "strings")]
    #[test]
    fn test_compact_list_with_string_and_casting() {
        use crate::FheAsciiString;

        let config = crate::ConfigBuilder::with_custom_parameters(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )
        .use_dedicated_compact_public_key_parameters((
            PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        ))
        .build();

        let ck = crate::ClientKey::generate(config);
        let sk = crate::ServerKey::new(&ck);
        let pk = crate::CompactPublicKey::new(&ck);

        let string1 = ClearString::new("The quick brown fox".to_string());
        let string2 = ClearString::new("jumps over the lazy dog".to_string());

        let compact_list = CompactCiphertextList::builder(&pk)
            .push(17u32)
            .push(true)
            .push(&string1)
            .push_string_with_fixed_size(&string2, 55)
            .build_packed();

        let serialized = bincode::serialize(&compact_list).unwrap();
        let compact_list: CompactCiphertextList = bincode::deserialize(&serialized).unwrap();
        let expander = compact_list.expand_with_key(&sk).unwrap();

        {
            let a: FheUint32 = expander.get(0).unwrap().unwrap();
            let b: FheBool = expander.get(1).unwrap().unwrap();
            let c: FheAsciiString = expander.get(2).unwrap().unwrap();
            let d: FheAsciiString = expander.get(3).unwrap().unwrap();

            assert_eq!(expander.get_kind_of(0), Some(crate::FheTypes::Uint32));
            assert_eq!(expander.get_kind_of(1), Some(crate::FheTypes::Bool));
            assert_eq!(expander.get_kind_of(2), Some(crate::FheTypes::AsciiString));
            assert_eq!(expander.get_kind_of(3), Some(crate::FheTypes::AsciiString));

            let a: u32 = a.decrypt(&ck);
            assert_eq!(a, 17);
            let b: bool = b.decrypt(&ck);
            assert!(b);
            let c = c.decrypt(&ck);
            assert_eq!(&c, string1.str());
            let d = d.decrypt(&ck);
            assert_eq!(&d, string2.str());

            assert!(expander.get::<FheBool>(4).unwrap().is_none());
        }

        {
            // Incorrect type
            assert!(expander.get::<FheInt64>(0).is_err());

            // Correct type but wrong number of bits
            assert!(expander.get::<FheAsciiString>(0).is_err());
        }
    }
}
