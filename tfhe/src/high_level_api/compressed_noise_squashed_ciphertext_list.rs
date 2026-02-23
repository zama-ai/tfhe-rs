use crate::backward_compatibility::compressed_ciphertext_list::CompressedSquashedNoiseCiphertextListVersions;
use crate::high_level_api::booleans::InnerSquashedNoiseBoolean;
use crate::high_level_api::global_state::try_with_internal_keys;
#[cfg(feature = "gpu")]
use crate::high_level_api::global_state::{
    with_cuda_internal_keys, with_thread_local_cuda_streams_for_gpu_indexes,
};
use crate::high_level_api::integers::signed::InnerSquashedNoiseSignedRadixCiphertext;
use crate::high_level_api::integers::unsigned::InnerSquashedNoiseRadixCiphertext;
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::traits::Tagged;
use crate::high_level_api::SquashedNoiseCiphertextState;
use crate::integer::ciphertext::{
    CompressedSquashedNoiseCiphertextList as IntegerCompressedSquashedNoiseCiphertextList,
    DataKind, SquashedNoiseBooleanBlock, SquashedNoiseExpandable, SquashedNoiseRadixCiphertext,
    SquashedNoiseSignedRadixCiphertext,
};
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::squashed_noise::CudaSquashedNoiseRadixCiphertext;
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::{
    CudaCompressedSquashedNoiseCiphertextList, CudaSquashedNoiseExpandable,
};
use crate::named::Named;
use crate::shortint::ciphertext::SquashedNoiseCiphertext;
use crate::{
    Device, SquashedNoiseFheBool, SquashedNoiseFheInt, SquashedNoiseFheUint, Tag, Versionize,
};
#[cfg(feature = "gpu")]
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::num::NonZero;
use tfhe_versionable::{Unversionize, UnversionizeError, VersionizeOwned};

#[derive(Clone)]
pub(in crate::high_level_api) enum InnerCompressedSquashedNoiseCiphertextList {
    Cpu(IntegerCompressedSquashedNoiseCiphertextList),
    #[cfg(feature = "gpu")]
    Cuda(CudaCompressedSquashedNoiseCiphertextList),
}

impl Versionize for InnerCompressedSquashedNoiseCiphertextList {
    type Versioned<'vers> =
        <IntegerCompressedSquashedNoiseCiphertextList as VersionizeOwned>::VersionedOwned;

    fn versionize(&self) -> Self::Versioned<'_> {
        self.on_cpu().versionize_owned()
    }
}

impl VersionizeOwned for InnerCompressedSquashedNoiseCiphertextList {
    type VersionedOwned =
        <IntegerCompressedSquashedNoiseCiphertextList as VersionizeOwned>::VersionedOwned;

    fn versionize_owned(self) -> Self::VersionedOwned {
        self.into_cpu().versionize_owned()
    }
}

impl Unversionize for InnerCompressedSquashedNoiseCiphertextList {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        IntegerCompressedSquashedNoiseCiphertextList::unversionize(versioned).map(Self::Cpu)
    }
}

impl Serialize for InnerCompressedSquashedNoiseCiphertextList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.on_cpu().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for InnerCompressedSquashedNoiseCiphertextList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut new = IntegerCompressedSquashedNoiseCiphertextList::deserialize(deserializer)
            .map(Self::Cpu)?;

        if let Some(device) = crate::high_level_api::global_state::device_of_internal_keys() {
            new.move_to_device(device)
                .map_err(serde::de::Error::custom)?;
        }

        Ok(new)
    }
}

impl InnerCompressedSquashedNoiseCiphertextList {
    /// Returns the inner cpu compressed ciphertext list if self is on the CPU, otherwise, returns a
    /// copy that is on the CPU
    fn on_cpu(&self) -> IntegerCompressedSquashedNoiseCiphertextList {
        match self {
            Self::Cpu(cpu_ct) => cpu_ct.clone(),
            #[cfg(feature = "gpu")]
            Self::Cuda(cuda_ct) => {
                let cpu_ct = with_thread_local_cuda_streams_for_gpu_indexes(
                    cuda_ct.gpu_indexes(),
                    |streams| cuda_ct.to_compressed_squashed_noise_ciphertext_list(streams),
                );
                cpu_ct
            }
        }
    }

    fn into_cpu(self) -> IntegerCompressedSquashedNoiseCiphertextList {
        match self {
            Self::Cpu(cpu_ct) => cpu_ct,
            #[cfg(feature = "gpu")]
            Self::Cuda(cuda_ct) => {
                let cpu_ct = with_thread_local_cuda_streams_for_gpu_indexes(
                    cuda_ct.gpu_indexes(),
                    |streams| cuda_ct.to_compressed_squashed_noise_ciphertext_list(streams),
                );
                cpu_ct
            }
        }
    }

    fn current_device(&self) -> crate::Device {
        match self {
            Self::Cpu(_) => crate::Device::Cpu,
            #[cfg(feature = "gpu")]
            Self::Cuda(_) => crate::Device::CudaGpu,
        }
    }

    #[cfg_attr(not(feature = "gpu"), allow(clippy::needless_pass_by_ref_mut))]
    #[allow(clippy::unnecessary_wraps, reason = "It depends on activated features")]
    fn move_to_device(&mut self, target_device: crate::Device) -> crate::Result<()> {
        let current_device = self.current_device();

        if current_device == target_device {
            #[cfg(feature = "gpu")]
            // We may not be on the correct Cuda device
            if let Self::Cuda(cuda_ct) = self {
                with_cuda_internal_keys(|keys| {
                    let streams = &keys.streams;
                    if cuda_ct.gpu_indexes() != streams.gpu_indexes() {
                        *cuda_ct = cuda_ct.duplicate(streams);
                    }
                })
            }
            return Ok(());
        }

        // The logic is that the common device is the CPU, all other devices
        // know how to transfer from and to CPU.

        // So we first transfer to CPU
        let cpu_ct = self.on_cpu();

        // Then we can transfer the desired device
        match target_device {
            Device::Cpu => {
                let _ = cpu_ct;
            }
            #[cfg(feature = "gpu")]
            Device::CudaGpu => {
                let new_inner = with_cuda_internal_keys(|keys| {
                    let streams = &keys.streams;
                    CudaCompressedSquashedNoiseCiphertextList::from_compressed_squashed_noise_ciphertext_list(&cpu_ct, streams)
                });
                *self = Self::Cuda(new_inner);
            }
            #[cfg(feature = "hpu")]
            Device::Hpu => {
                panic!("HPU does not support compression");
            }
        }

        Ok(())
    }
}

/// Compressed ciphertext list for squashed noise ciphertext
///
/// This list supports
///
/// * [SquashedNoiseFheUint]
/// * [SquashedNoiseFheInt]
/// * [SquashedNoiseFheBool]
///
/// Use the [CompressedSquashedNoiseCiphertextListBuilder] struct to
/// build a list.
///
/// This requires the server key to have noise-squashing compression keys,
/// which is enabled by calling [crate::ConfigBuilder::enable_noise_squashing_compression]
#[derive(Serialize, Deserialize, Versionize)]
#[versionize(CompressedSquashedNoiseCiphertextListVersions)]
pub struct CompressedSquashedNoiseCiphertextList {
    pub(in crate::high_level_api) inner: InnerCompressedSquashedNoiseCiphertextList,
    pub(crate) tag: Tag,
}

impl Named for CompressedSquashedNoiseCiphertextList {
    const NAME: &'static str = "high_level_api::CompressedSquashedNoiseCiphertextList";
}

impl CompressedSquashedNoiseCiphertextList {
    pub fn builder() -> CompressedSquashedNoiseCiphertextListBuilder {
        CompressedSquashedNoiseCiphertextListBuilder::new()
    }

    pub fn len(&self) -> usize {
        match &self.inner {
            InnerCompressedSquashedNoiseCiphertextList::Cpu(inner) => inner.len(),
            #[cfg(feature = "gpu")]
            InnerCompressedSquashedNoiseCiphertextList::Cuda(inner) => inner.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get<T>(&self, index: usize) -> crate::Result<Option<T>>
    where
        T: HlSquashedNoiseExpandable + Tagged,
    {
        let mut r = match &self.inner {
            InnerCompressedSquashedNoiseCiphertextList::Cpu(inner) => inner.get::<T>(index),
            #[cfg(feature = "gpu")]
            InnerCompressedSquashedNoiseCiphertextList::Cuda(cuda_ct) => {
                with_thread_local_cuda_streams_for_gpu_indexes(cuda_ct.gpu_indexes(), |streams| {
                    cuda_ct.get::<T>(index, streams)
                })
            }
        };

        if let Ok(Some(ct)) = &mut r {
            *ct.tag_mut() = self.tag.clone();
        }
        r
    }
}
#[cfg(not(feature = "gpu"))]
pub trait HlSquashedNoiseExpandable: SquashedNoiseExpandable {}
#[cfg(feature = "gpu")]
pub trait HlSquashedNoiseExpandable: SquashedNoiseExpandable + CudaSquashedNoiseExpandable {}

fn create_error_message(tried: DataKind, actual: DataKind) -> crate::Error {
    fn name(kind: DataKind) -> &'static str {
        match kind {
            DataKind::Unsigned(_) => "SquashedNoiseFheUint",
            DataKind::Signed(_) => "SquashedNoiseFheInt",
            DataKind::Boolean => "SquashedNoiseFheBool",
            DataKind::String { .. } => "SquashedNoiseFheString",
        }
    }
    crate::error!(
        "Tried to expand a {}, but a {} is stored in this slot",
        name(tried),
        name(actual)
    )
}

impl SquashedNoiseExpandable for SquashedNoiseFheBool {
    fn from_expanded_blocks(
        blocks: Vec<SquashedNoiseCiphertext>,
        kind: DataKind,
    ) -> crate::Result<Self> {
        if kind == DataKind::Boolean {
            SquashedNoiseBooleanBlock::from_expanded_blocks(blocks, kind).map(|v| {
                Self::new(
                    InnerSquashedNoiseBoolean::Cpu(v),
                    SquashedNoiseCiphertextState::PostDecompression,
                    Tag::default(),
                )
            })
        } else {
            Err(create_error_message(DataKind::Boolean, kind))
        }
    }
}

impl SquashedNoiseExpandable for SquashedNoiseFheUint {
    fn from_expanded_blocks(
        blocks: Vec<SquashedNoiseCiphertext>,
        kind: DataKind,
    ) -> crate::Result<Self> {
        if matches!(kind, DataKind::Unsigned(_)) {
            SquashedNoiseRadixCiphertext::from_expanded_blocks(blocks, kind).map(|v| {
                Self::new(
                    InnerSquashedNoiseRadixCiphertext::Cpu(v),
                    SquashedNoiseCiphertextState::PostDecompression,
                    Tag::default(),
                )
            })
        } else {
            Err(create_error_message(
                DataKind::Unsigned(NonZero::new(1).unwrap()),
                kind,
            ))
        }
    }
}

impl SquashedNoiseExpandable for SquashedNoiseFheInt {
    fn from_expanded_blocks(
        blocks: Vec<SquashedNoiseCiphertext>,
        kind: DataKind,
    ) -> crate::Result<Self> {
        if matches!(kind, DataKind::Signed(_)) {
            SquashedNoiseSignedRadixCiphertext::from_expanded_blocks(blocks, kind).map(|v| {
                Self::new(
                    InnerSquashedNoiseSignedRadixCiphertext::Cpu(v),
                    SquashedNoiseCiphertextState::PostDecompression,
                    Tag::default(),
                )
            })
        } else {
            Err(create_error_message(
                DataKind::Signed(NonZero::new(1).unwrap()),
                kind,
            ))
        }
    }
}

impl HlSquashedNoiseExpandable for SquashedNoiseFheBool {}

impl HlSquashedNoiseExpandable for SquashedNoiseFheUint {}

impl HlSquashedNoiseExpandable for SquashedNoiseFheInt {}

#[cfg(feature = "gpu")]
mod gpu {
    use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
    use crate::high_level_api::booleans::InnerSquashedNoiseBoolean;
    use crate::high_level_api::integers::signed::InnerSquashedNoiseSignedRadixCiphertext;
    use crate::high_level_api::integers::unsigned::InnerSquashedNoiseRadixCiphertext;
    use crate::high_level_api::SquashedNoiseCiphertextState;
    use crate::integer::ciphertext::DataKind;
    use crate::integer::gpu::ciphertext::info::CudaRadixCiphertextInfo;
    use crate::integer::gpu::ciphertext::squashed_noise::{
        CudaSquashedNoiseBooleanBlock, CudaSquashedNoiseRadixCiphertext,
        CudaSquashedNoiseSignedRadixCiphertext,
    };
    use crate::integer::gpu::ciphertext::CudaSquashedNoiseExpandable;
    use crate::{SquashedNoiseFheBool, SquashedNoiseFheInt, SquashedNoiseFheUint, Tag};

    impl CudaSquashedNoiseExpandable for SquashedNoiseFheBool {
        fn from_expanded_blocks(
            blocks: CudaLweCiphertextList<u128>,
            info: CudaRadixCiphertextInfo,
            _kind: DataKind,
        ) -> crate::Result<Self> {
            let cuda_ns_ct = CudaSquashedNoiseRadixCiphertext {
                packed_d_blocks: blocks,
                info,
                original_block_count: 1,
            };
            let cuda_ns_boolean_ct = CudaSquashedNoiseBooleanBlock {
                ciphertext: cuda_ns_ct,
            };
            Ok(Self::new(
                InnerSquashedNoiseBoolean::Cuda(cuda_ns_boolean_ct),
                SquashedNoiseCiphertextState::PostDecompression,
                Tag::default(),
            ))
        }
    }

    impl CudaSquashedNoiseExpandable for SquashedNoiseFheUint {
        fn from_expanded_blocks(
            blocks: CudaLweCiphertextList<u128>,
            info: CudaRadixCiphertextInfo,
            kind: DataKind,
        ) -> crate::Result<Self> {
            let message_modulus = info.blocks.first().unwrap().message_modulus;

            let cuda_ns_ct = CudaSquashedNoiseRadixCiphertext {
                packed_d_blocks: blocks,
                info,
                original_block_count: kind.num_blocks(message_modulus),
            };
            Ok(Self::new(
                InnerSquashedNoiseRadixCiphertext::Cuda(cuda_ns_ct),
                SquashedNoiseCiphertextState::PostDecompression,
                Tag::default(),
            ))
        }
    }
    impl CudaSquashedNoiseExpandable for SquashedNoiseFheInt {
        fn from_expanded_blocks(
            blocks: CudaLweCiphertextList<u128>,
            info: CudaRadixCiphertextInfo,
            kind: DataKind,
        ) -> crate::Result<Self> {
            let message_modulus = info.blocks.first().unwrap().message_modulus;
            let cuda_ns_ct = CudaSquashedNoiseRadixCiphertext {
                packed_d_blocks: blocks,
                info,
                original_block_count: kind.num_blocks(message_modulus),
            };
            let cuda_ns_signed_ct = CudaSquashedNoiseSignedRadixCiphertext {
                ciphertext: cuda_ns_ct,
            };
            Ok(Self::new(
                InnerSquashedNoiseSignedRadixCiphertext::Cuda(cuda_ns_signed_ct),
                SquashedNoiseCiphertextState::PostDecompression,
                Tag::default(),
            ))
        }
    }
}

mod private {
    #[cfg(feature = "gpu")]
    use crate::integer::gpu::ciphertext::squashed_noise::CudaSquashedNoiseRadixCiphertext;
    use crate::shortint::ciphertext::SquashedNoiseCiphertext;

    pub enum SquashedNoiseToBeCompressed {
        Cpu(Vec<SquashedNoiseCiphertext>),
        #[cfg(feature = "gpu")]
        Cuda(CudaSquashedNoiseRadixCiphertext),
    }
}

pub trait HlSquashedNoiseCompressible {
    fn compress_into(self, messages: &mut Vec<(private::SquashedNoiseToBeCompressed, DataKind)>);
}

impl HlSquashedNoiseCompressible for SquashedNoiseFheBool {
    fn compress_into(self, messages: &mut Vec<(private::SquashedNoiseToBeCompressed, DataKind)>) {
        let kind = DataKind::Boolean;
        match self.inner {
            InnerSquashedNoiseBoolean::Cpu(cpu_ct) => messages.push((
                private::SquashedNoiseToBeCompressed::Cpu(vec![cpu_ct.ciphertext]),
                kind,
            )),
            #[cfg(feature = "gpu")]
            InnerSquashedNoiseBoolean::Cuda(gpu_ct) => messages.push((
                private::SquashedNoiseToBeCompressed::Cuda(gpu_ct.ciphertext),
                kind,
            )),
        }
    }
}

impl HlSquashedNoiseCompressible for SquashedNoiseFheUint {
    fn compress_into(self, messages: &mut Vec<(private::SquashedNoiseToBeCompressed, DataKind)>) {
        match self.inner {
            InnerSquashedNoiseRadixCiphertext::Cpu(cpu_ct) => {
                if cpu_ct.original_block_count != 0 {
                    let kind =
                        DataKind::Unsigned(NonZero::new(cpu_ct.original_block_count).unwrap());
                    messages.push((
                        private::SquashedNoiseToBeCompressed::Cpu(cpu_ct.packed_blocks),
                        kind,
                    ))
                }
            }
            #[cfg(feature = "gpu")]
            InnerSquashedNoiseRadixCiphertext::Cuda(gpu_ct) => {
                if let Some(n) = NonZero::new(gpu_ct.original_block_count) {
                    let kind = DataKind::Unsigned(n);
                    messages.push((private::SquashedNoiseToBeCompressed::Cuda(gpu_ct), kind));
                }
            }
        }
    }
}

impl HlSquashedNoiseCompressible for SquashedNoiseFheInt {
    fn compress_into(self, messages: &mut Vec<(private::SquashedNoiseToBeCompressed, DataKind)>) {
        match self.inner {
            InnerSquashedNoiseSignedRadixCiphertext::Cpu(cpu_ct) => {
                if cpu_ct.original_block_count() != 0 {
                    let kind = DataKind::Signed(NonZero::new(cpu_ct.original_block_count).unwrap());
                    messages.push((
                        private::SquashedNoiseToBeCompressed::Cpu(cpu_ct.packed_blocks),
                        kind,
                    ))
                }
            }
            #[cfg(feature = "gpu")]
            InnerSquashedNoiseSignedRadixCiphertext::Cuda(gpu_ct) => {
                if let Some(n) = NonZero::new(gpu_ct.ciphertext.original_block_count) {
                    let kind = DataKind::Signed(n);
                    messages.push((
                        private::SquashedNoiseToBeCompressed::Cuda(gpu_ct.ciphertext),
                        kind,
                    ));
                }
            }
        }
    }
}

/// Builder to create [CompressedSquashedNoiseCiphertextList]
///
/// Use [push](Self::push) to add squashed noise ciphertext to the list,
/// then call [build](Self::build) to build the list.
pub struct CompressedSquashedNoiseCiphertextListBuilder {
    inner: Vec<(private::SquashedNoiseToBeCompressed, DataKind)>,
}

impl Default for CompressedSquashedNoiseCiphertextListBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CompressedSquashedNoiseCiphertextListBuilder {
    pub fn new() -> Self {
        Self { inner: vec![] }
    }

    pub fn push<T>(&mut self, value: T) -> &mut Self
    where
        T: HlSquashedNoiseCompressible,
    {
        value.compress_into(&mut self.inner);
        self
    }

    pub fn build(&self) -> crate::Result<CompressedSquashedNoiseCiphertextList> {
        try_with_internal_keys(|keys| match keys {
            Some(InternalServerKey::Cpu(cpu_key)) => {
                let mut flat_cpu_blocks = vec![];
                for (element, _) in &self.inner {
                    match element {
                        private::SquashedNoiseToBeCompressed::Cpu(cpu_blocks) => {
                            flat_cpu_blocks.extend_from_slice(cpu_blocks.as_slice());
                        }
                        #[cfg(feature = "gpu")]
                        private::SquashedNoiseToBeCompressed::Cuda(gpu_blocks) => {
                            // If gpu_blocks is on the GPU, we bring it back to the CPU
                            let cpu_blocks = with_thread_local_cuda_streams_for_gpu_indexes(
                                gpu_blocks.gpu_indexes(),
                                |streams| gpu_blocks.to_squashed_noise_radix_ciphertext(streams),
                            );

                            let vec_cpu_blocks =
                                cpu_blocks.packed_blocks.iter().cloned().collect_vec();
                            flat_cpu_blocks.extend_from_slice(vec_cpu_blocks.as_slice());
                        }
                    }
                }
                cpu_key
                    .key
                    .noise_squashing_compression_key
                    .as_ref()
                    .ok_or_else(|| {
                        crate::Error::new(
                            "Compression key for squashed noise data not set in server key"
                                .to_owned(),
                        )
                    })
                    .map(|compression_key| {
                        let compressed_list = compression_key
                            .key
                            .compress_noise_squashed_ciphertexts_into_list(&flat_cpu_blocks);
                        let info = self.inner.iter().map(|(_, kind)| *kind).collect();

                        CompressedSquashedNoiseCiphertextList {
                            inner: InnerCompressedSquashedNoiseCiphertextList::Cpu(
                                IntegerCompressedSquashedNoiseCiphertextList {
                                    list: compressed_list,
                                    info,
                                },
                            ),
                            tag: cpu_key.tag.clone(),
                        }
                    })
            }
            #[cfg(feature = "gpu")]
            Some(InternalServerKey::Cuda(cuda_key)) => {
                let mut cuda_radixes = vec![];
                for (element, _) in &self.inner {
                    match element {
                        private::SquashedNoiseToBeCompressed::Cpu(cpu_blocks) => {
                            let streams = &cuda_key.streams;
                            cuda_radixes.push(CudaSquashedNoiseRadixCiphertext::from_cpu_blocks(
                                cpu_blocks, streams,
                            ));
                        }
                        #[cfg(feature = "gpu")]
                        private::SquashedNoiseToBeCompressed::Cuda(cuda_radix) => {
                            {
                                let streams = &cuda_key.streams;
                                cuda_radixes.push(cuda_radix.duplicate(streams));
                            };
                        }
                    }
                }

                cuda_key
                    .key
                    .noise_squashing_compression_key
                    .as_ref()
                    .ok_or_else(|| {
                        crate::Error::new("Compression key not set in server key".to_owned())
                    })
                    .map(|compression_key| {
                        let streams = &cuda_key.streams;
                        let compressed_list = compression_key
                            .compress_noise_squashed_ciphertexts_into_list(&cuda_radixes, streams);
                        let info = self.inner.iter().map(|(_, kind)| *kind).collect();

                        CompressedSquashedNoiseCiphertextList {
                            inner: InnerCompressedSquashedNoiseCiphertextList::Cuda(
                                CudaCompressedSquashedNoiseCiphertextList {
                                    packed_list: compressed_list,
                                    info,
                                },
                            ),
                            tag: cuda_key.tag.clone(),
                        }
                    })
            }
            #[cfg(feature = "hpu")]
            Some(InternalServerKey::Hpu(_)) => Err(crate::error!(
                "HPU does not support compression of squashed noise ciphertexts"
            )),
            None => Err(crate::high_level_api::errors::UninitializedServerKey.into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::*;
    use crate::safe_serialization::{safe_deserialize, safe_serialize};
    use crate::shortint::parameters::current_params::*;
    use crate::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheInt32, FheUint32};
    use rand::Rng;

    #[test]
    fn test_compressed_squashed_noise_ciphertext_list() {
        let params = V1_6_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let noise_squashing_params =
            V1_6_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let noise_squashing_compression_params =
            V1_6_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let config = ConfigBuilder::with_custom_parameters(params)
            .enable_noise_squashing(noise_squashing_params)
            .enable_noise_squashing_compression(noise_squashing_compression_params)
            .build();

        let (cks, sks) = generate_keys(config);

        let mut rng = rand::rng();

        let clear_a = rng.gen::<i32>();
        let clear_b = rng.gen::<u32>();
        let clear_c = rng.gen_bool(0.5);

        let a = FheInt32::encrypt(clear_a, &cks);
        let b = FheUint32::encrypt(clear_b, &cks);
        let c = FheBool::encrypt(clear_c, &cks);

        set_server_key(sks);

        let ns_a = a.squash_noise().unwrap();
        let ns_b = b.squash_noise().unwrap();
        let ns_c = c.squash_noise().unwrap();

        let list = CompressedSquashedNoiseCiphertextList::builder()
            .push(ns_a)
            .push(ns_b)
            .push(ns_c)
            .build()
            .unwrap();

        let mut serialized_list = vec![];
        safe_serialize(&list, &mut serialized_list, 1 << 24).unwrap();
        let list: CompressedSquashedNoiseCiphertextList =
            safe_deserialize(serialized_list.as_slice(), 1 << 24).unwrap();

        let ns_a: SquashedNoiseFheInt = list.get(0).unwrap().unwrap();
        let ns_b: SquashedNoiseFheUint = list.get(1).unwrap().unwrap();
        let ns_c: SquashedNoiseFheBool = list.get(2).unwrap().unwrap();

        let decrypted: i32 = ns_a.decrypt(&cks);
        assert_eq!(decrypted, clear_a);

        let decrypted: u32 = ns_b.decrypt(&cks);
        assert_eq!(decrypted, clear_b);

        let decrypted: bool = ns_c.decrypt(&cks);
        assert_eq!(decrypted, clear_c);
    }

    #[test]
    #[cfg(feature = "gpu")]
    fn test_gpu_compressed_squashed_noise_ciphertext_list() {
        let params = V1_6_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let noise_squashing_params =
            V1_6_NOISE_SQUASHING_PARAM_GPU_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let noise_squashing_compression_params =
            V1_6_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let config = ConfigBuilder::with_custom_parameters(params)
            .enable_noise_squashing(noise_squashing_params)
            .enable_noise_squashing_compression(noise_squashing_compression_params)
            .build();

        let cks = crate::ClientKey::generate(config);
        let sks = crate::CompressedServerKey::new(&cks);

        set_server_key(sks.decompress_to_gpu());

        let mut rng = rand::rng();

        let clear_a = rng.gen::<i32>();
        let clear_b = rng.gen::<u32>();
        let clear_c = rng.gen_bool(0.5);

        let mut a = FheInt32::encrypt(clear_a, &cks);
        let mut b = FheUint32::encrypt(clear_b, &cks);
        let mut c = FheBool::encrypt(clear_c, &cks);

        a.move_to_device(crate::Device::CudaGpu);
        b.move_to_device(crate::Device::CudaGpu);
        c.move_to_device(crate::Device::CudaGpu);

        let ns_a = a.squash_noise().unwrap();
        let ns_b = b.squash_noise().unwrap();
        let ns_c = c.squash_noise().unwrap();

        let list = CompressedSquashedNoiseCiphertextList::builder()
            .push(ns_a)
            .push(ns_b)
            .push(ns_c)
            .build()
            .unwrap();

        let mut serialized_list = vec![];
        safe_serialize(&list, &mut serialized_list, 1 << 24).unwrap();
        let list: CompressedSquashedNoiseCiphertextList =
            safe_deserialize(serialized_list.as_slice(), 1 << 24).unwrap();

        let ns_a: SquashedNoiseFheInt = list.get(0).unwrap().unwrap();
        let ns_b: SquashedNoiseFheUint = list.get(1).unwrap().unwrap();
        let ns_c: SquashedNoiseFheBool = list.get(2).unwrap().unwrap();

        let decrypted: i32 = ns_a.decrypt(&cks);
        assert_eq!(decrypted, clear_a);

        let decrypted: u32 = ns_b.decrypt(&cks);
        assert_eq!(decrypted, clear_b);

        let decrypted: bool = ns_c.decrypt(&cks);
        assert_eq!(decrypted, clear_c);
    }
    #[test]
    #[cfg(feature = "gpu")]
    fn test_gpu_compressed_squashed_noise_ciphertext_list_multibit() {
        let params = V1_6_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let noise_squashing_params =
            V1_6_NOISE_SQUASHING_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let noise_squashing_compression_params =
            V1_6_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let config = ConfigBuilder::with_custom_parameters(params)
            .enable_noise_squashing(noise_squashing_params)
            .enable_noise_squashing_compression(noise_squashing_compression_params)
            .build();

        let cks = crate::ClientKey::generate(config);
        let sks = crate::CompressedServerKey::new(&cks);

        set_server_key(sks.decompress_to_gpu());

        let mut rng = rand::rng();

        let clear_a = rng.gen::<i32>();
        let clear_b = rng.gen::<u32>();
        let clear_c = rng.gen_bool(0.5);

        let mut a = FheInt32::encrypt(clear_a, &cks);
        let mut b = FheUint32::encrypt(clear_b, &cks);
        let mut c = FheBool::encrypt(clear_c, &cks);

        a.move_to_device(crate::Device::CudaGpu);
        b.move_to_device(crate::Device::CudaGpu);
        c.move_to_device(crate::Device::CudaGpu);

        let ns_a = a.squash_noise().unwrap();
        let ns_b = b.squash_noise().unwrap();
        let ns_c = c.squash_noise().unwrap();

        let list = CompressedSquashedNoiseCiphertextList::builder()
            .push(ns_a)
            .push(ns_b)
            .push(ns_c)
            .build()
            .unwrap();

        let mut serialized_list = vec![];
        safe_serialize(&list, &mut serialized_list, 1 << 24).unwrap();
        let list: CompressedSquashedNoiseCiphertextList =
            safe_deserialize(serialized_list.as_slice(), 1 << 24).unwrap();

        let ns_a: SquashedNoiseFheInt = list.get(0).unwrap().unwrap();
        let ns_b: SquashedNoiseFheUint = list.get(1).unwrap().unwrap();
        let ns_c: SquashedNoiseFheBool = list.get(2).unwrap().unwrap();

        let decrypted: i32 = ns_a.decrypt(&cks);
        assert_eq!(decrypted, clear_a);

        let decrypted: u32 = ns_b.decrypt(&cks);
        assert_eq!(decrypted, clear_b);

        let decrypted: bool = ns_c.decrypt(&cks);
        assert_eq!(decrypted, clear_c);
    }
}
