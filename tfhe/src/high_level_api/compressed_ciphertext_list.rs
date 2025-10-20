use std::num::NonZero;
use tfhe_versionable::{Unversionize, UnversionizeError, Versionize, VersionizeOwned};

use super::details::MaybeCloned;
#[cfg(feature = "gpu")]
use super::global_state::with_thread_local_cuda_streams_for_gpu_indexes;
use super::keys::InternalServerKey;
#[cfg(feature = "gpu")]
use super::GpuIndex;
use crate::backward_compatibility::compressed_ciphertext_list::CompressedCiphertextListVersions;
use crate::core_crypto::commons::math::random::{Deserialize, Serialize};
#[cfg(feature = "gpu")]
use crate::core_crypto::gpu::CudaStreams;
use crate::high_level_api::booleans::InnerBoolean;
use crate::high_level_api::errors::UninitializedServerKey;
#[cfg(feature = "gpu")]
use crate::high_level_api::global_state;
use crate::high_level_api::global_state::device_of_internal_keys;
#[cfg(feature = "gpu")]
use crate::high_level_api::global_state::with_cuda_internal_keys;
use crate::high_level_api::integers::{FheIntId, FheUintId};
use crate::high_level_api::re_randomization::ReRandomizationMetadata;
use crate::integer::ciphertext::{DataKind, Expandable};
use crate::integer::compression_keys::DecompressionKey;
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::compressed_ciphertext_list::{
    CudaCompressedCiphertextList, CudaExpandable,
};
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::CudaRadixCiphertext;
#[cfg(feature = "gpu")]
use crate::integer::gpu::list_compression::server_keys::CudaDecompressionKey;
#[cfg(feature = "gpu")]
use crate::integer::parameters::LweDimension;
use crate::named::Named;
use crate::prelude::{CiphertextList, Tagged};
use crate::shortint::Ciphertext;
#[cfg(feature = "gpu")]
use crate::shortint::{CarryModulus, MessageModulus};
use crate::{Device, FheBool, FheInt, FheUint, Tag};

impl<Id: FheUintId> HlCompressible for FheUint<Id> {
    fn compress_into(self, messages: &mut Vec<(ToBeCompressed, DataKind)>) {
        match self.ciphertext {
            crate::high_level_api::integers::unsigned::RadixCiphertext::Cpu(cpu_radix) => {
                let blocks = cpu_radix.blocks;
                if let Some(n) = NonZero::new(blocks.len()) {
                    let kind = DataKind::Unsigned(n);
                    messages.push((ToBeCompressed::Cpu(blocks), kind));
                }
            }
            #[cfg(feature = "gpu")]
            crate::high_level_api::integers::unsigned::RadixCiphertext::Cuda(gpu_radix) => {
                let blocks = gpu_radix.ciphertext;
                if let Some(n) = NonZero::new(blocks.info.blocks.len()) {
                    let kind = DataKind::Unsigned(n);
                    messages.push((ToBeCompressed::Cuda(blocks), kind));
                }
            }
            #[cfg(feature = "hpu")]
            crate::high_level_api::integers::unsigned::RadixCiphertext::Hpu(_) => {
                panic!("HPU does not support compression");
            }
        }
    }

    fn get_re_randomization_metadata(&self) -> ReRandomizationMetadata {
        self.re_randomization_metadata.clone()
    }
}
impl<Id: FheIntId> HlCompressible for FheInt<Id> {
    fn compress_into(self, messages: &mut Vec<(ToBeCompressed, DataKind)>) {
        match self.ciphertext {
            crate::high_level_api::integers::signed::SignedRadixCiphertext::Cpu(cpu_radix) => {
                let blocks = cpu_radix.blocks;
                if let Some(n) = NonZero::new(blocks.len()) {
                    let kind = DataKind::Signed(n);
                    messages.push((ToBeCompressed::Cpu(blocks), kind));
                }
            }
            #[cfg(feature = "gpu")]
            crate::high_level_api::integers::signed::SignedRadixCiphertext::Cuda(gpu_radix) => {
                let blocks = gpu_radix.ciphertext;
                if let Some(n) = NonZero::new(blocks.info.blocks.len()) {
                    let kind = DataKind::Signed(n);
                    messages.push((ToBeCompressed::Cuda(blocks), kind));
                }
            }
        }
    }

    fn get_re_randomization_metadata(&self) -> ReRandomizationMetadata {
        self.re_randomization_metadata.clone()
    }
}
impl HlCompressible for FheBool {
    fn compress_into(self, messages: &mut Vec<(ToBeCompressed, DataKind)>) {
        match self.ciphertext {
            InnerBoolean::Cpu(cpu_bool) => {
                let kind = DataKind::Boolean;
                messages.push((ToBeCompressed::Cpu(vec![cpu_bool.0]), kind));
            }
            #[cfg(feature = "gpu")]
            InnerBoolean::Cuda(cuda_bool) => {
                let kind = DataKind::Boolean;
                messages.push((ToBeCompressed::Cuda(cuda_bool.0.ciphertext), kind));
            }
            #[cfg(feature = "hpu")]
            InnerBoolean::Hpu(_) => panic!("HPU does not support compression"),
        }
    }

    fn get_re_randomization_metadata(&self) -> ReRandomizationMetadata {
        self.re_randomization_metadata.clone()
    }
}

impl<Id: FheUintId> HlExpandable for FheUint<Id> {
    fn set_re_randomization_metadata(&mut self, meta: ReRandomizationMetadata) {
        self.re_randomization_metadata = meta;
    }
}
impl<Id: FheIntId> HlExpandable for FheInt<Id> {
    fn set_re_randomization_metadata(&mut self, meta: ReRandomizationMetadata) {
        self.re_randomization_metadata = meta;
    }
}
impl HlExpandable for FheBool {
    fn set_re_randomization_metadata(&mut self, meta: ReRandomizationMetadata) {
        self.re_randomization_metadata = meta;
    }
}

#[cfg(not(feature = "gpu"))]
pub trait HlExpandable: Expandable {
    /// Sets the metadata of the ciphertext from the ones in the compressed list
    // Defined as an empty default method for backward compatibility
    fn set_re_randomization_metadata(&mut self, _meta: ReRandomizationMetadata) {}
}
#[cfg(feature = "gpu")]
pub trait HlExpandable: Expandable + CudaExpandable {
    fn set_re_randomization_metadata(&mut self, _meta: ReRandomizationMetadata) {}
}

pub trait HlCompressible {
    /// Adds a ciphertext to be compressed.
    ///
    /// This should push at most one single element at the end of the `messages` vec
    fn compress_into(self, messages: &mut Vec<(ToBeCompressed, DataKind)>);
    fn get_re_randomization_metadata(&self) -> ReRandomizationMetadata {
        ReRandomizationMetadata::default()
    }
}

pub enum ToBeCompressed {
    Cpu(Vec<Ciphertext>),
    #[cfg(feature = "gpu")]
    Cuda(CudaRadixCiphertext),
}

pub struct CompressedCiphertextListBuilder {
    inner: Vec<(ToBeCompressed, DataKind)>,
    rerandomization_metadata: Vec<ReRandomizationMetadata>,
}

impl CompressedCiphertextListBuilder {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            inner: vec![],
            rerandomization_metadata: vec![],
        }
    }

    pub fn push<T>(&mut self, value: T) -> &mut Self
    where
        T: HlCompressible,
    {
        let size_before = self.inner.len();
        let meta = value.get_re_randomization_metadata();
        value.compress_into(&mut self.inner);

        let size_after = self.inner.len();

        // `compress_into` should only push a single element at the end of the builder
        assert!(size_before <= size_after);
        assert!(size_after - size_before <= 1);
        if size_after - size_before == 1 {
            self.rerandomization_metadata.push(meta)
        }
        self
    }

    pub fn extend<T>(&mut self, values: impl Iterator<Item = T>) -> &mut Self
    where
        T: HlCompressible,
    {
        for value in values {
            self.push(value);
        }
        self
    }

    pub fn build(&self) -> crate::Result<CompressedCiphertextList> {
        if self.inner.len() != self.rerandomization_metadata.len() {
            return Err(crate::Error::new("Invalid CompressedCiphertextListBuilder, ct and metadata lists should have the same length".to_owned()));
        }

        crate::high_level_api::global_state::try_with_internal_keys(|keys| match keys {
            Some(InternalServerKey::Cpu(cpu_key)) => {
                let mut flat_cpu_blocks = vec![];
                for (element, _) in &self.inner {
                    match element {
                        ToBeCompressed::Cpu(cpu_blocks) => {
                            flat_cpu_blocks.extend_from_slice(cpu_blocks.as_slice());
                        }
                        #[cfg(feature = "gpu")]
                        ToBeCompressed::Cuda(cuda_radix) => {
                            with_thread_local_cuda_streams_for_gpu_indexes(
                                cuda_radix.d_blocks.0.d_vec.gpu_indexes.as_slice(),
                                |streams| {
                                    flat_cpu_blocks.append(&mut cuda_radix.to_cpu_blocks(streams));
                                },
                            );
                        }
                    }
                }
                cpu_key
                    .key
                    .compression_key
                    .as_ref()
                    .ok_or_else(|| {
                        crate::Error::new("Compression key not set in server key".to_owned())
                    })
                    .map(|compression_key| {
                        let compressed_list = compression_key
                            .key
                            .compress_ciphertexts_into_list(&flat_cpu_blocks);
                        let info = self.inner.iter().map(|(_, kind)| *kind).collect();

                        CompressedCiphertextList {
                            inner: InnerCompressedCiphertextList::Cpu(
                                crate::integer::ciphertext::CompressedCiphertextList {
                                    packed_list: compressed_list,
                                    info,
                                },
                            ),
                            tag: cpu_key.tag.clone(),
                            re_randomization_metadata: self.rerandomization_metadata.clone(),
                        }
                    })
            }
            #[cfg(feature = "gpu")]
            Some(InternalServerKey::Cuda(cuda_key)) => {
                let mut cuda_radixes = vec![];
                for (element, _) in &self.inner {
                    match element {
                        ToBeCompressed::Cpu(cpu_blocks) => {
                            let streams = &cuda_key.streams;
                            cuda_radixes
                                .push(CudaRadixCiphertext::from_cpu_blocks(cpu_blocks, streams));
                        }
                        #[cfg(feature = "gpu")]
                        ToBeCompressed::Cuda(cuda_radix) => {
                            {
                                let streams = &cuda_key.streams;
                                cuda_radixes.push(cuda_radix.duplicate(streams));
                            };
                        }
                    }
                }

                cuda_key
                    .key
                    .compression_key
                    .as_ref()
                    .ok_or_else(|| {
                        crate::Error::new("Compression key not set in server key".to_owned())
                    })
                    .map(|compression_key| {
                        let packed_list = {
                            let streams = &cuda_key.streams;
                            compression_key
                                .compress_ciphertexts_into_list(cuda_radixes.as_slice(), streams)
                        };
                        let info = self.inner.iter().map(|(_, kind)| *kind).collect();

                        let compressed_list = CudaCompressedCiphertextList { packed_list, info };

                        CompressedCiphertextList {
                            inner: InnerCompressedCiphertextList::Cuda(compressed_list),
                            tag: cuda_key.tag.clone(),
                            re_randomization_metadata: self.rerandomization_metadata.clone(),
                        }
                    })
            }
            #[cfg(feature = "hpu")]
            Some(InternalServerKey::Hpu(_)) => Err(crate::Error::new(
                "Hpu does not support compression".to_string(),
            )),
            None => Err(UninitializedServerKey.into()),
        })
    }
    #[cfg(feature = "gpu")]
    pub fn get_size_on_gpu(&self) -> crate::Result<u64> {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                let mut num_lwes = 0;
                let mut lwe_dimension = LweDimension(0);
                let mut message_modulus = MessageModulus(0);
                let mut carry_modulus = CarryModulus(0);
                for (element, _) in &self.inner {
                    if let ToBeCompressed::Cuda(cuda_radix) = element {
                        num_lwes += cuda_radix.d_blocks.0.lwe_ciphertext_count.0;
                        lwe_dimension = cuda_radix.d_blocks.0.lwe_dimension;
                        message_modulus = cuda_radix.info.blocks.first().unwrap().message_modulus;
                        carry_modulus = cuda_radix.info.blocks.first().unwrap().carry_modulus;
                    }
                }
                cuda_key
                    .key
                    .compression_key
                    .as_ref()
                    .ok_or_else(|| {
                        crate::Error::new("Compression key not set in server key".to_owned())
                    })
                    .map(|compression_key| {
                        compression_key.get_compression_size_on_gpu(
                            num_lwes as u32,
                            lwe_dimension,
                            message_modulus,
                            carry_modulus,
                            streams,
                        )
                    })
            } else {
                Ok(0)
            }
        })
    }
}

#[derive(Clone, Serialize)]
pub(crate) enum InnerCompressedCiphertextList {
    Cpu(crate::integer::ciphertext::CompressedCiphertextList),
    #[cfg(feature = "gpu")]
    Cuda(crate::integer::gpu::ciphertext::compressed_ciphertext_list::CudaCompressedCiphertextList),
}

impl<'de> serde::Deserialize<'de> for InnerCompressedCiphertextList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        enum Fake {
            Cpu(crate::integer::ciphertext::CompressedCiphertextList),
            #[cfg(feature = "gpu")]
            Cuda(crate::integer::gpu::ciphertext::compressed_ciphertext_list::CudaCompressedCiphertextList),
        }
        let mut new = match Fake::deserialize(deserializer)? {
            Fake::Cpu(v) => Self::Cpu(v),
            #[cfg(feature = "gpu")]
            Fake::Cuda(v) => Self::Cuda(v),
        };

        if let Some(device) = device_of_internal_keys() {
            new.move_to_device(device);
        }

        Ok(new)
    }
}

impl InnerCompressedCiphertextList {
    fn current_device(&self) -> crate::Device {
        match self {
            Self::Cpu(_) => crate::Device::Cpu,
            #[cfg(feature = "gpu")]
            Self::Cuda(_) => crate::Device::CudaGpu,
        }
    }

    #[allow(clippy::needless_pass_by_ref_mut)]
    fn move_to_device(&mut self, target_device: Device) {
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
            return;
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
                    cpu_ct.to_cuda_compressed_ciphertext_list(streams)
                });
                *self = Self::Cuda(new_inner);
            }
            #[cfg(feature = "hpu")]
            Device::Hpu => {
                panic!("HPU does not support compression");
            }
        }
    }

    fn on_cpu(&self) -> MaybeCloned<'_, crate::integer::ciphertext::CompressedCiphertextList> {
        match self {
            Self::Cpu(cpu_ct) => MaybeCloned::Borrowed(cpu_ct),
            #[cfg(feature = "gpu")]
            Self::Cuda(cuda_ct) => {
                let cpu_ct = with_thread_local_cuda_streams_for_gpu_indexes(
                    cuda_ct.gpu_indexes(),
                    |streams| cuda_ct.to_compressed_ciphertext_list(streams),
                );
                MaybeCloned::Cloned(cpu_ct)
            }
        }
    }

    #[cfg(feature = "gpu")]
    fn on_gpu(
        &self,
        streams: &CudaStreams,
    ) -> MaybeCloned<
        '_,
        crate::integer::gpu::ciphertext::compressed_ciphertext_list::CudaCompressedCiphertextList,
    > {
        match self {
            Self::Cpu(cpu_ct) => {
                let cuda_ct = cpu_ct.to_cuda_compressed_ciphertext_list(streams);
                MaybeCloned::Cloned(cuda_ct)
            }
            Self::Cuda(cuda_ct) => {
                if cuda_ct.gpu_indexes() == streams.gpu_indexes() {
                    MaybeCloned::Borrowed(cuda_ct)
                } else {
                    MaybeCloned::Cloned(cuda_ct.duplicate(streams))
                }
            }
        }
    }

    pub(crate) fn info(&self) -> &[DataKind] {
        match self {
            Self::Cpu(compressed_ciphertext_list) => &compressed_ciphertext_list.info,
            #[cfg(feature = "gpu")]
            Self::Cuda(compressed_ciphertext_list) => &compressed_ciphertext_list.info,
        }
    }
}

impl Versionize for InnerCompressedCiphertextList {
    type Versioned<'vers> =
        <crate::integer::ciphertext::CompressedCiphertextList as VersionizeOwned>::VersionedOwned;

    fn versionize(&self) -> Self::Versioned<'_> {
        match self {
            Self::Cpu(inner) => inner.clone().versionize_owned(),
            #[cfg(feature = "gpu")]
            Self::Cuda(inner) => {
                let cpu_data = with_cuda_internal_keys(|keys| {
                    let streams = &keys.streams;
                    inner.to_compressed_ciphertext_list(streams)
                });
                cpu_data.versionize_owned()
            }
        }
    }
}

impl VersionizeOwned for InnerCompressedCiphertextList {
    type VersionedOwned =
        <crate::integer::ciphertext::CompressedCiphertextList as VersionizeOwned>::VersionedOwned;

    fn versionize_owned(self) -> Self::VersionedOwned {
        match self {
            Self::Cpu(inner) => inner.versionize_owned(),
            #[cfg(feature = "gpu")]
            Self::Cuda(inner) => {
                let cpu_data = with_cuda_internal_keys(|keys| {
                    let streams = &keys.streams;
                    inner.to_compressed_ciphertext_list(streams)
                });
                cpu_data.versionize_owned()
            }
        }
    }
}

impl Unversionize for InnerCompressedCiphertextList {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        Ok(Self::Cpu(
            crate::integer::ciphertext::CompressedCiphertextList::unversionize(versioned)?,
        ))
    }
}

#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(CompressedCiphertextListVersions)]
pub struct CompressedCiphertextList {
    pub(in crate::high_level_api) inner: InnerCompressedCiphertextList,
    pub(in crate::high_level_api) tag: Tag,
    pub(in crate::high_level_api) re_randomization_metadata: Vec<ReRandomizationMetadata>,
}

impl Named for CompressedCiphertextList {
    const NAME: &'static str = "high_level_api::CompressedCiphertextList";
}

impl Tagged for CompressedCiphertextList {
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.tag
    }
}

impl CiphertextList for CompressedCiphertextList {
    fn len(&self) -> usize {
        match &self.inner {
            InnerCompressedCiphertextList::Cpu(inner) => inner.len(),
            #[cfg(feature = "gpu")]
            InnerCompressedCiphertextList::Cuda(inner) => inner.len(),
        }
    }

    fn is_empty(&self) -> bool {
        match &self.inner {
            InnerCompressedCiphertextList::Cpu(inner) => inner.len() == 0,
            #[cfg(feature = "gpu")]
            InnerCompressedCiphertextList::Cuda(inner) => inner.len() == 0,
        }
    }

    fn get_kind_of(&self, index: usize) -> Option<crate::FheTypes> {
        match &self.inner {
            InnerCompressedCiphertextList::Cpu(inner) => {
                inner.get_kind_of(index).and_then(|data_kind| {
                    crate::FheTypes::from_data_kind(data_kind, inner.packed_list.message_modulus()?)
                })
            }
            #[cfg(feature = "gpu")]
            InnerCompressedCiphertextList::Cuda(inner) => {
                inner.get_kind_of(index).and_then(|data_kind| {
                    crate::FheTypes::from_data_kind(data_kind, inner.packed_list.message_modulus()?)
                })
            }
        }
    }

    fn get<T>(&self, index: usize) -> crate::Result<Option<T>>
    where
        T: HlExpandable + Tagged,
    {
        // We use the server key to know where computation should happen,
        // if the data is not on the correct device, a temporary copy (and transfer) will happen
        //
        // This should be mitigated by the fact that the deserialization uses the current sks as a
        // hint on where to move data.
        crate::high_level_api::global_state::try_with_internal_keys(|keys| match keys {
            Some(InternalServerKey::Cpu(cpu_key)) => cpu_key
                .key
                .decompression_key
                .as_ref()
                .ok_or_else(|| {
                    crate::Error::new("Compression key not set in server key".to_owned())
                })
                .and_then(|decompression_key| {
                    self.get_using_key(index, decompression_key, &cpu_key.tag)
                }),
            #[cfg(feature = "gpu")]
            Some(InternalServerKey::Cuda(cuda_key)) => cuda_key
                .key
                .decompression_key
                .as_ref()
                .ok_or_else(|| {
                    crate::Error::new("Compression key not set in server key".to_owned())
                })
                .and_then(|decompression_key| {
                    self.get_using_cuda_key(
                        index,
                        decompression_key,
                        &cuda_key.streams,
                        &cuda_key.tag,
                    )
                }),
            #[cfg(feature = "hpu")]
            Some(InternalServerKey::Hpu(_)) => {
                panic!("HPU does not support compression");
            }
            None => Err(UninitializedServerKey.into()),
        })
    }

    #[cfg(feature = "gpu")]
    fn get_decompression_size_on_gpu(&self, index: usize) -> crate::Result<Option<u64>> {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                match &self.inner {
                    InnerCompressedCiphertextList::Cpu(ct_list) => cuda_key
                        .key
                        .decompression_key
                        .as_ref()
                        .ok_or_else(|| {
                            crate::Error::new("Compression key not set in server key".to_owned())
                        })
                        .map(|decompression_key| {
                            ct_list.get_decompression_size_on_gpu(index, decompression_key, streams)
                        }),
                    InnerCompressedCiphertextList::Cuda(cuda_ct_list) => cuda_key
                        .key
                        .decompression_key
                        .as_ref()
                        .ok_or_else(|| {
                            crate::Error::new("Compression key not set in server key".to_owned())
                        })
                        .map(|decompression_key| {
                            cuda_ct_list.get_decompression_size_on_gpu(
                                index,
                                decompression_key,
                                streams,
                            )
                        }),
                }
            } else {
                Ok(Some(0))
            }
        })
    }
}

impl CompressedCiphertextList {
    pub fn into_raw_parts(
        self,
    ) -> (
        crate::integer::ciphertext::CompressedCiphertextList,
        Tag,
        Vec<ReRandomizationMetadata>,
    ) {
        let Self {
            inner,
            tag,
            re_randomization_metadata,
        } = self;
        match inner {
            InnerCompressedCiphertextList::Cpu(inner) => (inner, tag, re_randomization_metadata),
            #[cfg(feature = "gpu")]
            InnerCompressedCiphertextList::Cuda(inner) => (
                with_cuda_internal_keys(|keys| {
                    let streams = &keys.streams;
                    inner.to_compressed_ciphertext_list(streams)
                }),
                tag,
                re_randomization_metadata,
            ),
        }
    }

    pub fn from_raw_parts(
        inner: crate::integer::ciphertext::CompressedCiphertextList,
        tag: Tag,
        re_randomization_metadata: Vec<ReRandomizationMetadata>,
    ) -> Self {
        Self {
            inner: InnerCompressedCiphertextList::Cpu(inner),
            tag,
            re_randomization_metadata,
        }
    }

    pub fn current_device(&self) -> crate::Device {
        self.inner.current_device()
    }

    pub fn move_to_current_device(&mut self) {
        if let Some(device) = device_of_internal_keys() {
            self.inner.move_to_device(device);
        }
    }

    fn get_re_randomization_metadata(
        &self,
        index: usize,
    ) -> crate::Result<ReRandomizationMetadata> {
        Ok(self
            .re_randomization_metadata
            .get(index)
            .ok_or_else(|| {
                crate::error!("Unable to retrieve metadata for ciphertext at index {index}.")
            })?
            .clone())
    }

    pub(crate) fn get_using_key<T>(
        &self,
        index: usize,
        decompression_key: &DecompressionKey,
        tag: &Tag,
    ) -> crate::Result<Option<T>>
    where
        T: HlExpandable + Tagged,
    {
        let mut ct = self.inner.on_cpu().get::<T>(index, decompression_key);
        if let Ok(Some(ct_ref)) = &mut ct {
            ct_ref.tag_mut().set_data(tag.data());

            ct_ref.set_re_randomization_metadata(self.get_re_randomization_metadata(index)?);
        }
        ct
    }

    #[cfg(feature = "gpu")]
    pub(crate) fn get_using_cuda_key<T>(
        &self,
        index: usize,
        decompression_key: &CudaDecompressionKey,
        streams: &CudaStreams,
        tag: &Tag,
    ) -> crate::Result<Option<T>>
    where
        T: HlExpandable + Tagged,
    {
        let mut ct = self
            .inner
            .on_gpu(streams)
            .get::<T>(index, decompression_key, streams);
        if let Ok(Some(ct_ref)) = &mut ct {
            ct_ref.tag_mut().set_data(tag.data());

            ct_ref.set_re_randomization_metadata(self.get_re_randomization_metadata(index)?);
        }
        ct
    }

    #[cfg(feature = "gpu")]
    pub fn gpu_indexes(&self) -> &[GpuIndex] {
        match &self.inner {
            InnerCompressedCiphertextList::Cpu(_) => &[],
            InnerCompressedCiphertextList::Cuda(cuda_ct) => cuda_ct.gpu_indexes(),
        }
    }
}

#[cfg(feature = "gpu")]
pub mod gpu {
    use crate::core_crypto::gpu::CudaStreams;
    use crate::high_level_api::integers::{FheIntId, FheUintId};
    use crate::integer::ciphertext::DataKind;
    use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
    use crate::integer::gpu::ciphertext::compressed_ciphertext_list::{
        CudaCompressible, CudaExpandable,
    };
    use crate::integer::gpu::ciphertext::CudaRadixCiphertext;
    use crate::{FheBool, FheInt, FheUint, ReRandomizationMetadata, Tag};

    impl<Id: FheUintId> CudaCompressible for FheUint<Id> {
        fn compress_into(
            self,
            messages: &mut Vec<CudaRadixCiphertext>,
            streams: &CudaStreams,
        ) -> Option<DataKind> {
            self.ciphertext
                .into_gpu(streams)
                .compress_into(messages, streams)
        }
    }

    impl<Id: FheIntId> CudaCompressible for FheInt<Id> {
        fn compress_into(
            self,
            messages: &mut Vec<CudaRadixCiphertext>,
            streams: &CudaStreams,
        ) -> Option<DataKind> {
            self.ciphertext
                .into_gpu(streams)
                .compress_into(messages, streams)
        }
    }

    impl CudaCompressible for FheBool {
        fn compress_into(
            self,
            messages: &mut Vec<CudaRadixCiphertext>,
            streams: &CudaStreams,
        ) -> Option<DataKind> {
            self.ciphertext
                .into_gpu(streams)
                .compress_into(messages, streams)
        }
    }

    fn cuda_num_bits_of_blocks(blocks: &CudaRadixCiphertext) -> u32 {
        blocks
            .info
            .blocks
            .iter()
            .map(|block| block.message_modulus.0.ilog2())
            .sum::<u32>()
    }

    impl<Id: FheUintId> CudaExpandable for FheUint<Id> {
        fn from_expanded_blocks(
            blocks: CudaRadixCiphertext,
            kind: DataKind,
        ) -> crate::Result<Self> {
            match kind {
                DataKind::Unsigned(_) => {
                    let stored_num_bits = cuda_num_bits_of_blocks(&blocks) as usize;
                    if stored_num_bits == Id::num_bits() {
                        // The expander will be responsible for setting the correct tag
                        Ok(Self::new(
                            crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext {
                                ciphertext: blocks,
                            },
                            Tag::default(),
                            ReRandomizationMetadata::default(),
                        ))
                    } else {
                        Err(crate::error!(
                            "Tried to expand a FheUint{} while a FheUint{} is stored in this slot",
                            Id::num_bits(),
                            stored_num_bits
                        ))
                    }
                }
                DataKind::Signed(_) => {
                    let stored_num_bits = cuda_num_bits_of_blocks(&blocks) as usize;
                    Err(crate::error!(
                        "Tried to expand a FheUint{} while a FheInt{} is stored in this slot",
                        Id::num_bits(),
                        stored_num_bits
                    ))
                }
                DataKind::Boolean => Err(crate::error!(
                    "Tried to expand a FheUint{} while a FheBool is stored in this slot",
                    Id::num_bits(),
                )),
                DataKind::String { .. } => Err(crate::error!(
                    "Tried to expand a FheUint{} while a FheString is stored in this slot",
                    Id::num_bits()
                )),
            }
        }
    }

    impl<Id: FheIntId> CudaExpandable for FheInt<Id> {
        fn from_expanded_blocks(
            blocks: CudaRadixCiphertext,
            kind: DataKind,
        ) -> crate::Result<Self> {
            match kind {
                DataKind::Unsigned(_) => {
                    let stored_num_bits = cuda_num_bits_of_blocks(&blocks) as usize;
                    Err(crate::error!(
                        "Tried to expand a FheInt{} while a FheUint{} is stored in this slot",
                        Id::num_bits(),
                        stored_num_bits
                    ))
                }
                DataKind::Signed(_) => {
                    let stored_num_bits = cuda_num_bits_of_blocks(&blocks) as usize;
                    if stored_num_bits == Id::num_bits() {
                        // The expander will be responsible for setting the correct tag
                        Ok(Self::new(
                            crate::integer::gpu::ciphertext::CudaSignedRadixCiphertext {
                                ciphertext: blocks,
                            },
                            Tag::default(),
                            ReRandomizationMetadata::default(),
                        ))
                    } else {
                        Err(crate::error!(
                            "Tried to expand a FheInt{} while a FheInt{} is stored in this slot",
                            Id::num_bits(),
                            stored_num_bits
                        ))
                    }
                }
                DataKind::Boolean => Err(crate::error!(
                    "Tried to expand a FheInt{} while a FheBool is stored in this slot",
                    Id::num_bits(),
                )),
                DataKind::String { .. } => Err(crate::error!(
                    "Tried to expand a FheInt{} while a FheString is stored in this slot",
                    Id::num_bits()
                )),
            }
        }
    }

    impl CudaExpandable for FheBool {
        fn from_expanded_blocks(
            blocks: CudaRadixCiphertext,
            kind: DataKind,
        ) -> crate::Result<Self> {
            match kind {
                DataKind::Unsigned(_) => {
                    let stored_num_bits = cuda_num_bits_of_blocks(&blocks) as usize;
                    Err(crate::error!(
                        "Tried to expand a FheBool while a FheUint{stored_num_bits} is stored in this slot",
                    ))
                }
                DataKind::Signed(_) => {
                    let stored_num_bits = cuda_num_bits_of_blocks(&blocks) as usize;
                    Err(crate::error!(
                        "Tried to expand a FheBool while a FheInt{stored_num_bits} is stored in this slot",
                    ))
                }
                DataKind::Boolean => {
                    let mut boolean_block = CudaBooleanBlock::from_cuda_radix_ciphertext(blocks);
                    // We know the value is a boolean one (via the data kind)
                    boolean_block.0.ciphertext.info.blocks[0].degree =
                        crate::shortint::ciphertext::Degree::new(1);

                    // The expander will be responsible for setting the correct tag
                    Ok(Self::new(
                        boolean_block,
                        Tag::default(),
                        ReRandomizationMetadata::default(),
                    ))
                }
                DataKind::String { .. } => Err(crate::error!(
                    "Tried to expand a FheBool while a FheString is stored in this slot"
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use crate::safe_serialization::{safe_deserialize, safe_serialize};
    #[cfg(not(feature = "gpu"))]
    use crate::shortint::parameters::test_params::TEST_PARAM_COMP_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_MB_GPU;
    #[cfg(not(feature = "gpu"))]
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128;
    #[cfg(feature = "gpu")]
    use crate::shortint::parameters::{
        COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    };
    use crate::shortint::parameters::{
        COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    };
    use crate::shortint::AtomicPatternParameters;
    #[cfg(feature = "gpu")]
    use crate::GpuIndex;
    use crate::{
        set_server_key, unset_server_key, ClientKey, CompressedCiphertextList,
        CompressedCiphertextListBuilder, FheBool, FheInt64, FheUint16, FheUint2, FheUint32,
    };

    #[test]
    fn test_compressed_ct_list_cpu_gpu() {
        for (params, comp_params) in [
            (
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ),
            #[cfg(not(feature = "gpu"))]
            (
                PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128.into(),
                COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ),
            // TODO: enable these params for gpu when supported
            #[cfg(not(feature = "gpu"))]
            (
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                TEST_PARAM_COMP_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_MB_GPU,
            ),
            #[cfg(feature = "gpu")]
            (
                PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ),
        ] {
            let config =
                crate::ConfigBuilder::with_custom_parameters::<AtomicPatternParameters>(params)
                    .enable_compression(comp_params)
                    .build();

            let ck = crate::ClientKey::generate(config);
            let sk = crate::CompressedServerKey::new(&ck);

            // Test with input data being on CPU
            {
                let ct1 = FheUint32::encrypt(17_u32, &ck);
                let ct2 = FheInt64::encrypt(-1i64, &ck);
                let ct3 = FheBool::encrypt(false, &ck);
                let ct4 = FheUint2::encrypt(3u8, &ck);

                let mut compressed_list_builder = CompressedCiphertextListBuilder::new();
                compressed_list_builder
                    .push(ct1)
                    .push(ct2)
                    .push(ct3)
                    .push(ct4);

                set_server_key(sk.decompress());
                let compressed_list = compressed_list_builder.build().unwrap();

                // Add a serialize-deserialize round trip as it will generally be
                // how compressed list are use as its meant for data exchange
                let mut serialized = vec![];
                safe_serialize(&compressed_list, &mut serialized, 1024 * 1024 * 16).unwrap();
                let compressed_list: CompressedCiphertextList =
                    safe_deserialize(serialized.as_slice(), 1024 * 1024 * 16).unwrap();

                check_is_correct(&compressed_list, &ck);

                #[cfg(feature = "gpu")]
                {
                    set_server_key(sk.decompress_to_gpu());
                    check_is_correct(&compressed_list, &ck);
                }

                // Now redo the tests, but with the server_key not being set when deserializing
                // meaning, the deserialization process could not use that as a hint on where to put
                // the data
                {
                    unset_server_key();
                    let compressed_list: CompressedCiphertextList =
                        safe_deserialize(serialized.as_slice(), 1024 * 1024 * 16).unwrap();
                    assert_eq!(compressed_list.current_device(), crate::Device::Cpu);
                    set_server_key(sk.decompress());
                    check_is_correct(&compressed_list, &ck);

                    #[cfg(feature = "gpu")]
                    {
                        unset_server_key();
                        let compressed_list: CompressedCiphertextList =
                            safe_deserialize(serialized.as_slice(), 1024 * 1024 * 16).unwrap();
                        assert_eq!(compressed_list.current_device(), crate::Device::Cpu);
                        set_server_key(sk.decompress_to_gpu());
                        check_is_correct(&compressed_list, &ck);
                    }
                }
            }

            // Test with input data being on GPU
            #[cfg(feature = "gpu")]
            {
                let mut ct1 = FheUint32::encrypt(17_u32, &ck);
                let mut ct2 = FheInt64::encrypt(-1i64, &ck);
                let mut ct3 = FheBool::encrypt(false, &ck);
                let mut ct4 = FheUint2::encrypt(3u8, &ck);

                ct1.move_to_device(crate::Device::CudaGpu);
                ct2.move_to_device(crate::Device::Cpu);
                ct3.move_to_device(crate::Device::CudaGpu);
                ct4.move_to_device(crate::Device::Cpu);

                let mut compressed_list_builder = CompressedCiphertextListBuilder::new();
                let compressed_list = compressed_list_builder
                    .push(ct1)
                    .push(ct2)
                    .push(ct3)
                    .push(ct4)
                    .build()
                    .unwrap();

                // Add a serialize-deserialize round trip as it will generally be
                // how compressed list are use as its meant for data exchange
                let mut serialized = vec![];
                safe_serialize(&compressed_list, &mut serialized, 1024 * 1024 * 16).unwrap();
                let compressed_list: CompressedCiphertextList =
                    safe_deserialize(serialized.as_slice(), 1024 * 1024 * 16).unwrap();

                set_server_key(sk.decompress());
                check_is_correct(&compressed_list, &ck);

                set_server_key(sk.decompress_to_gpu());
                check_is_correct(&compressed_list, &ck);

                // Now redo the tests, but with the server_key not being set when deserializing
                // meaning, the deserialization process could not use that as a hint on where to put
                // the data
                {
                    unset_server_key();
                    let compressed_list: CompressedCiphertextList =
                        safe_deserialize(serialized.as_slice(), 1024 * 1024 * 16).unwrap();
                    assert_eq!(compressed_list.current_device(), crate::Device::Cpu);
                    set_server_key(sk.decompress());
                    check_is_correct(&compressed_list, &ck);

                    unset_server_key();
                    let compressed_list: CompressedCiphertextList =
                        safe_deserialize(serialized.as_slice(), 1024 * 1024 * 16).unwrap();
                    assert_eq!(compressed_list.current_device(), crate::Device::Cpu);
                    set_server_key(sk.decompress_to_gpu());
                    check_is_correct(&compressed_list, &ck);
                }
            }

            fn check_is_correct(compressed_list: &CompressedCiphertextList, ck: &ClientKey) {
                {
                    let a: FheUint32 = compressed_list.get(0).unwrap().unwrap();
                    let b: FheInt64 = compressed_list.get(1).unwrap().unwrap();
                    let c: FheBool = compressed_list.get(2).unwrap().unwrap();
                    let d: FheUint2 = compressed_list.get(3).unwrap().unwrap();

                    let a: u32 = a.decrypt(ck);
                    assert_eq!(a, 17);
                    let b: i64 = b.decrypt(ck);
                    assert_eq!(b, -1);
                    let c = c.decrypt(ck);
                    assert!(!c);
                    let d: u8 = d.decrypt(ck);
                    assert_eq!(d, 3);

                    assert!(compressed_list.get::<FheBool>(4).unwrap().is_none());
                }

                {
                    // Incorrect type
                    assert!(compressed_list.get::<FheInt64>(0).is_err());

                    // Correct type but wrong number of bits
                    assert!(compressed_list.get::<FheUint16>(0).is_err());
                }
            }
        }
    }

    #[cfg(feature = "strings")]
    #[test]
    fn test_compressed_strings_cpu() {
        let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let config = crate::ConfigBuilder::with_custom_parameters(params)
            .enable_compression(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .build();

        let ck = crate::ClientKey::generate(config);
        let sk = crate::CompressedServerKey::new(&ck);

        // Test with input data being on CPU
        {
            let ct1 = crate::FheAsciiString::encrypt("Hello, World", &ck);
            let ct2 =
                crate::FheAsciiString::try_encrypt_with_fixed_sized("Hello", 50, &ck).unwrap();

            let mut compressed_list_builder = CompressedCiphertextListBuilder::new();
            compressed_list_builder.push(ct1).push(ct2);

            set_server_key(sk.decompress());
            let compressed_list = compressed_list_builder.build().unwrap();

            // Add a serialize-deserialize round trip as it will generally be
            // how compressed list are use as its meant for data exchange
            let mut serialized = vec![];
            safe_serialize(&compressed_list, &mut serialized, 1024 * 1024 * 16).unwrap();
            let compressed_list: CompressedCiphertextList =
                safe_deserialize(serialized.as_slice(), 1024 * 1024 * 16).unwrap();

            check_is_correct(&compressed_list, &ck);
        }

        fn check_is_correct(compressed_list: &CompressedCiphertextList, ck: &ClientKey) {
            {
                let a: crate::FheAsciiString = compressed_list.get(0).unwrap().unwrap();
                let b: crate::FheAsciiString = compressed_list.get(1).unwrap().unwrap();

                assert_eq!(
                    compressed_list.get_kind_of(0),
                    Some(crate::FheTypes::AsciiString)
                );

                let a = a.decrypt(ck);
                assert_eq!(&a, "Hello, World");
                let b = b.decrypt(ck);
                assert_eq!(&b, "Hello");
            }
        }
    }

    #[test]
    #[cfg(feature = "gpu")]
    fn test_compression_decompression_size_on_gpu() {
        for (params, comp_params) in [
            (
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ),
            (
                PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ),
        ] {
            let config =
                crate::ConfigBuilder::with_custom_parameters::<AtomicPatternParameters>(params)
                    .enable_compression(comp_params)
                    .build();

            let ck = crate::ClientKey::generate(config);
            let sk = crate::CompressedServerKey::new(&ck);

            set_server_key(sk.decompress_to_gpu());

            let mut ct1 = FheUint32::encrypt(17_u32, &ck);
            let mut ct2 = FheBool::encrypt(false, &ck);

            ct1.move_to_device(crate::Device::CudaGpu);
            ct2.move_to_device(crate::Device::CudaGpu);

            let mut compressed_list_builder = CompressedCiphertextListBuilder::new();
            let compressed_list_init = compressed_list_builder.push(ct1).push(ct2);
            let compression_size_on_gpu = compressed_list_init.get_size_on_gpu().unwrap();
            const N_ATTEMPTS: usize = 10usize;
            for i in 0..N_ATTEMPTS {
                if check_valid_cuda_malloc(compression_size_on_gpu, GpuIndex::new(0)) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
                assert!(
                    i != N_ATTEMPTS - 1,
                    "test_compression_decompression_size_on_gpu:
                         could not allocate enough memory for compression on GPU"
                );
            }

            let mut compressed_list = compressed_list_init.build().unwrap();
            let decompress_ct1_size_on_gpu = compressed_list
                .get_decompression_size_on_gpu(0)
                .unwrap()
                .unwrap();
            check_valid_cuda_malloc_assert_oom(decompress_ct1_size_on_gpu, GpuIndex::new(0));
            let decompress_ct2_size_on_gpu = compressed_list
                .get_decompression_size_on_gpu(1)
                .unwrap()
                .unwrap();
            check_valid_cuda_malloc_assert_oom(decompress_ct2_size_on_gpu, GpuIndex::new(0));
            compressed_list.move_to_current_device();
            let decompress_ct1_size_on_gpu_1 = compressed_list
                .get_decompression_size_on_gpu(0)
                .unwrap()
                .unwrap();
            let decompress_ct2_size_on_gpu_1 = compressed_list
                .get_decompression_size_on_gpu(1)
                .unwrap()
                .unwrap();
            assert_eq!(decompress_ct1_size_on_gpu, decompress_ct1_size_on_gpu_1);
            assert_eq!(decompress_ct2_size_on_gpu, decompress_ct2_size_on_gpu_1);
        }
    }
}
