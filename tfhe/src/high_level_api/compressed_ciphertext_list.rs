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
use crate::high_level_api::global_state::device_of_internal_keys;
#[cfg(feature = "gpu")]
use crate::high_level_api::global_state::with_thread_local_cuda_streams;
use crate::high_level_api::integers::{FheIntId, FheUintId};
use crate::integer::ciphertext::{DataKind, Expandable};
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::compressed_ciphertext_list::{
    CudaCompressedCiphertextList, CudaExpandable,
};
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::CudaRadixCiphertext;
use crate::named::Named;
use crate::prelude::{CiphertextList, Tagged};
use crate::shortint::Ciphertext;
use crate::{FheBool, FheInt, FheUint, Tag};

impl<Id: FheUintId> HlCompressible for FheUint<Id> {
    fn compress_into(self, messages: &mut Vec<(ToBeCompressed, DataKind)>) {
        match self.ciphertext {
            crate::high_level_api::integers::unsigned::RadixCiphertext::Cpu(cpu_radix) => {
                let blocks = cpu_radix.blocks;
                let kind = DataKind::Unsigned(blocks.len());
                messages.push((ToBeCompressed::Cpu(blocks), kind));
            }
            #[cfg(feature = "gpu")]
            crate::high_level_api::integers::unsigned::RadixCiphertext::Cuda(gpu_radix) => {
                let blocks = gpu_radix.ciphertext;
                let kind = DataKind::Unsigned(blocks.info.blocks.len());
                messages.push((ToBeCompressed::Cuda(blocks), kind));
            }
            #[cfg(feature = "hpu")]
            crate::high_level_api::integers::unsigned::RadixCiphertext::Hpu(_) => {
                panic!("HPU does not support compression");
            }
        }
    }
}
impl<Id: FheIntId> HlCompressible for FheInt<Id> {
    fn compress_into(self, messages: &mut Vec<(ToBeCompressed, DataKind)>) {
        match self.ciphertext {
            crate::high_level_api::integers::signed::SignedRadixCiphertext::Cpu(cpu_radix) => {
                let blocks = cpu_radix.blocks;
                let kind = DataKind::Signed(blocks.len());
                messages.push((ToBeCompressed::Cpu(blocks), kind));
            }
            #[cfg(feature = "gpu")]
            crate::high_level_api::integers::signed::SignedRadixCiphertext::Cuda(gpu_radix) => {
                let blocks = gpu_radix.ciphertext;
                let kind = DataKind::Signed(blocks.info.blocks.len());
                messages.push((ToBeCompressed::Cuda(blocks), kind));
            }
        }
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
        }
    }
}

impl<Id: FheUintId> HlExpandable for FheUint<Id> {}
impl<Id: FheIntId> HlExpandable for FheInt<Id> {}
impl HlExpandable for FheBool {}

#[cfg(not(feature = "gpu"))]
pub trait HlExpandable: Expandable {}
#[cfg(feature = "gpu")]
pub trait HlExpandable: Expandable + CudaExpandable {}

pub trait HlCompressible {
    fn compress_into(self, messages: &mut Vec<(ToBeCompressed, DataKind)>);
}

pub enum ToBeCompressed {
    Cpu(Vec<Ciphertext>),
    #[cfg(feature = "gpu")]
    Cuda(CudaRadixCiphertext),
}

pub struct CompressedCiphertextListBuilder {
    inner: Vec<(ToBeCompressed, DataKind)>,
}

impl CompressedCiphertextListBuilder {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self { inner: vec![] }
    }

    pub fn push<T>(&mut self, value: T) -> &mut Self
    where
        T: HlCompressible,
    {
        value.compress_into(&mut self.inner);
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
                            with_thread_local_cuda_streams(|streams| {
                                flat_cpu_blocks.append(&mut cuda_radix.to_cpu_blocks(streams));
                            });
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
                        }
                    })
            }
            #[cfg(feature = "gpu")]
            Some(InternalServerKey::Cuda(cuda_key)) => {
                let mut cuda_radixes = vec![];
                for (element, _) in &self.inner {
                    match element {
                        ToBeCompressed::Cpu(cpu_blocks) => {
                            with_thread_local_cuda_streams(|streams| {
                                cuda_radixes.push(CudaRadixCiphertext::from_cpu_blocks(
                                    cpu_blocks, streams,
                                ));
                            })
                        }
                        #[cfg(feature = "gpu")]
                        ToBeCompressed::Cuda(cuda_radix) => {
                            with_thread_local_cuda_streams(|streams| {
                                cuda_radixes.push(cuda_radix.duplicate(streams));
                            });
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
                        let packed_list = with_thread_local_cuda_streams(|streams| {
                            compression_key
                                .compress_ciphertexts_into_list(cuda_radixes.as_slice(), streams)
                        });
                        let info = self.inner.iter().map(|(_, kind)| *kind).collect();

                        let compressed_list = CudaCompressedCiphertextList { packed_list, info };

                        CompressedCiphertextList {
                            inner: InnerCompressedCiphertextList::Cuda(compressed_list),
                            tag: cuda_key.tag.clone(),
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

    fn move_to_device(&mut self, device: crate::Device) {
        let new_value = match (&self, device) {
            (Self::Cpu(_), crate::Device::Cpu) => None,
            #[cfg(feature = "gpu")]
            (Self::Cuda(cuda_ct), crate::Device::CudaGpu) => {
                with_thread_local_cuda_streams(|streams| {
                    if cuda_ct.gpu_indexes() == streams.gpu_indexes() {
                        None
                    } else {
                        Some(Self::Cuda(cuda_ct.duplicate(streams)))
                    }
                })
            }
            #[cfg(feature = "gpu")]
            (Self::Cuda(cuda_ct), crate::Device::Cpu) => {
                let cpu_ct = with_thread_local_cuda_streams_for_gpu_indexes(
                    cuda_ct.gpu_indexes(),
                    |streams| cuda_ct.to_compressed_ciphertext_list(streams),
                );
                Some(Self::Cpu(cpu_ct))
            }
            #[cfg(feature = "gpu")]
            (Self::Cpu(cpu_ct), crate::Device::CudaGpu) => {
                let cuda_ct = with_thread_local_cuda_streams(|streams| {
                    cpu_ct.to_cuda_compressed_ciphertext_list(streams)
                });
                Some(Self::Cuda(cuda_ct))
            }
            #[cfg(feature = "hpu")]
            (Self::Cpu(_), crate::Device::Hpu) => {
                panic!("HPU does not support compression");
            }
        };

        if let Some(v) = new_value {
            *self = v;
        }
    }

    fn on_cpu(&self) -> MaybeCloned<crate::integer::ciphertext::CompressedCiphertextList> {
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
}

impl Versionize for InnerCompressedCiphertextList {
    type Versioned<'vers> =
        <crate::integer::ciphertext::CompressedCiphertextList as VersionizeOwned>::VersionedOwned;

    fn versionize(&self) -> Self::Versioned<'_> {
        match self {
            Self::Cpu(inner) => inner.clone().versionize_owned(),
            #[cfg(feature = "gpu")]
            Self::Cuda(inner) => {
                let cpu_data = with_thread_local_cuda_streams(|streams| {
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
                let cpu_data = with_thread_local_cuda_streams(|streams| {
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
                    crate::FheTypes::from_data_kind(data_kind, inner.packed_list.message_modulus)
                })
            }
            #[cfg(feature = "gpu")]
            InnerCompressedCiphertextList::Cuda(inner) => {
                inner.get_kind_of(index).and_then(|data_kind| {
                    crate::FheTypes::from_data_kind(data_kind, inner.packed_list.message_modulus)
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
                    let mut ct = self.inner.on_cpu().get::<T>(index, decompression_key);
                    if let Ok(Some(ct_ref)) = &mut ct {
                        ct_ref.tag_mut().set_data(cpu_key.tag.data())
                    }
                    ct
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
                    let mut ct = with_thread_local_cuda_streams(|streams| {
                        self.inner
                            .on_gpu(streams)
                            .get::<T>(index, decompression_key, streams)
                    });
                    if let Ok(Some(ct_ref)) = &mut ct {
                        ct_ref.tag_mut().set_data(cuda_key.tag.data())
                    }
                    ct
                }),
            #[cfg(feature = "hpu")]
            Some(InternalServerKey::Hpu(_)) => {
                panic!("HPU does not support compression");
            }
            None => Err(UninitializedServerKey.into()),
        })
    }
}

impl CompressedCiphertextList {
    pub fn into_raw_parts(self) -> (crate::integer::ciphertext::CompressedCiphertextList, Tag) {
        let Self { inner, tag } = self;
        match inner {
            InnerCompressedCiphertextList::Cpu(inner) => (inner, tag),
            #[cfg(feature = "gpu")]
            InnerCompressedCiphertextList::Cuda(inner) => (
                with_thread_local_cuda_streams(|streams| {
                    inner.to_compressed_ciphertext_list(streams)
                }),
                tag,
            ),
        }
    }

    pub fn from_raw_parts(
        inner: crate::integer::ciphertext::CompressedCiphertextList,
        tag: Tag,
    ) -> Self {
        Self {
            inner: InnerCompressedCiphertextList::Cpu(inner),
            tag,
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
    use crate::{FheBool, FheInt, FheUint, Tag};

    impl<Id: FheUintId> CudaCompressible for FheUint<Id> {
        fn compress_into(
            self,
            messages: &mut Vec<CudaRadixCiphertext>,
            streams: &CudaStreams,
        ) -> DataKind {
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
        ) -> DataKind {
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
        ) -> DataKind {
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
                    Ok(Self::new(boolean_block, Tag::default()))
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
    use crate::shortint::parameters::{
        COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    };
    use crate::shortint::PBSParameters;
    use crate::{
        set_server_key, unset_server_key, ClientKey, CompressedCiphertextList,
        CompressedCiphertextListBuilder, FheBool, FheInt64, FheUint16, FheUint2, FheUint32,
    };

    #[test]
    fn test_compressed_ct_list_cpu_gpu() {
        for (params, comp_params) in [
            if cfg!(not(feature = "gpu")) {
                (
                    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                    COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                )
            } else {
                (
                    crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
                        .into(),
                    crate::shortint::parameters::COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                )
            },
            (
                PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ),
        ] {
            let config = crate::ConfigBuilder::with_custom_parameters::<PBSParameters>(params)
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
}
