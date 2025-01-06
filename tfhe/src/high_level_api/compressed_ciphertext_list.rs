use tfhe_versionable::{Unversionize, UnversionizeError, Version, Versionize, VersionizeOwned};

use super::details::MaybeCloned;
#[cfg(feature = "gpu")]
use super::global_state::with_thread_local_cuda_streams_for_gpu_indexes;
use super::global_state::device_of_internal_keys;
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
use crate::high_level_api::global_state::with_thread_local_cuda_streams;
use crate::high_level_api::integers::{FheIntId, FheUintId};
use crate::high_level_api::SerializedKind;
use crate::integer::ciphertext::Expandable;
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::CudaRadixCiphertext;
#[cfg(feature = "gpu")]
use crate::integer::gpu::list_compression::server_keys::CudaPackedGlweCiphertext;
use crate::integer::{BooleanBlock, RadixCiphertext, SignedRadixCiphertext};
use crate::named::Named;
use crate::prelude::{CiphertextList, Tagged};
use crate::shortint::Ciphertext;
use crate::{FheBool, FheInt, FheUint, Tag};

impl<Id: FheUintId> HlCompressible for FheUint<Id> {
    fn compress_into(self, messages: &mut Vec<(ToBeCompressed, SerializedKind)>) {
        let kind = SerializedKind::Uint {
            num_bits: Id::num_bits() as u32,
        };
        match self.ciphertext {
            crate::high_level_api::integers::unsigned::RadixCiphertext::Cpu(cpu_radix) => {
                let blocks = cpu_radix.blocks;
                messages.push((ToBeCompressed::Cpu(blocks), kind));
            }
            #[cfg(feature = "gpu")]
            crate::high_level_api::integers::unsigned::RadixCiphertext::Cuda(gpu_radix) => {
                let blocks = gpu_radix.ciphertext;
                messages.push((ToBeCompressed::Cuda(blocks), kind));
            }
        }
    }
}
impl<Id: FheIntId> HlCompressible for FheInt<Id> {
    fn compress_into(self, messages: &mut Vec<(ToBeCompressed, SerializedKind)>) {
        let kind = SerializedKind::Int {
            num_bits: Id::num_bits() as u32,
        };
        match self.ciphertext {
            crate::high_level_api::integers::signed::RadixCiphertext::Cpu(cpu_radix) => {
                let blocks = cpu_radix.blocks;
                messages.push((ToBeCompressed::Cpu(blocks), kind));
            }
            #[cfg(feature = "gpu")]
            crate::high_level_api::integers::signed::RadixCiphertext::Cuda(gpu_radix) => {
                let blocks = gpu_radix.ciphertext;
                messages.push((ToBeCompressed::Cuda(blocks), kind));
            }
        }
    }
}
impl HlCompressible for FheBool {
    fn compress_into(self, messages: &mut Vec<(ToBeCompressed, SerializedKind)>) {
        let kind = SerializedKind::Bool;
        match self.ciphertext {
            InnerBoolean::Cpu(cpu_bool) => {
                messages.push((ToBeCompressed::Cpu(vec![cpu_bool.0]), kind));
            }
            #[cfg(feature = "gpu")]
            InnerBoolean::Cuda(cuda_bool) => {
                messages.push((ToBeCompressed::Cuda(cuda_bool.0.ciphertext), kind));
            }
        }
    }
}

impl<Id: FheUintId> HlExpandable for FheUint<Id> {
    fn from_cpu_blocks(blocks: Vec<Ciphertext>, kind: SerializedKind) -> crate::Result<Self> {
        match kind {
            SerializedKind::Bool => Err(crate::Error::new(format!(
                "Tried to expand a FheUint{} while FheBool is stored",
                Id::num_bits()
            ))),
            SerializedKind::Uint { num_bits } => {
                if num_bits as usize == Id::num_bits() {
                    Ok(Self::new(RadixCiphertext::from(blocks), Tag::default()))
                } else {
                    Err(crate::Error::new(format!(
                        "Tried to expand a FheUint{} while FheUint{num_bits} is stored",
                        Id::num_bits()
                    )))
                }
            }
            SerializedKind::Int { num_bits } => Err(crate::Error::new(format!(
                "Tried to expand a FheUint{} while FheInt{num_bits} is stored",
                Id::num_bits()
            ))),
        }
    }

    #[cfg(feature = "gpu")]
    fn from_gpu_blocks(blocks: CudaRadixCiphertext, kind: SerializedKind) -> crate::Result<Self> {
        match kind {
            SerializedKind::Bool => Err(crate::Error::new(format!(
                "Tried to expand a FheUint{} while a FheUintBool is stored in this slot",
                Id::num_bits(),
            ))),
            SerializedKind::Uint { num_bits } => {
                if num_bits == Id::num_bits() as u32 {
                    // The expander will be responsible for setting the correct tag
                    Ok(Self::new(
                        crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext {
                            ciphertext: blocks,
                        },
                        Tag::default(),
                    ))
                } else {
                    Err(crate::Error::new(format!(
                        "Tried to expand a FheUint{} while a FheUint{num_bits} is stored in this slot",
                        Id::num_bits(),
                    )))
                }
            }
            SerializedKind::Int { num_bits } => Err(crate::Error::new(format!(
                "Tried to expand a FheUint{} while a FheInt{num_bits} is stored in this slot",
                Id::num_bits(),
            ))),
        }
    }
}
impl<Id: FheIntId> HlExpandable for FheInt<Id> {
    fn from_cpu_blocks(blocks: Vec<Ciphertext>, kind: SerializedKind) -> crate::Result<Self> {
        match kind {
            SerializedKind::Bool => Err(crate::Error::new(format!(
                "Tried to expand a FheUint{} while FheBool is stored",
                Id::num_bits()
            ))),
            SerializedKind::Uint { num_bits } => Err(crate::Error::new(format!(
                "Tried to expand a FheInt{} while FheUint{num_bits} is stored",
                Id::num_bits()
            ))),
            SerializedKind::Int { num_bits } => {
                if num_bits as usize == Id::num_bits() {
                    Ok(Self::new(
                        SignedRadixCiphertext::from(blocks),
                        Tag::default(),
                    ))
                } else {
                    Err(crate::Error::new(format!(
                        "Tried to expand a FheInt{} while FheInt{num_bits} is stored",
                        Id::num_bits()
                    )))
                }
            }
        }
    }

    #[cfg(feature = "gpu")]
    fn from_gpu_blocks(blocks: CudaRadixCiphertext, kind: SerializedKind) -> crate::Result<Self> {
        match kind {
            SerializedKind::Bool => Err(crate::Error::new(format!(
                "Tried to expand a FheInt{} while a FheUintBool is stored in this slot",
                Id::num_bits(),
            ))),
            SerializedKind::Uint { num_bits } => Err(crate::Error::new(format!(
                "Tried to expand a FheInt{} while a FheUint{num_bits} is stored in this slot",
                Id::num_bits(),
            ))),
            SerializedKind::Int { num_bits } => {
                if num_bits == Id::num_bits() as u32 {
                    // The expander will be responsible for setting the correct tag
                    Ok(Self::new(
                        crate::integer::gpu::ciphertext::CudaSignedRadixCiphertext {
                            ciphertext: blocks,
                        },
                        Tag::default(),
                    ))
                } else {
                    Err(crate::Error::new(format!(
                        "Tried to expand a FheInt{} while a FheInt{num_bits} is stored in this slot",
                        Id::num_bits(),
                    )))
                }
            }
        }
    }
}

impl HlExpandable for FheBool {
    fn from_cpu_blocks(mut blocks: Vec<Ciphertext>, kind: SerializedKind) -> crate::Result<Self> {
        match kind {
            SerializedKind::Bool => Ok(blocks
                .pop()
                .map(BooleanBlock::new_unchecked)
                .map(|b| Self::new(b, Tag::default()))
                .unwrap()),
            SerializedKind::Uint { num_bits } => Err(crate::Error::new(format!(
                "Tried to expand a FheBool while a FheUint{num_bits} is stored"
            ))),
            SerializedKind::Int { num_bits } => Err(crate::Error::new(format!(
                "Tried to expand a FheBool while a FheUint{num_bits} is stored"
            ))),
        }
    }

    #[cfg(feature = "gpu")]
    fn from_gpu_blocks(
        mut radix: CudaRadixCiphertext,
        kind: SerializedKind,
    ) -> crate::Result<Self> {
        use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;

        match kind {
            SerializedKind::Bool => {
                // We know the value is a boolean one (via the data kind)
                radix.info.blocks[0].degree = crate::shortint::ciphertext::Degree::new(1);

                let boolean_block = CudaBooleanBlock::from_cuda_radix_ciphertext(radix);

                // The expander will be responsible for setting the correct tag
                Ok(Self::new(boolean_block, Tag::default()))
            }
            SerializedKind::Uint { num_bits } => Err(crate::Error::new(format!(
                "Tried to expand a FheBool while a FheUint{num_bits} is stored in this slot",
            ))),
            SerializedKind::Int { num_bits } => Err(crate::Error::new(format!(
                "Tried to expand a FheBool while a FheInt{num_bits} is stored in this slot",
            ))),
        }
    }
}

pub trait HlExpandable: Expandable {
    fn from_cpu_blocks(blocks: Vec<Ciphertext>, kind: SerializedKind) -> crate::Result<Self>;

    #[cfg(feature = "gpu")]
    fn from_gpu_blocks(blocks: CudaRadixCiphertext, kind: SerializedKind) -> crate::Result<Self>;
}

pub trait HlCompressible {
    fn compress_into(self, messages: &mut Vec<(ToBeCompressed, SerializedKind)>);
}

pub enum ToBeCompressed {
    Cpu(Vec<Ciphertext>),
    #[cfg(feature = "gpu")]
    Cuda(CudaRadixCiphertext),
}

pub struct CompressedCiphertextListBuilder {
    inner: Vec<(ToBeCompressed, SerializedKind)>,
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
                            inner: InnerCompressedCiphertextList::Cpu(compressed_list),
                            info,
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

                        CompressedCiphertextList {
                            inner: InnerCompressedCiphertextList::Cuda(packed_list),
                            info,
                            tag: cuda_key.tag.clone(),
                        }
                    })
            }
            None => Err(UninitializedServerKey.into()),
        })
    }
}

#[derive(Clone)]
pub(crate) enum InnerCompressedCiphertextList {
    Cpu(crate::shortint::ciphertext::CompressedCiphertextList),
    #[cfg(feature = "gpu")]
    Cuda(CudaPackedGlweCiphertext),
}

impl serde::Serialize for InnerCompressedCiphertextList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        match self {
            Self::Cpu(inner) => inner.serialize(serializer),
            #[cfg(feature = "gpu")]
            Self::Cuda(inner) => {
                let cpu_list = with_thread_local_cuda_streams(|streams| {
                    inner.to_compressed_ciphertext_list(streams)
                });

                cpu_list.serialize(serializer)
            }
        }
    }
}

impl<'de> serde::Deserialize<'de> for InnerCompressedCiphertextList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        #[allow(unused_mut, reason = "Mutability is tied to a feature")]
        let mut data =
            crate::shortint::ciphertext::CompressedCiphertextList::deserialize(deserializer)
                .map(Self::Cpu)?;

        match device_of_internal_keys() {
            Some(crate::Device::Cpu) | None => Ok(data),
            #[cfg(feature = "gpu")]
            Some(device) => {
                data.move_to_device(device)
                    .map_err(<D::Error as serde::de::Error>::custom)?;
                Ok(data)
            }
        }
    }
}

#[derive(serde::Serialize)]
pub struct InnerCompressedCiphertextListVersion<'vers>(
    <InnerCompressedCiphertextList as Versionize>::Versioned<'vers>,
);

impl<'vers> From<&'vers InnerCompressedCiphertextList>
    for InnerCompressedCiphertextListVersion<'vers>
{
    fn from(value: &'vers InnerCompressedCiphertextList) -> Self {
        Self(value.versionize())
    }
}

#[derive(::serde::Serialize, ::serde::Deserialize)]
pub struct InnerCompressedCiphertextListOwned(
    <InnerCompressedCiphertextList as VersionizeOwned>::VersionedOwned,
);

impl From<InnerCompressedCiphertextList> for InnerCompressedCiphertextListOwned {
    fn from(value: InnerCompressedCiphertextList) -> Self {
        Self(value.versionize_owned())
    }
}

impl TryFrom<InnerCompressedCiphertextListOwned> for InnerCompressedCiphertextList {
    type Error = UnversionizeError;

    fn try_from(value: InnerCompressedCiphertextListOwned) -> Result<Self, Self::Error> {
        Self::unversionize(value.0)
    }
}

impl Version for InnerCompressedCiphertextList {
    type Ref<'vers>
        = InnerCompressedCiphertextListVersion<'vers>
    where
        Self: 'vers;

    type Owned = InnerCompressedCiphertextListOwned;
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
        match (&self, device) {
            (Self::Cpu(_), super::Device::Cpu) => {},
            #[cfg(feature = "gpu")]
            (Self::Cpu(cpu), super::Device::CudaGpu) => {
                let gpu = with_thread_local_cuda_streams(|streams| {
                    cpu.to_cuda_packed_glwe_ciphertext(streams)
                });
                *self = Self::Cuda(gpu);
            }
            #[cfg(feature = "gpu")]
            (Self::Cuda(gpu), super::Device::Cpu) => {
                let cpu = with_thread_local_cuda_streams(|streams| {
                    gpu.to_compressed_ciphertext_list(streams)
                });

                *self = Self::Cpu(cpu);
            }
            #[cfg(feature = "gpu")]
            // handle when not on same gpuindex
            (Self::Cuda(_), super::Device::CudaGpu) => {},
        }
    }

    // fn move_to_device(&mut self, device: crate::Device) {
    //     let new_value = match (&self, device) {
    //         (Self::Cpu(_), crate::Device::Cpu) => None,
    //         #[cfg(feature = "gpu")]
    //         (Self::Cuda(cuda_ct), crate::Device::CudaGpu) => {
    //             with_thread_local_cuda_streams(|streams| {
    //                 if cuda_ct.gpu_indexes() == streams.gpu_indexes() {
    //                     None
    //                 } else {
    //                     Some(Self::Cuda(cuda_ct.duplicate(streams)))
    //                 }
    //             })
    //         }
    //         #[cfg(feature = "gpu")]
    //         (Self::Cuda(cuda_ct), crate::Device::Cpu) => {
    //             let cpu_ct = with_thread_local_cuda_streams_for_gpu_indexes(
    //                 cuda_ct.gpu_indexes(),
    //                 |streams| cuda_ct.to_compressed_ciphertext_list(streams),
    //             );
    //             Some(Self::Cpu(cpu_ct))
    //         }
    //         #[cfg(feature = "gpu")]
    //         (Self::Cpu(cpu_ct), crate::Device::CudaGpu) => {
    //             let cuda_ct = with_thread_local_cuda_streams(|streams| {
    //                 cpu_ct.to_cuda_compressed_ciphertext_list(streams)
    //             });
    //             Some(Self::Cuda(cuda_ct))
    //         }
    //     };

    //     if let Some(v) = new_value {
    //         *self = v;
    //     }
    // }

    fn on_cpu(&self) -> MaybeCloned<crate::shortint::ciphertext::CompressedCiphertextList> {
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
        <crate::shortint::ciphertext::CompressedCiphertextList as VersionizeOwned>::VersionedOwned;

    fn versionize(&self) -> Self::Versioned<'_> {
        match self {
            Self::Cpu(inner) => inner.clone().versionize_owned(),
            #[cfg(feature = "gpu")]
            Self::Cuda(inner) => {
                let cpu_list = with_thread_local_cuda_streams(|streams| {
                    inner.to_compressed_ciphertext_list(streams)
                });

                cpu_list.versionize_owned()
            }
        }
    }
}

impl VersionizeOwned for InnerCompressedCiphertextList {
    type VersionedOwned =
        <crate::shortint::ciphertext::CompressedCiphertextList as VersionizeOwned>::VersionedOwned;

    fn versionize_owned(self) -> Self::VersionedOwned {
        match self {
            Self::Cpu(inner) => inner.versionize_owned(),
            #[cfg(feature = "gpu")]
            Self::Cuda(inner) => {
                let cpu_list = with_thread_local_cuda_streams(|streams| {
                    inner.to_compressed_ciphertext_list(streams)
                });

                cpu_list.versionize_owned()
            }
        }
    }
}

impl Unversionize for InnerCompressedCiphertextList {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        Ok(Self::Cpu(
            crate::shortint::ciphertext::CompressedCiphertextList::unversionize(versioned)?,
        ))
    }
}

#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(CompressedCiphertextListVersions)]
pub struct CompressedCiphertextList {
    pub(in crate::high_level_api) inner: InnerCompressedCiphertextList,
    pub(in crate::high_level_api) info: Vec<SerializedKind>,
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
        self.info.len()
    }

    fn is_empty(&self) -> bool {
        self.info.is_empty()
    }

    fn get_kind_of(&self, index: usize) -> Option<crate::FheTypes> {
        self.info
            .get(index)
            .and_then(|&kind| crate::FheTypes::try_from(kind).ok())
    }

    fn get<T>(&self, index: usize) -> crate::Result<Option<T>>
    where
        T: HlExpandable + Tagged,
    {
        if index >= self.info.len() {
            return Ok(None);
        }

        let Some(preceding_infos) = self.info.get(..index) else {
            return Ok(None);
        };
        let Some(current_info) = self.info.get(index).copied() else {
            return Ok(None);
        };

        let message_modulus = match &self.inner {
            InnerCompressedCiphertextList::Cpu(cpu) => cpu.message_modulus,
            #[cfg(feature = "gpu")]
            InnerCompressedCiphertextList::Cuda(gpu) => gpu.message_modulus,
        };
        let start_block_index: usize = preceding_infos
            .iter()
            .copied()
            .map(|kind| kind.num_blocks(message_modulus) as usize)
            .sum();

        let end_block_index = start_block_index + current_info.num_blocks(message_modulus) as usize;


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
                .ok_or_else(|| crate::Error::new("Compression key not set in server key".to_owned()))
                .and_then(|decompression_key| {
                    let mut ct = decompression_key
                        .key
                        .unpack_range(&self.inner.on_cpu(), start_block_index..end_block_index)
                        .and_then(|blocks| T::from_cpu_blocks(blocks, current_info));
                    if let Ok(ct_ref) = &mut ct {
                        ct_ref.tag_mut().set_data(cpu_key.tag.data())
                    }
                    Some(ct).transpose()
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
                        let radix: CudaRadixCiphertext = decompression_key.raw_unpack(
                            inner,
                            start_block_index..end_block_index,
                            streams,
                        );
                        Some(T::from_gpu_blocks(radix, current_info)).transpose()
                    });
                    if let Ok(Some(ct_ref)) = &mut ct {
                        ct_ref.tag_mut().set_data(cuda_key.tag.data())
                    }
                    ct
                }),
            None => Err(UninitializedServerKey.into()),
        })
    }
}

impl CompressedCiphertextList {
    pub fn move_to_device(&mut self, device: crate::Device) {
        self.inner.move_to_device(device)
    }

    pub fn into_raw_parts(
        self,
    ) -> (
        crate::shortint::ciphertext::CompressedCiphertextList,
        Vec<SerializedKind>,
        Tag,
    ) {
        let Self { inner, info, tag } = self;
        match inner {
            InnerCompressedCiphertextList::Cpu(inner) => (inner, info, tag),
            #[cfg(feature = "gpu")]
            InnerCompressedCiphertextList::Cuda(inner) => (
                with_thread_local_cuda_streams(|streams| {
                    inner.to_compressed_ciphertext_list(streams)
                }),
                info,
                tag,
            ),
        }
    }

    pub fn from_raw_parts(
        inner: crate::shortint::ciphertext::CompressedCiphertextList,
        info: Vec<SerializedKind>,
        tag: Tag,
    ) -> Self {
        Self {
            inner: InnerCompressedCiphertextList::Cpu(inner),
            info,
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
    use crate::integer::gpu::ciphertext::compressed_ciphertext_list::CudaCompressible;
    use crate::integer::gpu::ciphertext::CudaRadixCiphertext;
    use crate::{FheBool, FheInt, FheUint};

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
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use crate::safe_serialization::{safe_deserialize, safe_serialize};
    use crate::shortint::parameters::list_compression::COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    use crate::shortint::parameters::multi_bit::tuniform::p_fail_2_minus_64::ks_pbs::V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    use crate::shortint::PBSParameters;
    use crate::{
        set_server_key, unset_server_key, ClientKey, CompressedCiphertextList,
        CompressedCiphertextListBuilder, FheBool, FheInt64, FheUint16, FheUint2, FheUint32,
    };

    #[test]
    fn test_compressed_ct_list_cpu_gpu() {
        for params in [
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64.into(),
            V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64.into(),
        ] {
            let config = crate::ConfigBuilder::with_custom_parameters::<PBSParameters>(params)
                .enable_compression(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64)
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
}
