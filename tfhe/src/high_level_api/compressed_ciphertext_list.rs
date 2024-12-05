use tfhe_versionable::{Unversionize, UnversionizeError, Versionize, VersionizeOwned};

use super::keys::InternalServerKey;
use crate::backward_compatibility::compressed_ciphertext_list::CompressedCiphertextListVersions;
use crate::core_crypto::commons::math::random::{Deserialize, Serialize};
use crate::high_level_api::booleans::InnerBoolean;
use crate::high_level_api::errors::UninitializedServerKey;
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
        }
    }
}
impl<Id: FheIntId> HlCompressible for FheInt<Id> {
    fn compress_into(self, messages: &mut Vec<(ToBeCompressed, DataKind)>) {
        match self.ciphertext {
            crate::high_level_api::integers::signed::RadixCiphertext::Cpu(cpu_radix) => {
                let blocks = cpu_radix.blocks;
                let kind = DataKind::Signed(blocks.len());
                messages.push((ToBeCompressed::Cpu(blocks), kind));
            }
            #[cfg(feature = "gpu")]
            crate::high_level_api::integers::signed::RadixCiphertext::Cuda(gpu_radix) => {
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
            None => Err(UninitializedServerKey.into()),
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) enum InnerCompressedCiphertextList {
    Cpu(crate::integer::ciphertext::CompressedCiphertextList),
    #[cfg(feature = "gpu")]
    Cuda(crate::integer::gpu::ciphertext::compressed_ciphertext_list::CudaCompressedCiphertextList),
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
        match &self.inner {
            InnerCompressedCiphertextList::Cpu(inner) => {
                crate::high_level_api::global_state::try_with_internal_keys(|keys| match keys {
                    Some(InternalServerKey::Cpu(cpu_key)) => cpu_key
                        .key
                        .decompression_key
                        .as_ref()
                        .ok_or_else(|| {
                            crate::Error::new("Compression key not set in server key".to_owned())
                        })
                        .and_then(|decompression_key| {
                            let mut ct = inner.get::<T>(index, decompression_key);
                            if let Ok(Some(ct_ref)) = &mut ct {
                                ct_ref.tag_mut().set_data(cpu_key.tag.data())
                            }
                            ct
                        }),
                    _ => Err(crate::Error::new(
                        "A Cpu server key is needed to be set".to_string(),
                    )),
                })
            }
            #[cfg(feature = "gpu")]
            InnerCompressedCiphertextList::Cuda(inner) => {
                crate::high_level_api::global_state::try_with_internal_keys(|keys| match keys {
                    Some(InternalServerKey::Cuda(cuda_key)) => cuda_key
                        .key
                        .decompression_key
                        .as_ref()
                        .ok_or_else(|| {
                            crate::Error::new("Compression key not set in server key".to_owned())
                        })
                        .and_then(|decompression_key| {
                            let mut ct = with_thread_local_cuda_streams(|streams| {
                                inner.get::<T>(index, decompression_key, streams)
                            });
                            if let Ok(Some(ct_ref)) = &mut ct {
                                ct_ref.tag_mut().set_data(cuda_key.tag.data())
                            }
                            ct
                        }),
                    _ => Err(crate::Error::new(
                        "A Cuda server key is needed to be set".to_string(),
                    )),
                })
            }
        }
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
            self.ciphertext.into_gpu().compress_into(messages, streams)
        }
    }

    impl<Id: FheIntId> CudaCompressible for FheInt<Id> {
        fn compress_into(
            self,
            messages: &mut Vec<CudaRadixCiphertext>,
            streams: &CudaStreams,
        ) -> DataKind {
            self.ciphertext.into_gpu().compress_into(messages, streams)
        }
    }

    impl CudaCompressible for FheBool {
        fn compress_into(
            self,
            messages: &mut Vec<CudaRadixCiphertext>,
            streams: &CudaStreams,
        ) -> DataKind {
            self.ciphertext.into_gpu().compress_into(messages, streams)
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
                        Err(crate::Error::new(format!(
                            "Tried to expand a FheUint{} while a FheUint{} is stored in this slot",
                            Id::num_bits(),
                            stored_num_bits
                        )))
                    }
                }
                DataKind::Signed(_) => {
                    let stored_num_bits = cuda_num_bits_of_blocks(&blocks) as usize;
                    Err(crate::Error::new(format!(
                        "Tried to expand a FheUint{} while a FheInt{} is stored in this slot",
                        Id::num_bits(),
                        stored_num_bits
                    )))
                }
                DataKind::Boolean => Err(crate::Error::new(format!(
                    "Tried to expand a FheUint{} while a FheBool is stored in this slot",
                    Id::num_bits(),
                ))),
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
                    Err(crate::Error::new(format!(
                        "Tried to expand a FheInt{} while a FheUint{} is stored in this slot",
                        Id::num_bits(),
                        stored_num_bits
                    )))
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
                        Err(crate::Error::new(format!(
                            "Tried to expand a FheInt{} while a FheInt{} is stored in this slot",
                            Id::num_bits(),
                            stored_num_bits
                        )))
                    }
                }
                DataKind::Boolean => Err(crate::Error::new(format!(
                    "Tried to expand a FheUint{} while a FheBool is stored in this slot",
                    Id::num_bits(),
                ))),
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
                    Err(crate::Error::new(format!(
                        "Tried to expand a FheBool while a FheUint{stored_num_bits} is stored in this slot",
                    )))
                }
                DataKind::Signed(_) => {
                    let stored_num_bits = cuda_num_bits_of_blocks(&blocks) as usize;
                    Err(crate::Error::new(format!(
                        "Tried to expand a FheBool while a FheInt{stored_num_bits} is stored in this slot",
                    )))
                }
                DataKind::Boolean => {
                    let mut boolean_block = CudaBooleanBlock::from_cuda_radix_ciphertext(blocks);
                    // We know the value is a boolean one (via the data kind)
                    boolean_block.0.ciphertext.info.blocks[0].degree =
                        crate::shortint::ciphertext::Degree::new(1);

                    // The expander will be responsible for setting the correct tag
                    Ok(Self::new(boolean_block, Tag::default()))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use crate::shortint::parameters::list_compression::COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    use crate::{
        set_server_key, ClientKey, CompressedCiphertextList, CompressedCiphertextListBuilder,
        FheBool, FheInt64, FheUint16, FheUint2, FheUint32,
    };

    #[test]
    fn test_compressed_ct_list_cpu_gpu() {
        let config = crate::ConfigBuilder::with_custom_parameters(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        )
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
            check_is_correct(&compressed_list_builder.build().unwrap(), &ck);

            #[cfg(feature = "gpu")]
            {
                set_server_key(sk.decompress_to_gpu());
                check_is_correct(&compressed_list_builder.build().unwrap(), &ck);
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
            compressed_list_builder
                .push(ct1)
                .push(ct2)
                .push(ct3)
                .push(ct4);

            set_server_key(sk.decompress());
            check_is_correct(&compressed_list_builder.build().unwrap(), &ck);

            set_server_key(sk.decompress_to_gpu());
            check_is_correct(&compressed_list_builder.build().unwrap(), &ck);
        }

        fn check_is_correct(compressed_list: &CompressedCiphertextList, ck: &ClientKey) {
            let serialized = bincode::serialize(&compressed_list).unwrap();

            let compressed_list: CompressedCiphertextList =
                bincode::deserialize(&serialized).unwrap();
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
