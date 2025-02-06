use std::convert::Infallible;
use tfhe_versionable::{
    Unversionize, UnversionizeError, Upgrade, Version, Versionize, VersionizeOwned,
    VersionsDispatch,
};

use crate::core_crypto::commons::math::random::{Deserialize, Serialize};
use crate::high_level_api::compressed_ciphertext_list::InnerCompressedCiphertextList;
#[cfg(feature = "gpu")]
use crate::high_level_api::global_state::with_thread_local_cuda_streams;
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::compressed_ciphertext_list::CudaCompressedCiphertextList;
use crate::{CompressedCiphertextList, SerializedKind, Tag};

#[derive(Clone, Serialize, Deserialize)]
pub(crate) enum InnerCompressedCiphertextListV0 {
    Cpu(crate::integer::ciphertext::CompressedCiphertextList),
    #[cfg(feature = "gpu")]
    Cuda(CudaCompressedCiphertextList),
}

#[derive(serde::Serialize)]
pub struct InnerCompressedCiphertextListV0Version<'vers>(
    <InnerCompressedCiphertextListV0 as Versionize>::Versioned<'vers>,
);

impl<'vers> From<&'vers InnerCompressedCiphertextListV0>
    for InnerCompressedCiphertextListV0Version<'vers>
{
    fn from(value: &'vers InnerCompressedCiphertextListV0) -> Self {
        Self(value.versionize())
    }
}

#[derive(::serde::Serialize, ::serde::Deserialize)]
pub struct InnerCompressedCiphertextListV0Owned(
    <InnerCompressedCiphertextListV0 as VersionizeOwned>::VersionedOwned,
);

impl From<InnerCompressedCiphertextListV0> for InnerCompressedCiphertextListV0Owned {
    fn from(value: InnerCompressedCiphertextListV0) -> Self {
        Self(value.versionize_owned())
    }
}

impl TryFrom<InnerCompressedCiphertextListV0Owned> for InnerCompressedCiphertextListV0 {
    type Error = UnversionizeError;

    fn try_from(value: InnerCompressedCiphertextListV0Owned) -> Result<Self, Self::Error> {
        Self::unversionize(value.0)
    }
}

impl Version for InnerCompressedCiphertextListV0 {
    type Ref<'vers>
        = InnerCompressedCiphertextListV0Version<'vers>
    where
        Self: 'vers;

    type Owned = InnerCompressedCiphertextListV0Owned;
}

impl Versionize for InnerCompressedCiphertextListV0 {
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

impl VersionizeOwned for InnerCompressedCiphertextListV0 {
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

impl Unversionize for InnerCompressedCiphertextListV0 {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        Ok(Self::Cpu(
            crate::integer::ciphertext::CompressedCiphertextList::unversionize(versioned)?,
        ))
    }
}

impl Upgrade<InnerCompressedCiphertextList> for InnerCompressedCiphertextListV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<InnerCompressedCiphertextList, Self::Error> {
        Ok(match self {
            Self::Cpu(cpu) => InnerCompressedCiphertextList::Cpu(cpu.packed_list),
            #[cfg(feature = "gpu")]
            Self::Cuda(cuda) => InnerCompressedCiphertextList::Cuda(cuda.packed_list),
        })
    }
}

#[derive(VersionsDispatch)]
#[allow(unused)]
pub(crate) enum InnerCompressedCiphertextListVersions {
    V0(InnerCompressedCiphertextListV0),
    V1(InnerCompressedCiphertextList),
}

#[derive(Version)]
pub struct CompressedCiphertextListV0(crate::integer::ciphertext::CompressedCiphertextList);

impl Upgrade<CompressedCiphertextListV1> for CompressedCiphertextListV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedCiphertextListV1, Self::Error> {
        Ok(CompressedCiphertextListV1 {
            inner: self.0,
            tag: Tag::default(),
        })
    }
}

#[derive(Version)]
pub struct CompressedCiphertextListV1 {
    inner: crate::integer::ciphertext::CompressedCiphertextList,
    tag: Tag,
}

impl Upgrade<CompressedCiphertextListV2> for CompressedCiphertextListV1 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedCiphertextListV2, Self::Error> {
        Ok(CompressedCiphertextListV2 {
            inner: InnerCompressedCiphertextListV0::Cpu(self.inner),
            tag: self.tag,
        })
    }
}

#[derive(Version)]
pub struct CompressedCiphertextListV2 {
    inner: InnerCompressedCiphertextListV0,
    tag: Tag,
}

impl Upgrade<CompressedCiphertextList> for CompressedCiphertextListV2 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedCiphertextList, Self::Error> {
        let (block_kinds, msg_modulus) = match &self.inner {
            InnerCompressedCiphertextListV0::Cpu(inner) => {
                (&inner.info, inner.packed_list.message_modulus)
            }
            #[cfg(feature = "gpu")]
            InnerCompressedCiphertextListV0::Cuda(inner) => {
                (&inner.info, inner.packed_list.message_modulus)
            }
        };
        let info = block_kinds
            .iter()
            .map(|kind| SerializedKind::from_data_kind(*kind, msg_modulus))
            .collect();
        Ok(CompressedCiphertextList {
            inner: self.inner.upgrade()?,
            info,
            tag: self.tag,
        })
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedCiphertextListVersions {
    V0(CompressedCiphertextListV0),
    V1(CompressedCiphertextListV1),
    V2(CompressedCiphertextListV2),
    V3(CompressedCiphertextList),
}
