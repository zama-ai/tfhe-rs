use std::convert::Infallible;

use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use self::signed::SignedRadixCiphertext;
use self::unsigned::RadixCiphertext as UnsignedRadixCiphertext;
use crate::high_level_api::global_state::with_cpu_internal_keys;
use crate::high_level_api::integers::signed::InnerSquashedNoiseSignedRadixCiphertext;
use crate::high_level_api::integers::unsigned::InnerSquashedNoiseRadixCiphertext;
use crate::high_level_api::integers::*;
use crate::high_level_api::re_randomization::ReRandomizationMetadata;
use crate::high_level_api::SquashedNoiseCiphertextState;
use crate::integer::backward_compatibility::ciphertext::{
    CompressedModulusSwitchedRadixCiphertextTFHE06,
    CompressedModulusSwitchedSignedRadixCiphertextTFHE06,
};
use crate::integer::ciphertext::{
    BaseRadixCiphertext, BaseSignedRadixCiphertext,
    CompressedRadixCiphertext as IntegerCompressedRadixCiphertext,
    CompressedSignedRadixCiphertext as IntegerCompressedSignedRadixCiphertext,
};
use crate::shortint::ciphertext::CompressedModulusSwitchedCiphertext;
use crate::shortint::{Ciphertext, ServerKey};
use crate::Tag;
use serde::{Deserialize, Serialize};

// Manual impl
#[derive(Serialize, Deserialize)]
pub(crate) enum SignedRadixCiphertextVersionedOwned {
    V0(SignedRadixCiphertextVersionOwned),
}

#[derive(Serialize, Deserialize)]
pub(crate) enum UnsignedRadixCiphertextVersionedOwned {
    V0(UnsignedRadixCiphertextVersionOwned),
}

// This method was used to decompress a ciphertext in tfhe-rs < 0.7
fn old_sk_decompress(
    sk: &ServerKey,
    compressed_ct: &CompressedModulusSwitchedCiphertext,
) -> Ciphertext {
    let acc = sk.generate_lookup_table(|a| a);

    let mut result = sk.decompress_and_apply_lookup_table(compressed_ct, &acc);

    result.degree = compressed_ct.degree;

    result
}

#[derive(Version)]
pub enum CompressedSignedRadixCiphertextV0 {
    Seeded(IntegerCompressedSignedRadixCiphertext),
    ModulusSwitched(CompressedModulusSwitchedSignedRadixCiphertextTFHE06),
}

impl Upgrade<CompressedSignedRadixCiphertext> for CompressedSignedRadixCiphertextV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedSignedRadixCiphertext, Self::Error> {
        match self {
            Self::Seeded(ct) => Ok(CompressedSignedRadixCiphertext::Seeded(ct)),

            // Upgrade by decompressing and recompressing with the new scheme
            Self::ModulusSwitched(ct) => {
                let upgraded = with_cpu_internal_keys(|sk| {
                    let blocks = ct
                        .blocks
                        .par_iter()
                        .map(|a| old_sk_decompress(&sk.key.key.key, a))
                        .collect();

                    let radix = BaseSignedRadixCiphertext { blocks };
                    sk.pbs_key()
                        .switch_modulus_and_compress_signed_parallelized(&radix)
                });
                Ok(CompressedSignedRadixCiphertext::ModulusSwitched(upgraded))
            }
        }
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedSignedRadixCiphertextVersions {
    V0(CompressedSignedRadixCiphertextV0),
    V1(CompressedSignedRadixCiphertext),
}

#[derive(Version)]
pub enum CompressedRadixCiphertextV0 {
    Seeded(IntegerCompressedRadixCiphertext),
    ModulusSwitched(CompressedModulusSwitchedRadixCiphertextTFHE06),
}

impl Upgrade<CompressedRadixCiphertext> for CompressedRadixCiphertextV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedRadixCiphertext, Self::Error> {
        match self {
            Self::Seeded(ct) => Ok(CompressedRadixCiphertext::Seeded(ct)),

            // Upgrade by decompressing and recompressing with the new scheme
            Self::ModulusSwitched(ct) => {
                let upgraded = with_cpu_internal_keys(|sk| {
                    let blocks = ct
                        .blocks
                        .par_iter()
                        .map(|a| old_sk_decompress(&sk.key.key.key, a))
                        .collect();

                    let radix = BaseRadixCiphertext { blocks };
                    sk.pbs_key()
                        .switch_modulus_and_compress_parallelized(&radix)
                });
                Ok(CompressedRadixCiphertext::ModulusSwitched(upgraded))
            }
        }
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedRadixCiphertextVersions {
    V0(CompressedRadixCiphertextV0),
    V1(CompressedRadixCiphertext),
}

#[derive(Version)]
pub struct FheIntV0<Id: FheIntId> {
    pub(in crate::high_level_api) ciphertext: SignedRadixCiphertext,
    pub(in crate::high_level_api) id: Id,
}

impl<Id: FheIntId> Upgrade<FheIntV1<Id>> for FheIntV0<Id> {
    type Error = Infallible;

    fn upgrade(self) -> Result<FheIntV1<Id>, Self::Error> {
        Ok(FheIntV1 {
            ciphertext: self.ciphertext,
            id: self.id,
            tag: Tag::default(),
        })
    }
}

#[derive(Version)]
pub struct FheIntV1<Id: FheIntId> {
    pub(in crate::high_level_api) ciphertext: SignedRadixCiphertext,
    pub(in crate::high_level_api) id: Id,
    pub(crate) tag: Tag,
}

impl<Id: FheIntId> Upgrade<FheInt<Id>> for FheIntV1<Id> {
    type Error = Infallible;

    fn upgrade(self) -> Result<FheInt<Id>, Self::Error> {
        let Self {
            ciphertext,
            id,
            tag,
        } = self;

        Ok(FheInt {
            ciphertext,
            id,
            tag,
            re_randomization_metadata: ReRandomizationMetadata::default(),
        })
    }
}

#[derive(VersionsDispatch)]
pub enum FheIntVersions<Id: FheIntId> {
    V0(FheIntV0<Id>),
    V1(FheIntV1<Id>),
    V2(FheInt<Id>),
}

#[derive(Version)]
pub struct CompressedFheIntV0<Id>
where
    Id: FheIntId,
{
    pub(in crate::high_level_api) ciphertext: CompressedSignedRadixCiphertext,
    pub(in crate::high_level_api) id: Id,
}

impl<Id: FheIntId> Upgrade<CompressedFheInt<Id>> for CompressedFheIntV0<Id> {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedFheInt<Id>, Self::Error> {
        Ok(CompressedFheInt {
            ciphertext: self.ciphertext,
            id: self.id,
            tag: Tag::default(),
        })
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedFheIntVersions<Id: FheIntId> {
    V0(CompressedFheIntV0<Id>),
    V1(CompressedFheInt<Id>),
}

#[derive(Version)]
pub struct FheUintV0<Id: FheUintId> {
    pub(in crate::high_level_api) ciphertext: UnsignedRadixCiphertext,
    pub(in crate::high_level_api) id: Id,
}

impl<Id: FheUintId> Upgrade<FheUintV1<Id>> for FheUintV0<Id> {
    type Error = Infallible;

    fn upgrade(self) -> Result<FheUintV1<Id>, Self::Error> {
        Ok(FheUintV1 {
            ciphertext: self.ciphertext,
            id: self.id,
            tag: Tag::default(),
        })
    }
}

#[derive(Version)]
pub struct FheUintV1<Id: FheUintId> {
    pub(in crate::high_level_api) ciphertext: UnsignedRadixCiphertext,
    pub(in crate::high_level_api) id: Id,
    pub(crate) tag: Tag,
}

impl<Id: FheUintId> Upgrade<FheUint<Id>> for FheUintV1<Id> {
    type Error = Infallible;

    fn upgrade(self) -> Result<FheUint<Id>, Self::Error> {
        let Self {
            ciphertext,
            id,
            tag,
        } = self;

        Ok(FheUint {
            ciphertext,
            id,
            tag,
            re_randomization_metadata: ReRandomizationMetadata::default(),
        })
    }
}

#[derive(VersionsDispatch)]
pub enum FheUintVersions<Id: FheUintId> {
    V0(FheUintV0<Id>),
    V1(FheUintV1<Id>),
    V2(FheUint<Id>),
}

#[derive(Version)]
pub struct CompressedFheUintV0<Id>
where
    Id: FheUintId,
{
    pub(in crate::high_level_api) ciphertext: CompressedRadixCiphertext,
    pub(in crate::high_level_api) id: Id,
}

impl<Id: FheUintId> Upgrade<CompressedFheUint<Id>> for CompressedFheUintV0<Id> {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedFheUint<Id>, Self::Error> {
        Ok(CompressedFheUint::new(self.ciphertext, Tag::default()))
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedFheUintVersions<Id: FheUintId> {
    V0(CompressedFheUintV0<Id>),
    V1(CompressedFheUint<Id>),
}

// Squashed Noise
// Manual impl
#[derive(Serialize, Deserialize)]
pub(crate) enum InnerSquashedNoiseRadixCiphertextVersionedOwned {
    V0(InnerSquashedNoiseRadixCiphertextVersionOwned),
}

#[derive(Version)]
pub struct SquashedNoiseFheUintV0 {
    pub(in crate::high_level_api) inner: InnerSquashedNoiseRadixCiphertext,
    pub(in crate::high_level_api) tag: Tag,
}

impl Upgrade<SquashedNoiseFheUint> for SquashedNoiseFheUintV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<SquashedNoiseFheUint, Self::Error> {
        Ok(SquashedNoiseFheUint::new(
            self.inner,
            SquashedNoiseCiphertextState::Normal,
            self.tag,
        ))
    }
}

#[derive(VersionsDispatch)]
pub enum SquashedNoiseFheUintVersions {
    V0(SquashedNoiseFheUintV0),
    V1(SquashedNoiseFheUint),
}

// Manual impl
#[derive(Serialize, Deserialize)]
pub(crate) enum InnerSquashedNoiseSignedRadixCiphertextVersionedOwned {
    V0(InnerSquashedNoiseSignedRadixCiphertextVersionOwned),
}

#[derive(Version)]
pub struct SquashedNoiseFheIntV0 {
    pub(in crate::high_level_api) inner: InnerSquashedNoiseSignedRadixCiphertext,
    pub(in crate::high_level_api) tag: Tag,
}

impl Upgrade<SquashedNoiseFheInt> for SquashedNoiseFheIntV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<SquashedNoiseFheInt, Self::Error> {
        Ok(SquashedNoiseFheInt::new(
            self.inner,
            SquashedNoiseCiphertextState::Normal,
            self.tag,
        ))
    }
}

#[derive(VersionsDispatch)]
pub enum SquashedNoiseFheIntVersions {
    V0(SquashedNoiseFheIntV0),
    V1(SquashedNoiseFheInt),
}
