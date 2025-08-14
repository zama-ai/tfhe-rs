use crate::backward_compatibility::compressed_ciphertext_list::CompressedSquashedNoiseCiphertextListVersions;
use crate::high_level_api::booleans::InnerSquashedNoiseBoolean;
use crate::high_level_api::global_state::try_with_internal_keys;
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
use crate::named::Named;
use crate::shortint::ciphertext::SquashedNoiseCiphertext;
use crate::{SquashedNoiseFheBool, SquashedNoiseFheInt, SquashedNoiseFheUint, Tag, Versionize};
use serde::{Deserialize, Serialize};
use std::num::NonZero;
use tfhe_versionable::{Unversionize, UnversionizeError, VersionizeOwned};

pub(in crate::high_level_api) enum InnerCompressedSquashedNoiseCiphertextList {
    Cpu(IntegerCompressedSquashedNoiseCiphertextList),
}

impl Versionize for InnerCompressedSquashedNoiseCiphertextList {
    type Versioned<'vers>
        = <IntegerCompressedSquashedNoiseCiphertextList as Versionize>::Versioned<'vers>
    where
        Self: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        self.on_cpu().versionize()
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
    fn on_cpu(&self) -> &IntegerCompressedSquashedNoiseCiphertextList {
        match self {
            Self::Cpu(inner) => inner,
        }
    }

    fn into_cpu(self) -> IntegerCompressedSquashedNoiseCiphertextList {
        match self {
            Self::Cpu(inner) => inner,
        }
    }

    fn current_device(&self) -> crate::Device {
        match self {
            Self::Cpu(_) => crate::Device::Cpu,
        }
    }

    #[allow(clippy::unnecessary_wraps, reason = "It depends on activated features")]
    fn move_to_device(&mut self, target_device: crate::Device) -> crate::Result<()> {
        let current_device = self.current_device();
        if current_device == target_device {
            return Ok(());
        }

        let cpu_ct = self.on_cpu();

        match target_device {
            crate::Device::Cpu => {
                *self = Self::Cpu(cpu_ct.to_owned());
                Ok(())
            }
            #[cfg(feature = "gpu")]
            crate::Device::CudaGpu => Err(crate::error!(
                "Cuda does not support CompressedSquashedNoiseCiphertextList"
            )),
            #[cfg(feature = "hpu")]
            crate::Device::Hpu => Err(crate::error!(
                "Hpu does not support CompressedSquashedNoiseCiphertextList"
            )),
        }
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
        };

        if let Ok(Some(ct)) = &mut r {
            *ct.tag_mut() = self.tag.clone();
        }
        r
    }
}

pub trait HlSquashedNoiseExpandable: SquashedNoiseExpandable {}

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

mod private {
    use crate::shortint::ciphertext::SquashedNoiseCiphertext;

    pub enum SquashedNoiseToBeCompressed {
        Cpu(Vec<SquashedNoiseCiphertext>),
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
            Some(InternalServerKey::Cuda(_)) => Err(crate::error!(
                "Cuda GPU does not support compression of squashed noise ciphertexts"
            )),
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
        let params = V1_3_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let noise_squashing_params =
            V1_3_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let noise_squashing_compression_params =
            V1_3_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let config = ConfigBuilder::with_custom_parameters(params)
            .enable_noise_squashing(noise_squashing_params)
            .enable_noise_squashing_compression(noise_squashing_compression_params)
            .build();

        let (cks, sks) = generate_keys(config);

        let mut rng = rand::thread_rng();

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
}
