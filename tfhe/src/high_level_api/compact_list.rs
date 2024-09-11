use tfhe_versionable::Versionize;

use crate::backward_compatibility::compact_list::CompactCiphertextListVersions;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::commons::math::random::{Deserialize, Serialize};
use crate::core_crypto::prelude::Numeric;
use crate::high_level_api::global_state;
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::traits::Tagged;
use crate::integer::ciphertext::{Compactable, DataKind, Expandable};
use crate::integer::encryption::KnowsMessageModulus;
use crate::integer::parameters::{
    CompactCiphertextListConformanceParams, IntegerCompactCiphertextListCastingMode,
    IntegerCompactCiphertextListUnpackingMode,
};
use crate::named::Named;
use crate::shortint::MessageModulus;
#[cfg(feature = "zk-pok")]
pub use zk::ProvenCompactCiphertextList;

#[cfg(feature = "zk-pok")]
use crate::zk::{CompactPkePublicParams, ZkComputeLoad};
use crate::{CompactPublicKey, Tag};

impl crate::FheTypes {
    fn from_data_kind(data_kind: DataKind, message_modulus: MessageModulus) -> Option<Self> {
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
                    32 => Self::Uint32,
                    64 => Self::Uint64,
                    128 => Self::Uint128,
                    160 => Self::Uint160,
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
                    32 => Self::Int32,
                    64 => Self::Int64,
                    128 => Self::Int128,
                    160 => Self::Int160,
                    256 => Self::Int256,
                    _ => return None,
                }
            }
            DataKind::Boolean => Self::Bool,
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
            .expand(
                IntegerCompactCiphertextListUnpackingMode::UnpackIfNecessary(sks.key.pbs_key()),
                IntegerCompactCiphertextListCastingMode::NoCasting,
            )
            .map(|inner| CompactCiphertextListExpander {
                inner,
                tag: self.tag.clone(),
            })
    }

    pub fn expand(&self) -> crate::Result<CompactCiphertextListExpander> {
        // For WASM
        if !self.inner.is_packed() && !self.inner.needs_casting() {
            // No ServerKey required, short-circuit to avoid the global state call
            return Ok(CompactCiphertextListExpander {
                inner: self.inner.expand(
                    IntegerCompactCiphertextListUnpackingMode::NoUnpacking,
                    IntegerCompactCiphertextListCastingMode::NoCasting,
                )?,
                tag: self.tag.clone(),
            });
        }

        global_state::try_with_internal_keys(|maybe_keys| match maybe_keys {
            None => Err(crate::high_level_api::errors::UninitializedServerKey.into()),
            Some(InternalServerKey::Cpu(cpu_key)) => {
                let unpacking_mode = if self.inner.is_packed() {
                    IntegerCompactCiphertextListUnpackingMode::UnpackIfNecessary(cpu_key.pbs_key())
                } else {
                    IntegerCompactCiphertextListUnpackingMode::NoUnpacking
                };

                let casting_mode = if self.inner.needs_casting() {
                    IntegerCompactCiphertextListCastingMode::CastIfNecessary(
                        cpu_key.cpk_casting_key().ok_or_else(|| {
                            crate::Error::new(
                                "No casting key found in ServerKey, \
                                required to expand this CompactCiphertextList"
                                    .to_string(),
                            )
                        })?,
                    )
                } else {
                    IntegerCompactCiphertextListCastingMode::NoCasting
                };

                self.inner
                    .expand(unpacking_mode, casting_mode)
                    .map(|inner| CompactCiphertextListExpander {
                        inner,
                        tag: self.tag.clone(),
                    })
            }
            #[cfg(feature = "gpu")]
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

    #[derive(Clone, Serialize, Deserialize)]
    pub struct ProvenCompactCiphertextList {
        pub(crate) inner: crate::integer::ciphertext::ProvenCompactCiphertextList,
        pub(crate) tag: Tag,
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
            self.inner.len()
        }

        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }

        pub fn get_kind_of(&self, index: usize) -> Option<crate::FheTypes> {
            self.inner.get_kind_of(index).and_then(|data_kind| {
                crate::FheTypes::from_data_kind(data_kind, self.inner.ct_list.message_modulus())
            })
        }

        pub fn verify_and_expand(
            &self,
            public_params: &CompactPkePublicParams,
            pk: &CompactPublicKey,
            metadata: &[u8],
        ) -> crate::Result<CompactCiphertextListExpander> {
            // For WASM
            if !self.inner.is_packed() && !self.inner.needs_casting() {
                // No ServerKey required, short circuit to avoid the global state call
                return Ok(CompactCiphertextListExpander {
                    inner: self.inner.verify_and_expand(
                        public_params,
                        &pk.key.key,
                        metadata,
                        IntegerCompactCiphertextListUnpackingMode::NoUnpacking,
                        IntegerCompactCiphertextListCastingMode::NoCasting,
                    )?,
                    tag: self.tag.clone(),
                });
            }

            global_state::try_with_internal_keys(|maybe_keys| match maybe_keys {
                None => Err(crate::high_level_api::errors::UninitializedServerKey.into()),
                Some(InternalServerKey::Cpu(cpu_key)) => {
                    let unpacking_mode = if self.inner.is_packed() {
                        IntegerCompactCiphertextListUnpackingMode::UnpackIfNecessary(
                            cpu_key.pbs_key(),
                        )
                    } else {
                        IntegerCompactCiphertextListUnpackingMode::NoUnpacking
                    };

                    let casting_mode = if self.inner.needs_casting() {
                        IntegerCompactCiphertextListCastingMode::CastIfNecessary(
                            cpu_key.cpk_casting_key().ok_or_else(|| {
                                crate::Error::new(
                                    "No casting key found in ServerKey, \
                                required to expand this CompactCiphertextList"
                                        .to_string(),
                                )
                            })?,
                        )
                    } else {
                        IntegerCompactCiphertextListCastingMode::NoCasting
                    };

                    self.inner
                        .verify_and_expand(
                            public_params,
                            &pk.key.key,
                            metadata,
                            unpacking_mode,
                            casting_mode,
                        )
                        .map(|expander| CompactCiphertextListExpander {
                            inner: expander,
                            tag: self.tag.clone(),
                        })
                }
                #[cfg(feature = "gpu")]
                Some(_) => Err(crate::Error::new("Expected a CPU server key".to_string())),
            })
        }

        #[doc(hidden)]
        /// This function allows to expand a ciphertext without verifying the associated proof.
        ///
        /// If you are here you were probably looking for it: use at your own risks.
        pub fn expand_without_verification(&self) -> crate::Result<CompactCiphertextListExpander> {
            // For WASM
            if !self.inner.is_packed() && !self.inner.needs_casting() {
                // No ServerKey required, short circuit to avoid the global state call
                return Ok(CompactCiphertextListExpander {
                    inner: self.inner.expand_without_verification(
                        IntegerCompactCiphertextListUnpackingMode::NoUnpacking,
                        IntegerCompactCiphertextListCastingMode::NoCasting,
                    )?,
                    tag: self.tag.clone(),
                });
            }

            global_state::try_with_internal_keys(|maybe_keys| match maybe_keys {
                None => Err(crate::high_level_api::errors::UninitializedServerKey.into()),
                Some(InternalServerKey::Cpu(cpu_key)) => {
                    let unpacking_mode = if self.inner.is_packed() {
                        IntegerCompactCiphertextListUnpackingMode::UnpackIfNecessary(
                            cpu_key.pbs_key(),
                        )
                    } else {
                        IntegerCompactCiphertextListUnpackingMode::NoUnpacking
                    };

                    let casting_mode = if self.inner.needs_casting() {
                        IntegerCompactCiphertextListCastingMode::CastIfNecessary(
                            cpu_key.cpk_casting_key().ok_or_else(|| {
                                crate::Error::new(
                                    "No casting key found in ServerKey, \
                                required to expand this CompactCiphertextList"
                                        .to_string(),
                                )
                            })?,
                        )
                    } else {
                        IntegerCompactCiphertextListCastingMode::NoCasting
                    };

                    self.inner
                        .expand_without_verification(unpacking_mode, casting_mode)
                        .map(|expander| CompactCiphertextListExpander {
                            inner: expander,
                            tag: self.tag.clone(),
                        })
                }
                #[cfg(feature = "gpu")]
                Some(_) => Err(crate::Error::new("Expected a CPU server key".to_string())),
            })
        }
    }
}

pub struct CompactCiphertextListExpander {
    pub(in crate::high_level_api) inner: crate::integer::ciphertext::CompactCiphertextListExpander,
    tag: Tag,
}

impl CompactCiphertextListExpander {
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get_kind_of(&self, index: usize) -> Option<crate::FheTypes> {
        self.inner.get_kind_of(index).and_then(|data_kind| {
            crate::FheTypes::from_data_kind(data_kind, self.inner.message_modulus())
        })
    }

    pub fn get<T>(&self, index: usize) -> Option<crate::Result<T>>
    where
        T: Expandable + Tagged,
    {
        let mut expanded = self.inner.get::<T>(index);
        if let Some(Ok(inner)) = &mut expanded {
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
        T: Compactable,
    {
        self.inner.push(value);
        self
    }

    pub fn extend<T>(&mut self, values: impl Iterator<Item = T>) -> &mut Self
    where
        T: Compactable,
    {
        self.inner.extend(values);
        self
    }

    pub fn push_with_num_bits<T>(&mut self, number: T, num_bits: usize) -> crate::Result<&mut Self>
    where
        T: Compactable + Numeric,
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
        T: Compactable + Numeric,
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
        public_params: &CompactPkePublicParams,
        metadata: &[u8],
        compute_load: ZkComputeLoad,
    ) -> crate::Result<ProvenCompactCiphertextList> {
        self.inner
            .build_with_proof_packed(public_params, metadata, compute_load)
            .map(|proved_list| ProvenCompactCiphertextList {
                inner: proved_list,
                tag: self.tag.clone(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::*;
    #[cfg(feature = "zk-pok")]
    use crate::zk::CompactPkeCrs;
    use crate::{set_server_key, FheBool, FheInt64, FheUint16, FheUint2, FheUint32};

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

            assert!(expander.get::<FheBool>(5).is_none());
        }

        {
            // Incorrect type
            assert!(expander.get::<FheInt64>(0).unwrap().is_err());

            // Correct type but wrong number of bits
            assert!(expander.get::<FheUint16>(0).unwrap().is_err());
        }
    }

    #[cfg(feature = "zk-pok")]
    #[test]
    fn test_proven_compact_list() {
        use crate::shortint::parameters::classic::tuniform::p_fail_2_minus_64::ks_pbs::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

        let config = crate::ConfigBuilder::with_custom_parameters(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        )
        .build();

        let ck = crate::ClientKey::generate(config);
        let pk = crate::CompactPublicKey::new(&ck);
        let sks = crate::ServerKey::new(&ck);

        set_server_key(sks);

        // Intentionally low to that we test when multiple lists and proofs are needed
        let crs = CompactPkeCrs::from_config(config, 32).unwrap();

        let metadata = [b'h', b'l', b'a', b'p', b'i'];

        let compact_list = ProvenCompactCiphertextList::builder(&pk)
            .push(17u32)
            .push(-1i64)
            .push(false)
            .push_with_num_bits(3u32, 2)
            .unwrap()
            .build_with_proof_packed(crs.public_params(), &metadata, ZkComputeLoad::Proof)
            .unwrap();

        let serialized = bincode::serialize(&compact_list).unwrap();
        let compact_list: ProvenCompactCiphertextList = bincode::deserialize(&serialized).unwrap();
        let expander = compact_list
            .verify_and_expand(crs.public_params(), &pk, &metadata)
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

            assert!(expander.get::<FheBool>(4).is_none());
        }

        {
            // Incorrect type
            assert!(expander.get::<FheInt64>(0).unwrap().is_err());

            // Correct type but wrong number of bits
            assert!(expander.get::<FheUint16>(0).unwrap().is_err());
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

            assert!(unverified_expander.get::<FheBool>(4).is_none());
        }
    }

    #[cfg(feature = "zk-pok")]
    #[test]
    fn test_proven_compact_list_with_casting() {
        use crate::shortint::parameters::compact_public_key_only::p_fail_2_minus_64::ks_pbs::PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        use crate::shortint::parameters::key_switching::p_fail_2_minus_64::ks_pbs::PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

        let config = crate::ConfigBuilder::with_custom_parameters(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        )
        .use_dedicated_compact_public_key_parameters((
            PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
            PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        ))
        .build();

        let ck = crate::ClientKey::generate(config);
        let pk = crate::CompactPublicKey::new(&ck);
        let sks = crate::ServerKey::new(&ck);

        set_server_key(sks);

        // Intentionally low to that we test when multiple lists and proofs are needed
        let crs = CompactPkeCrs::from_config(config, 32).unwrap();

        let metadata = [b'h', b'l', b'a', b'p', b'i'];

        let compact_list = ProvenCompactCiphertextList::builder(&pk)
            .push(17u32)
            .push(-1i64)
            .push(false)
            .push_with_num_bits(3u32, 2)
            .unwrap()
            .build_with_proof_packed(crs.public_params(), &metadata, ZkComputeLoad::Proof)
            .unwrap();

        let serialized = bincode::serialize(&compact_list).unwrap();
        let compact_list: ProvenCompactCiphertextList = bincode::deserialize(&serialized).unwrap();
        let expander = compact_list
            .verify_and_expand(crs.public_params(), &pk, &metadata)
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

            assert!(expander.get::<FheBool>(4).is_none());
        }

        {
            // Incorrect type
            assert!(expander.get::<FheInt64>(0).unwrap().is_err());

            // Correct type but wrong number of bits
            assert!(expander.get::<FheUint16>(0).unwrap().is_err());
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

            assert!(unverified_expander.get::<FheBool>(4).is_none());
        }
    }
}
