use tfhe_versionable::Versionize;

use crate::backward_compatibility::compact_list::CompactCiphertextListVersions;
#[cfg(feature = "zk-pok")]
use crate::backward_compatibility::compact_list::ProvenCompactCiphertextListVersions;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::commons::math::random::{Deserialize, Serialize};
use crate::core_crypto::prelude::Numeric;
use crate::high_level_api::global_state;
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::traits::Tagged;
use crate::integer::ciphertext::{Compactable, DataKind, Expandable};
use crate::integer::encryption::KnowsMessageModulus;
use crate::integer::parameters::{
    CompactCiphertextListConformanceParams, IntegerCompactCiphertextListExpansionMode,
};
use crate::named::Named;
use crate::prelude::CiphertextList;
use crate::shortint::MessageModulus;
#[cfg(feature = "zk-pok")]
pub use zk::ProvenCompactCiphertextList;

#[cfg(feature = "zk-pok")]
use crate::zk::{CompactPkeCrs, ZkComputeLoad};
use crate::{CompactPublicKey, Tag};

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
            .expand(sks.integer_compact_ciphertext_list_expansion_mode())
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
                inner: self
                    .inner
                    .expand(IntegerCompactCiphertextListExpansionMode::NoCastingAndNoUnpacking)?,
                tag: self.tag.clone(),
            });
        }

        global_state::try_with_internal_keys(|maybe_keys| match maybe_keys {
            None => Err(crate::high_level_api::errors::UninitializedServerKey.into()),
            Some(InternalServerKey::Cpu(cpu_key)) => self
                .inner
                .expand(cpu_key.integer_compact_ciphertext_list_expansion_mode())
                .map(|inner| CompactCiphertextListExpander {
                    inner,
                    tag: self.tag.clone(),
                }),
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
    use crate::conformance::ParameterSetConformant;
    use crate::integer::ciphertext::IntegerProvenCompactCiphertextListConformanceParams;
    use crate::zk::CompactPkeCrs;

    #[derive(Clone, Serialize, Deserialize, Versionize)]
    #[versionize(ProvenCompactCiphertextListVersions)]
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

        pub fn verify(
            &self,
            crs: &CompactPkeCrs,
            pk: &CompactPublicKey,
            metadata: &[u8],
        ) -> crate::zk::ZkVerificationOutcome {
            self.inner.verify(crs, &pk.key.key, metadata)
        }

        pub fn verify_and_expand(
            &self,
            crs: &CompactPkeCrs,
            pk: &CompactPublicKey,
            metadata: &[u8],
        ) -> crate::Result<CompactCiphertextListExpander> {
            // For WASM
            if !self.inner.is_packed() && !self.inner.needs_casting() {
                // No ServerKey required, short circuit to avoid the global state call
                return Ok(CompactCiphertextListExpander {
                    inner: self.inner.verify_and_expand(
                        crs,
                        &pk.key.key,
                        metadata,
                        IntegerCompactCiphertextListExpansionMode::NoCastingAndNoUnpacking,
                    )?,
                    tag: self.tag.clone(),
                });
            }

            global_state::try_with_internal_keys(|maybe_keys| match maybe_keys {
                None => Err(crate::high_level_api::errors::UninitializedServerKey.into()),
                Some(InternalServerKey::Cpu(cpu_key)) => self
                    .inner
                    .verify_and_expand(
                        crs,
                        &pk.key.key,
                        metadata,
                        cpu_key.integer_compact_ciphertext_list_expansion_mode(),
                    )
                    .map(|expander| CompactCiphertextListExpander {
                        inner: expander,
                        tag: self.tag.clone(),
                    }),
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
                        IntegerCompactCiphertextListExpansionMode::NoCastingAndNoUnpacking,
                    )?,
                    tag: self.tag.clone(),
                });
            }

            global_state::try_with_internal_keys(|maybe_keys| match maybe_keys {
                None => Err(crate::high_level_api::errors::UninitializedServerKey.into()),
                Some(InternalServerKey::Cpu(cpu_key)) => self
                    .inner
                    .expand_without_verification(
                        cpu_key.integer_compact_ciphertext_list_expansion_mode(),
                    )
                    .map(|expander| CompactCiphertextListExpander {
                        inner: expander,
                        tag: self.tag.clone(),
                    }),
                #[cfg(feature = "gpu")]
                Some(_) => Err(crate::Error::new("Expected a CPU server key".to_string())),
            })
        }
    }

    impl ParameterSetConformant for ProvenCompactCiphertextList {
        type ParameterSet = IntegerProvenCompactCiphertextListConformanceParams;

        fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
            let Self { inner, tag: _ } = self;

            inner.is_conformant(parameter_set)
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use crate::integer::ciphertext::IntegerProvenCompactCiphertextListConformanceParams;
        use crate::zk::CompactPkeCrs;
        use rand::{thread_rng, Rng};

        #[test]
        fn conformance_zk_compact_ciphertext_list() {
            let mut rng = thread_rng();

            let params: crate::shortint::ClassicPBSParameters =
                crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
            let config = crate::ConfigBuilder::with_custom_parameters(params);

            let client_key = crate::ClientKey::generate(config.clone());
            // This is done in an offline phase and the CRS is shared to all clients and the server
            let crs = CompactPkeCrs::from_config(config.into(), 64).unwrap();
            let public_key = crate::CompactPublicKey::try_new(&client_key).unwrap();
            // This can be left empty, but if provided allows to tie the proof to arbitrary data
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
                    params.try_into().unwrap(),
                    &crs,
                );

            assert!(proven_compact_list.is_conformant(&params));
        }

        #[test]
        fn conformance_zk_compact_ciphertext_list_casting() {
            let mut rng = thread_rng();

            let params = crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

            let cpk_params = crate::shortint::parameters::compact_public_key_only::p_fail_2_minus_64::ks_pbs::PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

            let casting_params = crate::shortint::parameters::key_switching::p_fail_2_minus_64::ks_pbs::PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

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

pub struct CompactCiphertextListExpander {
    pub(in crate::high_level_api) inner: crate::integer::ciphertext::CompactCiphertextListExpander,
    tag: Tag,
}

impl CiphertextList for CompactCiphertextListExpander {
    fn len(&self) -> usize {
        self.inner.len()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn get_kind_of(&self, index: usize) -> Option<crate::FheTypes> {
        self.inner.get_kind_of(index).and_then(|data_kind| {
            crate::FheTypes::from_data_kind(data_kind, self.inner.message_modulus())
        })
    }

    fn get<T>(&self, index: usize) -> crate::Result<Option<T>>
    where
        T: Expandable + Tagged,
    {
        let mut expanded = self.inner.get::<T>(index);
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
        crs: &CompactPkeCrs,
        metadata: &[u8],
        compute_load: ZkComputeLoad,
    ) -> crate::Result<ProvenCompactCiphertextList> {
        self.inner
            .build_with_proof_packed(crs, metadata, compute_load)
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

            assert!(expander.get::<FheBool>(5).unwrap().is_none());
        }

        {
            // Incorrect type
            assert!(expander.get::<FheInt64>(0).is_err());

            // Correct type but wrong number of bits
            assert!(expander.get::<FheUint16>(0).is_err());
        }
    }

    #[test]
    fn test_compact_list_with_casting() {
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
}
