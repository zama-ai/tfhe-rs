use tfhe_versionable::Versionize;

use crate::backward_compatibility::compact_list::CompactCiphertextListVersions;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::commons::math::random::{Deserialize, Serialize};
use crate::core_crypto::prelude::Numeric;
use crate::high_level_api::global_state;
use crate::high_level_api::keys::InternalServerKey;
use crate::integer::ciphertext::{Compactable, DataKind, Expandable};
use crate::integer::encryption::KnowsMessageModulus;
use crate::integer::parameters::{
    CompactCiphertextListConformanceParams, IntegerCompactCiphertextListCastingMode,
    IntegerCompactCiphertextListUnpackingMode,
};
use crate::named::Named;
use crate::shortint::MessageModulus;
#[cfg(feature = "zk-pok")]
use crate::zk::{CompactPkePublicParams, ZkComputeLoad};
use crate::CompactPublicKey;

#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(CompactCiphertextListVersions)]
pub struct CompactCiphertextList(pub(crate) crate::integer::ciphertext::CompactCiphertextList);

impl Named for CompactCiphertextList {
    const NAME: &'static str = "high_level_api::CompactCiphertextList";
}

impl CompactCiphertextList {
    pub fn builder(pk: &CompactPublicKey) -> CompactCiphertextListBuilder {
        CompactCiphertextListBuilder::new(pk)
    }

    pub fn expand_with_key(
        &self,
        sks: &crate::ServerKey,
    ) -> crate::Result<CompactCiphertextListExpander> {
        self.0
            .expand(
                IntegerCompactCiphertextListUnpackingMode::UnpackIfNecessary(sks.key.pbs_key()),
                IntegerCompactCiphertextListCastingMode::NoCasting,
            )
            .map(|inner| CompactCiphertextListExpander { inner })
    }

    pub fn expand(&self) -> crate::Result<CompactCiphertextListExpander> {
        // For WASM
        if !self.0.is_packed() && !self.0.needs_casting() {
            // No ServerKey required, shortcircuit to avoid the global state call
            return Ok(CompactCiphertextListExpander {
                inner: self.0.expand(
                    IntegerCompactCiphertextListUnpackingMode::NoUnpacking,
                    IntegerCompactCiphertextListCastingMode::NoCasting,
                )?,
            });
        }

        global_state::try_with_internal_keys(|maybe_keys| match maybe_keys {
            None => Err(crate::high_level_api::errors::UninitializedServerKey.into()),
            Some(InternalServerKey::Cpu(cpu_key)) => {
                let unpacking_mode = if self.0.is_packed() {
                    IntegerCompactCiphertextListUnpackingMode::UnpackIfNecessary(cpu_key.pbs_key())
                } else {
                    IntegerCompactCiphertextListUnpackingMode::NoUnpacking
                };

                let casting_mode = if self.0.needs_casting() {
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

                self.0
                    .expand(unpacking_mode, casting_mode)
                    .map(|inner| CompactCiphertextListExpander { inner })
            }
            #[cfg(feature = "gpu")]
            Some(_) => Err(crate::Error::new("Expected a CPU server key".to_string())),
        })
    }
}
impl ParameterSetConformant for CompactCiphertextList {
    type ParameterSet = CompactCiphertextListConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        self.0.is_conformant(parameter_set)
    }
}

#[cfg(feature = "zk-pok")]
#[derive(Clone, Serialize, Deserialize)]
pub struct ProvenCompactCiphertextList(crate::integer::ciphertext::ProvenCompactCiphertextList);

#[cfg(feature = "zk-pok")]
impl Named for ProvenCompactCiphertextList {
    const NAME: &'static str = "high_level_api::ProvenCompactCiphertextList";
}

#[cfg(feature = "zk-pok")]
impl ProvenCompactCiphertextList {
    pub fn builder(pk: &CompactPublicKey) -> CompactCiphertextListBuilder {
        CompactCiphertextListBuilder::new(pk)
    }

    pub fn verify_and_expand(
        &self,
        public_params: &CompactPkePublicParams,
        pk: &CompactPublicKey,
    ) -> crate::Result<CompactCiphertextListExpander> {
        // For WASM
        if !self.0.is_packed() && !self.0.needs_casting() {
            // No ServerKey required, shortcircuit to avoid the global state call
            return Ok(CompactCiphertextListExpander {
                inner: self.0.verify_and_expand(
                    public_params,
                    &pk.key.key,
                    IntegerCompactCiphertextListUnpackingMode::NoUnpacking,
                    IntegerCompactCiphertextListCastingMode::NoCasting,
                )?,
            });
        }

        global_state::try_with_internal_keys(|maybe_keys| match maybe_keys {
            None => Err(crate::high_level_api::errors::UninitializedServerKey.into()),
            Some(InternalServerKey::Cpu(cpu_key)) => {
                let unpacking_mode = if self.0.is_packed() {
                    IntegerCompactCiphertextListUnpackingMode::UnpackIfNecessary(cpu_key.pbs_key())
                } else {
                    IntegerCompactCiphertextListUnpackingMode::NoUnpacking
                };

                let casting_mode = if self.0.needs_casting() {
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

                self.0
                    .verify_and_expand(public_params, &pk.key.key, unpacking_mode, casting_mode)
                    .map(|expander| CompactCiphertextListExpander { inner: expander })
            }
            #[cfg(feature = "gpu")]
            Some(_) => Err(crate::Error::new("Expected a CPU server key".to_string())),
        })
    }
}

pub struct CompactCiphertextListExpander {
    inner: crate::integer::ciphertext::CompactCiphertextListExpander,
}

impl CompactCiphertextListExpander {
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get_kind_of(&self, index: usize) -> Option<crate::FheTypes> {
        Some(match self.inner.get_kind_of(index)? {
            DataKind::Unsigned(n) => {
                let num_bits_per_block = self.inner.message_modulus().0.ilog2() as usize;
                let num_bits = n * num_bits_per_block;
                match num_bits {
                    2 => crate::FheTypes::Uint2,
                    4 => crate::FheTypes::Uint4,
                    6 => crate::FheTypes::Uint6,
                    8 => crate::FheTypes::Uint8,
                    10 => crate::FheTypes::Uint10,
                    12 => crate::FheTypes::Uint12,
                    14 => crate::FheTypes::Uint14,
                    16 => crate::FheTypes::Uint16,
                    32 => crate::FheTypes::Uint32,
                    64 => crate::FheTypes::Uint64,
                    128 => crate::FheTypes::Uint128,
                    160 => crate::FheTypes::Uint160,
                    256 => crate::FheTypes::Uint256,
                    _ => return None,
                }
            }
            DataKind::Signed(n) => {
                let num_bits_per_block = self.inner.message_modulus().0.ilog2() as usize;
                let num_bits = n * num_bits_per_block;
                match num_bits {
                    2 => crate::FheTypes::Int2,
                    4 => crate::FheTypes::Int4,
                    6 => crate::FheTypes::Int6,
                    8 => crate::FheTypes::Int8,
                    10 => crate::FheTypes::Int10,
                    12 => crate::FheTypes::Int12,
                    14 => crate::FheTypes::Int14,
                    16 => crate::FheTypes::Int16,
                    32 => crate::FheTypes::Int32,
                    64 => crate::FheTypes::Int64,
                    128 => crate::FheTypes::Int128,
                    160 => crate::FheTypes::Int160,
                    256 => crate::FheTypes::Int256,
                    _ => return None,
                }
            }
            DataKind::Boolean => crate::FheTypes::Bool,
        })
    }

    pub fn get<T>(&self, index: usize) -> Option<crate::Result<T>>
    where
        T: Expandable,
    {
        self.inner.get(index)
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
}

impl CompactCiphertextListBuilder {
    pub fn new(pk: &CompactPublicKey) -> Self {
        Self {
            inner: crate::integer::ciphertext::CompactCiphertextListBuilder::new(&pk.key.key),
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
        CompactCiphertextList(self.inner.build())
    }

    pub fn build_packed(&self) -> CompactCiphertextList {
        self.inner
            .build_packed()
            .map(CompactCiphertextList)
            .expect("Internal error, invalid parameters should not have been allowed")
    }

    #[cfg(feature = "zk-pok")]
    pub fn build_with_proof_packed(
        &self,
        public_params: &CompactPkePublicParams,
        compute_load: ZkComputeLoad,
    ) -> crate::Result<ProvenCompactCiphertextList> {
        self.inner
            .build_with_proof_packed(public_params, compute_load)
            .map(ProvenCompactCiphertextList)
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

        let compact_list = ProvenCompactCiphertextList::builder(&pk)
            .push(17u32)
            .push(-1i64)
            .push(false)
            .push_with_num_bits(3u32, 2)
            .unwrap()
            .build_with_proof_packed(crs.public_params(), ZkComputeLoad::Proof)
            .unwrap();

        let serialized = bincode::serialize(&compact_list).unwrap();
        let compact_list: ProvenCompactCiphertextList = bincode::deserialize(&serialized).unwrap();
        let expander = compact_list
            .verify_and_expand(crs.public_params(), &pk)
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
    }

    #[cfg(feature = "zk-pok")]
    #[test]
    fn test_proven_compact_list_with_casting() {
        use crate::shortint::parameters::compact_public_key_only::PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        use crate::shortint::parameters::key_switching::PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
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

        let compact_list = ProvenCompactCiphertextList::builder(&pk)
            .push(17u32)
            .push(-1i64)
            .push(false)
            .push_with_num_bits(3u32, 2)
            .unwrap()
            .build_with_proof_packed(crs.public_params(), ZkComputeLoad::Proof)
            .unwrap();

        let serialized = bincode::serialize(&compact_list).unwrap();
        let compact_list: ProvenCompactCiphertextList = bincode::deserialize(&serialized).unwrap();
        let expander = compact_list
            .verify_and_expand(crs.public_params(), &pk)
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
    }
}
