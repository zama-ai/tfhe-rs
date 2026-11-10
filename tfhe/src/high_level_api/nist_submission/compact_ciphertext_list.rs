use crate::core_crypto::prelude::Numeric;
use crate::high_level_api::CompactCiphertextListBuilder as InnerBuilder;
use crate::integer::bigint::{StaticSignedBigInt, StaticUnsignedBigInt};
use crate::{CompactPublicKey, HlCompactable};

use crate::core_crypto::prelude::{
    par_expand_lwe_compact_ciphertext_list, ContiguousEntityContainer, LweCiphertext,
    LweCiphertextList,
};
use crate::high_level_api::ServerKey as HlServerKey;
use crate::shortint::atomic_pattern::AtomicPattern;
use crate::shortint::ciphertext::CompactCiphertextList as ShortintCompactCiphertextList;
use crate::shortint::parameters::{CompactPublicKeyEncryptionParameters, Degree, NoiseLevel};
use crate::shortint::Ciphertext;
use rayon::prelude::*;

/// Does the expand + keyswitch following NIST submission documents
///
/// Each LWE of the lists becomes one block of degree `message_modulus - 1` with a nominal noise
/// level, without a PBS to clean it, so their proofs must guarantee that each block is below the
/// message modulus.
fn expand_and_keyswitch<'a>(
    compact_lists: impl Iterator<Item = &'a ShortintCompactCiphertextList>,
    cpu_key: &HlServerKey,
) -> crate::Result<Vec<Ciphertext>> {
    let casting_key = cpu_key
        .cpk_casting_key()
        .map(|key| key.key)
        .ok_or_else(|| crate::error!("NIST submission requires a casting key"))?;

    let post_ks_lwe_size = casting_key
        .dest_server_key
        .atomic_pattern
        .ciphertext_lwe_dimension_for_key(casting_key.key_switching_key_material.destination_key)
        .to_lwe_size();

    let post_ks_ciphertext_modulus = casting_key
        .dest_server_key
        .atomic_pattern
        .ciphertext_modulus_for_key(casting_key.key_switching_key_material.destination_key);

    let shortint_key = &cpu_key.key.key.key;

    let mut out_collection = Vec::new();

    for shortint_list in compact_lists {
        let mut expanded_lwe_ciphertext_list = LweCiphertextList::new(
            0u64,
            shortint_list.ct_list.lwe_size(),
            shortint_list.ct_list.lwe_ciphertext_count(),
            shortint_list.ct_list.ciphertext_modulus(),
        );

        let start_index = out_collection.len();
        for _ in 0..expanded_lwe_ciphertext_list.lwe_ciphertext_count().0 {
            let ct = LweCiphertext::new(0u64, post_ks_lwe_size, post_ks_ciphertext_modulus);
            out_collection.push(Ciphertext::new(
                ct,
                Degree::new(cpu_key.message_modulus().0 - 1),
                NoiseLevel::NOMINAL,
                cpu_key.message_modulus(),
                shortint_key.carry_modulus,
                shortint_key.atomic_pattern.kind(),
            ));
        }

        let ct_chunk = &mut out_collection[start_index..];

        par_expand_lwe_compact_ciphertext_list(
            &mut expanded_lwe_ciphertext_list,
            &shortint_list.ct_list,
        );

        expanded_lwe_ciphertext_list
            .par_iter()
            .zip(ct_chunk.par_iter_mut())
            .for_each(|(expanded, key_switched)| {
                use crate::core_crypto::prelude::keyswitch_lwe_ciphertext;

                keyswitch_lwe_ciphertext(
                    casting_key.key_switching_key_material.key_switching_key,
                    &expanded,
                    &mut key_switched.ct,
                );
            });
    }

    Ok(out_collection)
}

mod sealed {
    pub trait Sealed {}
}

/// Clear values that can be put in a NIST list: integers only.
///
/// Booleans and strings are not allowed: their blocks need a tighter bound than the message modulus
/// (0 or 1 for a boolean, below 128 for an ASCII character), which the proofs cannot guarantee and
/// the NIST expansion does not enforce as it does not clean the blocks.
pub trait NistCompactable: HlCompactable + sealed::Sealed {}

macro_rules! impl_nist_compactable {
    ($($ty:ty),* $(,)?) => {
        $(
            impl sealed::Sealed for $ty {}
            impl NistCompactable for $ty {}
        )*
    };
}

impl_nist_compactable!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

impl<const N: usize> sealed::Sealed for StaticUnsignedBigInt<N> {}
impl<const N: usize> NistCompactable for StaticUnsignedBigInt<N> {}
impl<const N: usize> sealed::Sealed for StaticSignedBigInt<N> {}
impl<const N: usize> NistCompactable for StaticSignedBigInt<N> {}

pub struct CompactCiphertextListBuilder(InnerBuilder);

impl CompactCiphertextListBuilder {
    pub fn new(pk: &CompactPublicKey) -> Self {
        Self(InnerBuilder::new(pk))
    }

    pub fn push<T>(&mut self, value: T) -> &mut Self
    where
        T: NistCompactable,
    {
        self.0.push(value);
        self
    }

    pub fn extend<T>(&mut self, values: impl Iterator<Item = T>) -> &mut Self
    where
        T: NistCompactable,
    {
        self.0.extend(values);
        self
    }

    pub fn push_with_num_bits<T>(&mut self, number: T, num_bits: usize) -> crate::Result<&mut Self>
    where
        T: NistCompactable + Numeric,
    {
        self.0.push_with_num_bits(number, num_bits)?;
        Ok(self)
    }

    pub fn extend_with_num_bits<T>(
        &mut self,
        values: impl Iterator<Item = T>,
        num_bits: usize,
    ) -> crate::Result<&mut Self>
    where
        T: NistCompactable + Numeric,
    {
        self.0.extend_with_num_bits(values, num_bits)?;
        Ok(self)
    }
}

use crate::core_crypto::algorithms::verify_lwe_compact_ciphertext_list;
use crate::high_level_api::compact_list::zk::InnerProvenCompactCiphertextList;
use crate::high_level_api::compact_list::InnerCompactCiphertextListExpander;
use crate::high_level_api::global_state;
use crate::integer::ciphertext::{DataKind, IntegerProvenCompactCiphertextListConformanceParams};
use crate::keys::InternalServerKeyRef;
use crate::prelude::ParameterSetConformant;
use crate::zk::{CompactPkeCrs, ZkComputeLoad, ZkPkeV2SupportedHashConfig};
use crate::CompactCiphertextListExpander;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use crate::high_level_api::nist_submission::backward_compatibility::ProvenCompactCiphertextListVersions;

#[derive(Clone, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(ProvenCompactCiphertextListVersions)]
pub struct ProvenCompactCiphertextList {
    inner: InnerProvenCompactCiphertextList,
    tag: crate::Tag,
}

impl crate::named::Named for ProvenCompactCiphertextList {
    const NAME: &'static str = "high_level_api::nist_submission::ProvenCompactCiphertextList";
}

impl ProvenCompactCiphertextList {
    pub fn builder(pk: &CompactPublicKey) -> CompactCiphertextListBuilder {
        CompactCiphertextListBuilder::new(pk)
    }

    pub fn into_raw_parts(
        self,
    ) -> (
        crate::integer::ciphertext::ProvenCompactCiphertextList,
        crate::Tag,
    ) {
        let Self { inner, tag } = self;
        #[allow(clippy::infallible_destructuring_match)]
        let integer_list = match inner {
            InnerProvenCompactCiphertextList::Cpu(cpu) => cpu,
            #[cfg(feature = "gpu")]
            InnerProvenCompactCiphertextList::Cuda(cuda) => cuda.h_proved_lists,
        };
        (integer_list, tag)
    }

    /// The `crs` must be conformant to [`new_compact_pke_crs_conformance_params`]
    /// as the expansion relies on the proofs to bound the blocks below the message modulus.
    ///
    /// [new_compact_pke_crs_conformance_params]: super::new_compact_pke_crs_conformance_params
    pub fn verify_and_expand(
        &self,
        crs: &CompactPkeCrs,
        pk: &CompactPublicKey,
        metadata: &[u8],
    ) -> crate::Result<CompactCiphertextListExpander> {
        global_state::try_with_internal_keys(|maybe_keys| {
            maybe_keys.map_or_else(
                || Err(crate::high_level_api::errors::UninitializedServerKey.into()),
                |internal_key| self.verify_and_expand_with_keys(crs, pk, metadata, internal_key),
            )
        })
    }

    pub fn expand_without_verification(&self) -> crate::Result<CompactCiphertextListExpander> {
        global_state::try_with_internal_keys(|maybe_keys| {
            maybe_keys.map_or_else(
                || Err(crate::high_level_api::errors::UninitializedServerKey.into()),
                |internal_key| self.expand_without_verification_with_keys(internal_key),
            )
        })
    }

    fn verify_and_expand_with_keys<'a>(
        &self,
        crs: &CompactPkeCrs,
        pk: &CompactPublicKey,
        metadata: &[u8],
        sks: impl Into<InternalServerKeyRef<'a>>,
    ) -> crate::Result<CompactCiphertextListExpander> {
        let cpu_inner = self.inner.on_cpu();
        let any_invalid = cpu_inner
            .ct_list
            .proved_lists
            .par_iter()
            .any(|(ct_list, proof)| {
                verify_lwe_compact_ciphertext_list(
                    &ct_list.ct_list,
                    &pk.key.key.key.key,
                    proof,
                    crs,
                    metadata,
                )
                .is_invalid()
            });

        if any_invalid {
            return Err(crate::ErrorKind::InvalidZkProof.into());
        }

        self.expand_without_verification_with_keys(sks)
    }

    fn expand_without_verification_with_keys<'a>(
        &self,
        sks: impl Into<InternalServerKeyRef<'a>>,
    ) -> crate::Result<CompactCiphertextListExpander> {
        let sks = sks.into();
        match sks {
            InternalServerKeyRef::Cpu(cpu_key) => {
                let cpu_inner = self.inner.on_cpu();
                let shortint_lists_iter = cpu_inner
                    .ct_list
                    .proved_lists
                    .iter()
                    .map(|(ct_list, _proof)| ct_list);

                let final_cts = expand_and_keyswitch(shortint_lists_iter, cpu_key)?;

                Ok(CompactCiphertextListExpander {
                    inner: InnerCompactCiphertextListExpander::Cpu(
                        crate::integer::ciphertext::CompactCiphertextListExpander::new(
                            final_cts,
                            cpu_inner.info.clone(),
                        ),
                    ),
                    tag: self.tag.clone(),
                })
            }
            #[cfg(feature = "gpu")]
            InternalServerKeyRef::Cuda(_) => {
                Err(crate::error!("GPU does not support NIST specific lists"))
            }
            #[cfg(feature = "hpu")]
            InternalServerKeyRef::Hpu(_) => Err(crate::error!("HPU does not support expand")),
        }
    }
}

impl CompactCiphertextListBuilder {
    pub fn build_with_proof(
        &self,
        crs: &CompactPkeCrs,
        metadata: &[u8],
        compute_load: ZkComputeLoad,
    ) -> crate::Result<ProvenCompactCiphertextList> {
        let shortint_proven_list = self.0.inner.pk.key.encrypt_and_prove_slice(
            &self.0.inner.messages,
            crs,
            metadata,
            compute_load,
            self.0.inner.pk.parameters().message_modulus.0,
        )?;

        Ok(ProvenCompactCiphertextList {
            inner: InnerProvenCompactCiphertextList::Cpu(
                crate::integer::ProvenCompactCiphertextList {
                    ct_list: shortint_proven_list,
                    info: self.0.inner.info.clone(),
                },
            ),
            tag: self.0.tag.clone(),
        })
    }

    pub fn build_with_proof_seeded(
        &self,
        crs: &CompactPkeCrs,
        metadata: &[u8],
        compute_load: ZkComputeLoad,
        seed: &[u8],
    ) -> crate::Result<ProvenCompactCiphertextList> {
        let shortint_proven_list = self.0.inner.pk.key.encrypt_and_prove_slice_seeded(
            &self.0.inner.messages,
            crs,
            metadata,
            compute_load,
            self.0.inner.pk.parameters().message_modulus.0,
            seed,
        )?;

        Ok(ProvenCompactCiphertextList {
            inner: InnerProvenCompactCiphertextList::Cpu(
                crate::integer::ProvenCompactCiphertextList {
                    ct_list: shortint_proven_list,
                    info: self.0.inner.info.clone(),
                },
            ),
            tag: self.0.tag.clone(),
        })
    }
}

/// Conformance parameters of a NIST [`ProvenCompactCiphertextList`]
///
/// On top of the regular checks, the list must not be packed and must only hold integers (see
/// [`NistCompactable`])
#[derive(Copy, Clone)]
pub struct ProvenCompactCiphertextListConformanceParams {
    inner: IntegerProvenCompactCiphertextListConformanceParams,
}

impl ProvenCompactCiphertextListConformanceParams {
    /// Conformance parameters of the lists encrypted with `params` and proven with `crs`
    pub fn from_crs_and_parameters(
        params: CompactPublicKeyEncryptionParameters,
        crs: &CompactPkeCrs,
    ) -> Self {
        Self {
            // Packed lists are refused by the NIST is_conformant
            inner: IntegerProvenCompactCiphertextListConformanceParams::from_crs_and_parameters(
                params, crs,
            )
            .allow_unpacked(),
        }
    }

    /// Forbid proofs coming with the provided [`ZkComputeLoad`]
    pub fn forbid_compute_load(self, forbidden_compute_load: ZkComputeLoad) -> Self {
        Self {
            inner: self.inner.forbid_compute_load(forbidden_compute_load),
        }
    }

    /// Forbid proofs coming with the provided [`ZkPkeV2SupportedHashConfig`]. This has no effect on
    /// PkeV1 proofs
    pub fn forbid_hash_config(self, forbidden_hash_config: ZkPkeV2SupportedHashConfig) -> Self {
        Self {
            inner: self.inner.forbid_hash_config(forbidden_hash_config),
        }
    }
}

impl ParameterSetConformant for ProvenCompactCiphertextList {
    type ParameterSet = ProvenCompactCiphertextListConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self { inner, tag: _ } = self;
        let inner = inner.on_cpu();

        let only_integers = inner
            .info
            .iter()
            .all(|kind| matches!(kind, DataKind::Unsigned(_) | DataKind::Signed(_)));

        // The integer conformance checks that all the lists are packed or none is, and that they
        // hold as many LWEs as the metadata describes blocks
        only_integers && !inner.is_packed() && inner.is_conformant(&parameter_set.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::high_level_api::nist_submission::parameters::{
        NIST_META_PARAMS_2_2, NIST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    };
    use crate::high_level_api::nist_submission::prelude::*;
    use crate::high_level_api::nist_submission::{
        set_server_key, FheInt64, FheUint16, FheUint2, FheUint32,
    };

    #[test]
    fn test_proven_compact_list() {
        use crate::high_level_api::nist_submission::{new_compact_pke_crs, ZkComputeLoad};

        let config = crate::Config::from(NIST_META_PARAMS_2_2);

        let ck = crate::ClientKey::generate(config);
        let sk = crate::ServerKey::new(&ck);
        let pk = crate::CompactPublicKey::new(&ck);

        // Intentionally low so that we test when multiple lists and proofs are needed
        let crs = new_compact_pke_crs(config, 32).unwrap();

        let metadata = *b"nist";

        let proven_list = ProvenCompactCiphertextList::builder(&pk)
            .push(17u32)
            .push(-1i64)
            .push_with_num_bits(3u32, 2)
            .unwrap()
            .build_with_proof(&crs, &metadata, ZkComputeLoad::Proof)
            .unwrap();

        set_server_key(sk);

        let expander = proven_list.verify_and_expand(&crs, &pk, &metadata).unwrap();

        {
            let a: FheUint32 = expander.get(0).unwrap().unwrap();
            let b: FheInt64 = expander.get(1).unwrap().unwrap();
            let c: FheUint2 = expander.get(2).unwrap().unwrap();

            let a: u32 = a.decrypt(&ck);
            assert_eq!(a, 17);
            let b: i64 = b.decrypt(&ck);
            assert_eq!(b, -1);
            let c: u8 = c.decrypt(&ck);
            assert_eq!(c, 3);

            assert!(expander.get::<FheUint2>(3).unwrap().is_none());
        }

        {
            // Incorrect type
            assert!(expander.get::<FheInt64>(0).is_err());

            // Correct type but wrong number of bits
            assert!(expander.get::<FheUint16>(0).is_err());
        }

        let unverified_expander = proven_list.expand_without_verification().unwrap();

        {
            let a: FheUint32 = unverified_expander.get(0).unwrap().unwrap();
            let b: FheInt64 = unverified_expander.get(1).unwrap().unwrap();
            let c: FheUint2 = unverified_expander.get(2).unwrap().unwrap();

            let a: u32 = a.decrypt(&ck);
            assert_eq!(a, 17);
            let b: i64 = b.decrypt(&ck);
            assert_eq!(b, -1);
            let c: u8 = c.decrypt(&ck);
            assert_eq!(c, 3);

            assert!(unverified_expander.get::<FheUint2>(3).unwrap().is_none());
        }
    }

    fn nist_conformance_params(
        crs: &CompactPkeCrs,
    ) -> ProvenCompactCiphertextListConformanceParams {
        ProvenCompactCiphertextListConformanceParams::from_crs_and_parameters(
            NIST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            crs,
        )
    }

    /// Conformance parameters of the regular lists, which accept the NIST lists
    fn integer_conformance_params(
        crs: &CompactPkeCrs,
    ) -> IntegerProvenCompactCiphertextListConformanceParams {
        IntegerProvenCompactCiphertextListConformanceParams::from_crs_and_parameters(
            NIST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            crs,
        )
        .allow_unpacked()
    }

    fn integer_list_mut(
        list: &mut ProvenCompactCiphertextList,
    ) -> &mut crate::integer::ProvenCompactCiphertextList {
        match &mut list.inner {
            InnerProvenCompactCiphertextList::Cpu(list) => list,
            #[cfg(feature = "gpu")]
            InnerProvenCompactCiphertextList::Cuda(_) => unreachable!(),
        }
    }

    #[test]
    fn test_nist_crs_conformance() {
        use crate::high_level_api::nist_submission::{
            new_compact_pke_crs, new_compact_pke_crs_conformance_params,
        };

        let config = crate::Config::from(NIST_META_PARAMS_2_2);
        let crs = new_compact_pke_crs(config, 32).unwrap();
        let conformance_params = new_compact_pke_crs_conformance_params(config, 32).unwrap();

        assert!(crs.is_conformant(&conformance_params));

        // The regular CRS only proves the padding bit
        let regular_crs = CompactPkeCrs::from_config(config, 32).unwrap();
        assert!(!regular_crs.is_conformant(&conformance_params));
    }

    /// The NIST expansion does not clean the blocks: the proofs must reject any block with a
    /// carry bit set, while honest blocks expand with a degree that bounds their value.
    #[test]
    fn test_nist_proofs_bound_blocks_below_message_modulus() {
        use crate::high_level_api::nist_submission::new_compact_pke_crs;

        let config = crate::Config::from(NIST_META_PARAMS_2_2);
        let ck = crate::ClientKey::generate(config);
        let sk = crate::ServerKey::new(&ck);
        let pk = crate::CompactPublicKey::new(&ck);
        let crs = new_compact_pke_crs(config, 32).unwrap();
        let metadata = *b"nist";
        set_server_key(sk);

        // A malicious client is not bound to the builder: overwrite the blocks it produced with
        // values it never would
        let mut builder = ProvenCompactCiphertextList::builder(&pk);
        builder.push(0u32);
        let num_blocks = builder.0.inner.messages.len();

        // message_modulus, message_modulus + 1, message_modulus * carry_modulus - 1
        for block_value in [4u64, 5, 15] {
            builder.0.inner.messages = vec![block_value; num_blocks];
            let proven_list = builder
                .build_with_proof(&crs, &metadata, ZkComputeLoad::Proof)
                .unwrap();
            assert!(proven_list.is_conformant(&nist_conformance_params(&crs)));

            assert!(
                proven_list.verify_and_expand(&crs, &pk, &metadata).is_err(),
                "a list with blocks of value {block_value} must not verify"
            );
        }

        // Only one block with a carry bit set
        builder.0.inner.messages = vec![0; num_blocks];
        builder.0.inner.messages[0] = 6;
        let proven_list = builder
            .build_with_proof(&crs, &metadata, ZkComputeLoad::Proof)
            .unwrap();
        assert!(proven_list.verify_and_expand(&crs, &pk, &metadata).is_err());

        // Every block at the largest honest value
        let proven_list = ProvenCompactCiphertextList::builder(&pk)
            .push(u32::MAX)
            .build_with_proof(&crs, &metadata, ZkComputeLoad::Proof)
            .unwrap();
        let expander = proven_list.verify_and_expand(&crs, &pk, &metadata).unwrap();
        let a: FheUint32 = expander.get(0).unwrap().unwrap();

        let clear_a: u32 = a.decrypt(&ck);
        assert_eq!(clear_a, u32::MAX);
        let sum: u32 = (&a + &a).decrypt(&ck);
        assert_eq!(sum, clear_a.wrapping_add(clear_a));

        let shortint_ck = ck.into_raw_parts().0.key;
        let (radix, _, _, _) = a.into_raw_parts();
        for block in radix.blocks.iter() {
            assert!(shortint_ck.decrypt_message_and_carry(block) <= block.degree.get());
        }
    }

    /// The NIST expansion maps each LWE to a block, packed lists must not be conformant
    #[test]
    fn test_nist_packed_list_is_not_conformant() {
        use crate::high_level_api::nist_submission::new_compact_pke_crs;

        let config = crate::Config::from(NIST_META_PARAMS_2_2);
        let ck = crate::ClientKey::generate(config);
        let pk = crate::CompactPublicKey::new(&ck);
        let crs = new_compact_pke_crs(config, 32).unwrap();
        let metadata = *b"nist";

        let proven_list = ProvenCompactCiphertextList::builder(&pk)
            .push(17u32)
            .build_with_proof(&crs, &metadata, ZkComputeLoad::Proof)
            .unwrap();
        assert!(proven_list.is_conformant(&nist_conformance_params(&crs)));

        // Claim the 16 LWEs are 32 packed blocks: two FheUint32
        let mut packed_list = proven_list;
        let list = integer_list_mut(&mut packed_list);
        list.info.push(DataKind::Unsigned(16.try_into().unwrap()));
        for (ct_list, _proof) in list.ct_list.proved_lists.iter_mut() {
            ct_list.degree = Degree::new(ct_list.message_modulus.0 * ct_list.message_modulus.0 - 1);
        }

        // Fine for the regular lists, not for NIST ones
        assert!(packed_list
            .inner
            .on_cpu()
            .is_conformant(&integer_conformance_params(&crs)));
        assert!(!packed_list.is_conformant(&nist_conformance_params(&crs)));
    }

    /// The NIST expansion cannot bound booleans to 0 or 1, nor ASCII characters below 128: lists
    /// holding them must not be conformant
    #[test]
    fn test_nist_non_integer_list_is_not_conformant() {
        use crate::high_level_api::nist_submission::new_compact_pke_crs;

        let config = crate::Config::from(NIST_META_PARAMS_2_2);
        let ck = crate::ClientKey::generate(config);
        let pk = crate::CompactPublicKey::new(&ck);
        let crs = new_compact_pke_crs(config, 32).unwrap();
        let metadata = *b"nist";

        // A boolean is 1 block, an ASCII character is 4 blocks with 2_2 parameters
        let cases = [
            (2, DataKind::Boolean),
            (
                8,
                DataKind::String {
                    n_chars: 1,
                    padded: false,
                },
            ),
        ];

        for (num_bits, kind) in cases {
            let proven_list = ProvenCompactCiphertextList::builder(&pk)
                .push_with_num_bits(1u8, num_bits)
                .unwrap()
                .build_with_proof(&crs, &metadata, ZkComputeLoad::Proof)
                .unwrap();
            assert!(proven_list.is_conformant(&nist_conformance_params(&crs)));

            let mut non_integer_list = proven_list;
            integer_list_mut(&mut non_integer_list).info = vec![kind];

            // Fine for the regular lists, not for NIST ones
            assert!(non_integer_list
                .inner
                .on_cpu()
                .is_conformant(&integer_conformance_params(&crs)));
            assert!(
                !non_integer_list.is_conformant(&nist_conformance_params(&crs)),
                "{kind:?}"
            );
        }
    }
}
