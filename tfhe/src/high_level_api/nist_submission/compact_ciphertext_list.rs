use crate::core_crypto::prelude::{LweCiphertext, LweCiphertextList, Numeric};
use crate::high_level_api::compact_list::InnerCompactCiphertextList;
use crate::high_level_api::{
    global_state, CompactCiphertextList as InnerList, CompactCiphertextListBuilder as InnerBuilder,
};
use crate::keys::InternalServerKeyRef;
use crate::named::Named;
use crate::prelude::{ParameterSetConformant, Tagged};
use crate::shortint::atomic_pattern::AtomicPattern;
use crate::shortint::parameters::{Degree, NoiseLevel};
use crate::shortint::Ciphertext;
use crate::{
    CompactCiphertextListConformanceParams, CompactCiphertextListExpander, CompactPublicKey,
    HlCompactable, Tag,
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use crate::high_level_api::ServerKey as HlServerKey;
use crate::shortint::ciphertext::CompactCiphertextList as ShortintCompactCiphertextList;

/// Does the expand + keyswitch as per NIST submission documents
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

        // No parallelism allowed
        #[cfg(all(feature = "__wasm_api", not(feature = "parallel-wasm-api")))]
        {
            use crate::core_crypto::prelude::expand_lwe_compact_ciphertext_list;
            expand_lwe_compact_ciphertext_list(
                &mut expanded_lwe_ciphertext_list,
                &shortint_list.ct_list,
            );
            expanded_lwe_ciphertext_list
                .iter()
                .zip(ct_chunk.iter_mut())
                .for_each(|(expanded, key_switched)| {
                    use crate::core_crypto::prelude::keyswitch_lwe_ciphertext;

                    keyswitch_lwe_ciphertext(
                        casting_key.key_switching_key_material.key_switching_key,
                        &expanded,
                        &mut key_switched.ct,
                    );
                });
        }

        // Parallelism allowed
        #[cfg(any(not(feature = "__wasm_api"), feature = "parallel-wasm-api"))]
        {
            use crate::core_crypto::prelude::{
                par_expand_lwe_compact_ciphertext_list, ContiguousEntityContainer,
            };
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
    }

    Ok(out_collection)
}

use super::backward_compatibility::CompactCiphertextListVersions;

#[derive(Clone, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(CompactCiphertextListVersions)]
pub struct CompactCiphertextList(InnerList);

impl Named for CompactCiphertextList {
    const NAME: &'static str = "high_level_api::nist_submission::CompactCiphertextList";
}

impl CompactCiphertextList {
    pub fn builder(pk: &CompactPublicKey) -> CompactCiphertextListBuilder {
        CompactCiphertextListBuilder::new(pk)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn get_kind_of(&self, index: usize) -> Option<crate::FheTypes> {
        self.0.get_kind_of(index)
    }

    pub fn expand_with_key<'a>(
        &self,
        sks: impl Into<InternalServerKeyRef<'a>>,
    ) -> crate::Result<CompactCiphertextListExpander> {
        let sks = sks.into();
        match (&self.0.inner, sks) {
            (InnerCompactCiphertextList::Cpu(cpu_inner), InternalServerKeyRef::Cpu(cpu_key)) => {
                let final_cts = expand_and_keyswitch(std::iter::once(&cpu_inner.ct_list), cpu_key)?;

                Ok(CompactCiphertextListExpander {
                    inner:
                        crate::high_level_api::compact_list::InnerCompactCiphertextListExpander::Cpu(
                            crate::integer::ciphertext::CompactCiphertextListExpander::new(
                                final_cts,
                                cpu_inner.info.clone(),
                            ),
                        ),
                    tag: self.0.tag.clone(),
                })
            }
            #[cfg(feature = "gpu")]
            (InnerCompactCiphertextList::Cuda(gpu_inner), InternalServerKeyRef::Cpu(cpu_key)) => {
                // CUDA data, CPU key case
                // We copy data to CPU and then expand it

                use crate::high_level_api::global_state::with_cuda_internal_keys;
                let cpu_inner = with_cuda_internal_keys(|cuda_key| {
                    let streams = &cuda_key.streams;
                    gpu_inner.to_integer_compact_ciphertext_list(streams)
                })?;

                let final_cts = expand_and_keyswitch(std::iter::once(&cpu_inner.ct_list), cpu_key)?;

                Ok(CompactCiphertextListExpander {
                    inner:
                        crate::high_level_api::compact_list::InnerCompactCiphertextListExpander::Cpu(
                            crate::integer::ciphertext::CompactCiphertextListExpander::new(
                                final_cts,
                                cpu_inner.info,
                            ),
                        ),
                    tag: self.0.tag.clone(),
                })
            }
            #[cfg(feature = "gpu")]
            (_, InternalServerKeyRef::Cuda(_)) => {
                // NIST does not pack data, GPU only supports packed
                Err(crate::error!("GPU does not support NIST specific lists"))
            }
            #[cfg(feature = "hpu")]
            (_, InternalServerKeyRef::Hpu(_)) => Err(crate::error!("HPU does not support expand")),
        }
    }

    pub fn expand(&self) -> crate::Result<CompactCiphertextListExpander> {
        global_state::try_with_internal_keys(|maybe_keys| {
            maybe_keys.map_or_else(
                || Err(crate::high_level_api::errors::UninitializedServerKey.into()),
                |internal_key| self.expand_with_key(internal_key),
            )
        })
    }
}

impl Tagged for CompactCiphertextList {
    fn tag(&self) -> &Tag {
        &self.0.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.0.tag
    }
}

impl ParameterSetConformant for CompactCiphertextList {
    type ParameterSet = CompactCiphertextListConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        self.0.is_conformant(parameter_set)
    }
}

pub struct CompactCiphertextListBuilder(InnerBuilder);

impl CompactCiphertextListBuilder {
    pub fn new(pk: &CompactPublicKey) -> Self {
        Self(InnerBuilder::new(pk))
    }

    pub fn push<T>(&mut self, value: T) -> &mut Self
    where
        T: HlCompactable,
    {
        self.0.push(value);
        self
    }

    pub fn extend<T>(&mut self, values: impl Iterator<Item = T>) -> &mut Self
    where
        T: HlCompactable,
    {
        self.0.extend(values);
        self
    }

    pub fn push_with_num_bits<T>(&mut self, number: T, num_bits: usize) -> crate::Result<&mut Self>
    where
        T: HlCompactable + Numeric,
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
        T: HlCompactable + Numeric,
    {
        self.0.extend_with_num_bits(values, num_bits)?;
        Ok(self)
    }

    pub fn build(&self) -> CompactCiphertextList {
        CompactCiphertextList(self.0.build())
    }
}

#[cfg(feature = "zk-pok")]
mod zk_pok {
    use crate::core_crypto::algorithms::verify_lwe_compact_ciphertext_list;
    use crate::high_level_api::compact_list::zk::InnerProvenCompactCiphertextList;
    use crate::high_level_api::compact_list::InnerCompactCiphertextListExpander;
    use crate::high_level_api::global_state;
    use crate::integer::ciphertext::IntegerProvenCompactCiphertextListConformanceParams;
    use crate::keys::InternalServerKeyRef;
    use crate::prelude::ParameterSetConformant;
    use crate::zk::{CompactPkeCrs, ZkComputeLoad};
    use crate::{CompactCiphertextListExpander, CompactPublicKey};
    use rayon::prelude::*;
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
        pub fn into_raw_parts(
            self,
        ) -> (
            crate::integer::ciphertext::ProvenCompactCiphertextList,
            crate::Tag,
        ) {
            let Self { inner, tag } = self;
            let integer_list = match inner {
                InnerProvenCompactCiphertextList::Cpu(cpu) => cpu,
                #[cfg(feature = "gpu")]
                InnerProvenCompactCiphertextList::Cuda(cuda) => cuda.h_proved_lists,
            };
            (integer_list, tag)
        }

        pub fn verify_and_expand(
            &self,
            crs: &CompactPkeCrs,
            pk: &CompactPublicKey,
            metadata: &[u8],
        ) -> crate::Result<CompactCiphertextListExpander> {
            global_state::try_with_internal_keys(|maybe_keys| {
                maybe_keys.map_or_else(
                    || Err(crate::high_level_api::errors::UninitializedServerKey.into()),
                    |internal_key| {
                        self.verify_and_expand_with_keys(crs, pk, metadata, internal_key)
                    },
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

                    let final_cts = super::expand_and_keyswitch(shortint_lists_iter, cpu_key)?;

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

    impl super::CompactCiphertextListBuilder {
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

    impl ParameterSetConformant for ProvenCompactCiphertextList {
        type ParameterSet = IntegerProvenCompactCiphertextListConformanceParams;

        fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
            self.inner.on_cpu().is_conformant(parameter_set)
        }
    }
}
#[cfg(feature = "zk-pok")]
pub use zk_pok::ProvenCompactCiphertextList;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::high_level_api::nist_submission::parameters::{
        NIST_PARAM_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M128,
        NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        NIST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    };
    use crate::high_level_api::nist_submission::prelude::*;
    use crate::high_level_api::nist_submission::{
        set_server_key, FheBool, FheInt64, FheUint16, FheUint2, FheUint32,
    };

    #[test]
    fn test_compact_list_with_casting_inner() {
        let config = crate::ConfigBuilder::with_custom_parameters(
            NIST_PARAM_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M128,
        )
        .use_dedicated_compact_public_key_parameters((
            NIST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
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
            .build();

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

    #[test]
    fn test_compact_list_with_global_key() {
        let config = crate::ConfigBuilder::with_custom_parameters(
            NIST_PARAM_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M128,
        )
        .use_dedicated_compact_public_key_parameters((
            NIST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        ))
        .build();

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
            .build();

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
    fn test_empty_list() {
        let config = crate::ConfigBuilder::with_custom_parameters(
            NIST_PARAM_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M128,
        )
        .use_dedicated_compact_public_key_parameters((
            NIST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        ))
        .build();

        let ck = crate::ClientKey::generate(config);
        let sk = crate::ServerKey::new(&ck);
        let pk = crate::CompactPublicKey::new(&ck);

        set_server_key(sk);

        let compact_list = CompactCiphertextList::builder(&pk).build();

        let expander = compact_list.expand().unwrap();

        assert!(expander.get::<FheBool>(0).unwrap().is_none());
    }

    #[cfg(feature = "zk-pok")]
    #[test]
    fn test_proven_compact_list() {
        use crate::high_level_api::nist_submission::{CompactPkeCrs, ZkComputeLoad};

        let config = crate::ConfigBuilder::with_custom_parameters(
            NIST_PARAM_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M128,
        )
        .use_dedicated_compact_public_key_parameters((
            NIST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        ))
        .build();

        let ck = crate::ClientKey::generate(config);
        let sk = crate::ServerKey::new(&ck);
        let pk = crate::CompactPublicKey::new(&ck);

        // Intentionally low so that we test when multiple lists and proofs are needed
        let crs = CompactPkeCrs::from_config(config, 32).unwrap();

        let metadata = [b'n', b'i', b's', b't'];

        let proven_list = CompactCiphertextList::builder(&pk)
            .push(17u32)
            .push(-1i64)
            .push(false)
            .push_with_num_bits(3u32, 2)
            .unwrap()
            .build_with_proof(&crs, &metadata, ZkComputeLoad::Proof)
            .unwrap();

        set_server_key(sk);

        let expander = proven_list.verify_and_expand(&crs, &pk, &metadata).unwrap();

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

        let unverified_expander = proven_list.expand_without_verification().unwrap();

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

    #[cfg(feature = "extended-types")]
    #[test]
    fn test_compact_list_extended_types() {
        let config = crate::ConfigBuilder::with_custom_parameters(
            NIST_PARAM_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M128,
        )
        .use_dedicated_compact_public_key_parameters((
            NIST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        ))
        .build();

        let ck = crate::ClientKey::generate(config);
        let sk = crate::ServerKey::new(&ck);
        let pk = crate::CompactPublicKey::new(&ck);

        set_server_key(sk);

        let compact_list = CompactCiphertextList::builder(&pk)
            .push_with_num_bits(-17i64, 40)
            .unwrap()
            .push_with_num_bits(3u8, 24)
            .unwrap()
            .build();

        let expander = compact_list.expand().unwrap();

        {
            let a: crate::FheInt40 = expander.get(0).unwrap().unwrap();
            let b: crate::FheUint24 = expander.get(1).unwrap().unwrap();

            let a: i64 = a.decrypt(&ck);
            assert_eq!(a, -17);
            let b: u8 = b.decrypt(&ck);
            assert_eq!(b, 3);
        }

        {
            // Incorrect type
            assert!(expander.get::<FheUint32>(0).is_err());

            // Correct type but wrong number of bits
            assert!(expander.get::<FheInt64>(0).is_err());
        }
    }
}
