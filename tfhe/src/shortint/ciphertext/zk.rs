use super::Degree;
use crate::conformance::{ListSizeConstraint, ParameterSetConformant};
use crate::core_crypto::algorithms::verify_lwe_compact_ciphertext_list;
use crate::core_crypto::prelude::{LweCiphertextCount, LweCiphertextListParameters};
use crate::shortint::backward_compatibility::ciphertext::ProvenCompactCiphertextListVersions;
use crate::shortint::ciphertext::CompactCiphertextList;
use crate::shortint::parameters::{
    CarryModulus, CiphertextListConformanceParams, CiphertextModulus,
    CompactCiphertextListExpansionKind, CompactPublicKeyEncryptionParameters, LweDimension,
    MessageModulus, ShortintCompactCiphertextListCastingMode, SupportedCompactPkeZkScheme,
};
use crate::shortint::{Ciphertext, CompactPublicKey};
use crate::zk::{
    CompactPkeCrs, CompactPkeProof, CompactPkeZkScheme, ZkMSBZeroPaddingBitCount,
    ZkVerificationOutcome,
};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

impl CompactPkeCrs {
    /// Construct the CRS that corresponds to the given parameters
    ///
    /// max_num_message is how many message a single proof can prove.
    /// The version of the zk scheme is based on the [`CompactPkeZkScheme`] value in the params.
    pub fn from_shortint_params<P, E>(
        params: P,
        max_num_message: LweCiphertextCount,
    ) -> crate::Result<Self>
    where
        P: TryInto<CompactPublicKeyEncryptionParameters, Error = E>,
        crate::Error: From<E>,
    {
        let params: CompactPublicKeyEncryptionParameters = params.try_into()?;
        let (size, noise_distribution) = (
            params.encryption_lwe_dimension,
            params.encryption_noise_distribution,
        );

        let mut plaintext_modulus = params.message_modulus.0 * params.carry_modulus.0;
        // Our plaintext modulus does not take into account the bit of padding
        plaintext_modulus *= 2;

        // 1 padding bit for the PBS
        // Note that if we want to we can prove carry bits are 0 should we need it
        crate::shortint::engine::ShortintEngine::with_thread_local_mut(|engine| {
            match params.zk_scheme {
                SupportedCompactPkeZkScheme::V1 => Self::new_legacy_v1(
                    size,
                    max_num_message,
                    noise_distribution,
                    params.ciphertext_modulus,
                    plaintext_modulus,
                    ZkMSBZeroPaddingBitCount(1),
                    &mut engine.random_generator,
                ),
                SupportedCompactPkeZkScheme::V2 => Self::new(
                    size,
                    max_num_message,
                    noise_distribution,
                    params.ciphertext_modulus,
                    plaintext_modulus,
                    ZkMSBZeroPaddingBitCount(1),
                    &mut engine.random_generator,
                ),
                SupportedCompactPkeZkScheme::ZkNotSupported => {
                    Err("Zk proof of encryption is not supported by the provided parameters".into())
                }
            }
        })
    }
}

/// A List of CompactCiphertext with their zero-knowledge proofs
///
/// The proofs can only be generated during the encryption with a [CompactPublicKey]
#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(ProvenCompactCiphertextListVersions)]
pub struct ProvenCompactCiphertextList {
    pub(crate) proved_lists: Vec<(CompactCiphertextList, CompactPkeProof)>,
}

impl ProvenCompactCiphertextList {
    pub fn ciphertext_count(&self) -> usize {
        self.proved_lists
            .iter()
            .map(|(list, _)| list.ct_list.lwe_ciphertext_count().0)
            .sum()
    }

    pub fn verify_and_expand(
        &self,
        crs: &CompactPkeCrs,
        public_key: &CompactPublicKey,
        metadata: &[u8],
        casting_mode: ShortintCompactCiphertextListCastingMode<'_>,
    ) -> crate::Result<Vec<Ciphertext>> {
        let not_all_valid = self.proved_lists.par_iter().any(|(ct_list, proof)| {
            verify_lwe_compact_ciphertext_list(
                &ct_list.ct_list,
                &public_key.key,
                proof,
                crs,
                metadata,
            )
            .is_invalid()
        });

        if not_all_valid {
            return Err(crate::ErrorKind::InvalidZkProof.into());
        }

        // We can call the function as we have verified the proofs
        self.expand_without_verification(casting_mode)
    }

    #[doc(hidden)]
    /// This function allows to expand a ciphertext without verifying the associated proof.
    ///
    /// If you are here you were probably looking for it: use at your own risks.
    pub fn expand_without_verification(
        &self,
        casting_mode: ShortintCompactCiphertextListCastingMode<'_>,
    ) -> crate::Result<Vec<Ciphertext>> {
        let per_list_casting_mode: Vec<_> = match casting_mode {
            ShortintCompactCiphertextListCastingMode::CastIfNecessary {
                casting_key,
                functions,
            } => match functions {
                Some(functions) => {
                    // For how many ciphertexts we have functions
                    let functions_sets_count = functions.len();
                    let total_ciphertext_count: usize = self
                        .proved_lists
                        .iter()
                        .map(|list| list.0.ct_list.lwe_ciphertext_count().0)
                        .sum();

                    if functions_sets_count != total_ciphertext_count {
                        return Err(crate::Error::new(format!(
                            "Cannot expand a CompactCiphertextList: got {functions_sets_count} \
                            sets of functions for casting, expected {total_ciphertext_count}"
                        )));
                    }

                    let mut modes = vec![];
                    let mut functions_used_so_far = 0;
                    for list in self.proved_lists.iter() {
                        let blocks_in_list = list.0.ct_list.lwe_ciphertext_count().0;

                        let functions_to_use = &functions
                            [functions_used_so_far..functions_used_so_far + blocks_in_list];

                        modes.push(ShortintCompactCiphertextListCastingMode::CastIfNecessary {
                            casting_key,
                            functions: Some(functions_to_use),
                        });

                        functions_used_so_far += blocks_in_list;
                    }
                    modes
                }
                None => vec![
                    ShortintCompactCiphertextListCastingMode::NoCasting;
                    self.proved_lists.len()
                ],
            },
            ShortintCompactCiphertextListCastingMode::NoCasting => {
                vec![ShortintCompactCiphertextListCastingMode::NoCasting; self.proved_lists.len()]
            }
        };
        let expanded = self
            .proved_lists
            .iter()
            .zip(per_list_casting_mode.into_iter())
            .map(|((ct_list, _proof), casting_mode)| ct_list.expand(casting_mode))
            .collect::<Result<Vec<Vec<_>>, _>>()?
            .into_iter()
            .flatten()
            .collect();

        Ok(expanded)
    }

    pub fn verify(
        &self,
        crs: &CompactPkeCrs,
        public_key: &CompactPublicKey,
        metadata: &[u8],
    ) -> ZkVerificationOutcome {
        let all_valid = self.proved_lists.par_iter().all(|(ct_list, proof)| {
            verify_lwe_compact_ciphertext_list(
                &ct_list.ct_list,
                &public_key.key,
                proof,
                crs,
                metadata,
            )
            .is_valid()
        });

        if all_valid {
            ZkVerificationOutcome::Valid
        } else {
            ZkVerificationOutcome::Invalid
        }
    }

    pub fn proof_size(&self) -> usize {
        self.proved_lists.len() * core::mem::size_of::<CompactPkeProof>()
    }

    pub fn message_modulus(&self) -> MessageModulus {
        self.proved_lists[0].0.message_modulus
    }
}

#[derive(Copy, Clone)]
pub struct ProvenCompactCiphertextListConformanceParams {
    pub encryption_lwe_dimension: LweDimension,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub ciphertext_modulus: CiphertextModulus,
    pub expansion_kind: CompactCiphertextListExpansionKind,
    pub max_lwe_count_per_compact_list: usize,
    pub total_expected_lwe_count: usize,
    pub zk_scheme: CompactPkeZkScheme,
}

impl ParameterSetConformant for ProvenCompactCiphertextList {
    type ParameterSet = ProvenCompactCiphertextListConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self { proved_lists } = self;

        let ProvenCompactCiphertextListConformanceParams {
            max_lwe_count_per_compact_list,
            total_expected_lwe_count,
            expansion_kind,
            encryption_lwe_dimension,
            message_modulus,
            carry_modulus,
            ciphertext_modulus,
            zk_scheme,
        } = parameter_set;

        let max_elements_per_compact_list = *max_lwe_count_per_compact_list;

        let mut remaining_len = *total_expected_lwe_count;

        for (compact_ct_list, proof) in proved_lists {
            if !proof.is_conformant(zk_scheme) {
                return false;
            }

            if remaining_len == 0 {
                return false;
            }

            let expected_len;

            if remaining_len > max_elements_per_compact_list {
                remaining_len -= max_elements_per_compact_list;

                expected_len = max_elements_per_compact_list;
            } else {
                expected_len = remaining_len;
                remaining_len = 0;
            };

            let params = CiphertextListConformanceParams {
                ct_list_params: LweCiphertextListParameters {
                    lwe_dim: *encryption_lwe_dimension,
                    lwe_ciphertext_count_constraint: ListSizeConstraint::exact_size(expected_len),
                    ct_modulus: *ciphertext_modulus,
                },
                message_modulus: *message_modulus,
                carry_modulus: *carry_modulus,
                degree: Degree::new(message_modulus.0 * message_modulus.0 - 1),
                expansion_kind: *expansion_kind,
            };

            if !compact_ct_list.is_conformant(&params) {
                return false;
            }
        }

        if remaining_len != 0 {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use crate::core_crypto::prelude::LweCiphertextCount;
    use crate::shortint::parameters::compact_public_key_only::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    use crate::shortint::parameters::key_switching::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    use crate::shortint::parameters::{
        ShortintCompactCiphertextListCastingMode, PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    };
    use crate::shortint::{
        ClientKey, CompactPrivateKey, CompactPublicKey, KeySwitchingKey, ServerKey,
    };
    use crate::zk::{CompactPkeCrs, ZkComputeLoad};
    use rand::random;

    #[test]
    fn test_zk_ciphertext_encryption_ci_run_filter() {
        let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        let pke_params = V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        let ksk_params = V0_11_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

        let crs = CompactPkeCrs::from_shortint_params(pke_params, LweCiphertextCount(4)).unwrap();
        let priv_key = CompactPrivateKey::new(pke_params);
        let pub_key = CompactPublicKey::new(&priv_key);
        let ck = ClientKey::new(params);
        let sk = ServerKey::new(&ck);
        let ksk = KeySwitchingKey::new((&priv_key, None), (&ck, &sk), ksk_params);

        let id = |x: u64| x;
        let dyn_id: &(dyn Fn(u64) -> u64 + Sync) = &id;

        let functions = vec![Some(vec![dyn_id; 1]); 1];

        let metadata = [b's', b'h', b'o', b'r', b't', b'i', b'n', b't'];

        let msg = random::<u64>() % pke_params.message_modulus.0;
        // No packing
        let encryption_modulus = pke_params.message_modulus.0;

        let proven_ct = pub_key
            .encrypt_and_prove(
                msg,
                &crs,
                &metadata,
                ZkComputeLoad::Proof,
                encryption_modulus,
            )
            .unwrap();

        {
            let unproven_ct = proven_ct.expand_without_verification(
                ShortintCompactCiphertextListCastingMode::CastIfNecessary {
                    casting_key: ksk.as_view(),
                    functions: Some(functions.as_slice()),
                },
            );
            let unproven_ct = unproven_ct.unwrap();

            let decrypted = ck.decrypt(&unproven_ct[0]);
            assert_eq!(msg, decrypted);
        }

        let proven_ct = proven_ct.verify_and_expand(
            &crs,
            &pub_key,
            &metadata,
            ShortintCompactCiphertextListCastingMode::CastIfNecessary {
                casting_key: ksk.as_view(),
                functions: Some(functions.as_slice()),
            },
        );
        let proven_ct = proven_ct.unwrap();

        let decrypted = ck.decrypt(&proven_ct[0]);
        assert_eq!(msg, decrypted);
    }

    #[test]
    fn test_zk_compact_ciphertext_list_encryption_ci_run_filter() {
        let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        let pke_params = V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        let ksk_params = V0_11_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

        let crs = CompactPkeCrs::from_shortint_params(pke_params, LweCiphertextCount(4)).unwrap();
        let priv_key = CompactPrivateKey::new(pke_params);
        let pub_key = CompactPublicKey::new(&priv_key);
        let ck = ClientKey::new(params);
        let sk = ServerKey::new(&ck);
        let ksk = KeySwitchingKey::new((&priv_key, None), (&ck, &sk), ksk_params);

        let id = |x: u64| x;
        let dyn_id: &(dyn Fn(u64) -> u64 + Sync) = &id;

        let functions = vec![Some(vec![dyn_id; 1]); 512];

        let metadata = [b's', b'h', b'o', b'r', b't', b'i', b'n', b't'];

        let msgs = (0..512)
            .map(|_| random::<u64>() % params.message_modulus.0)
            .collect::<Vec<_>>();

        let proven_ct = pub_key
            .encrypt_and_prove_slice(
                &msgs,
                &crs,
                &metadata,
                ZkComputeLoad::Proof,
                params.message_modulus.0,
            )
            .unwrap();
        assert!(proven_ct.verify(&crs, &pub_key, &metadata).is_valid());

        let expanded = proven_ct
            .verify_and_expand(
                &crs,
                &pub_key,
                &metadata,
                ShortintCompactCiphertextListCastingMode::CastIfNecessary {
                    casting_key: ksk.as_view(),
                    functions: Some(functions.as_slice()),
                },
            )
            .unwrap();
        let decrypted = expanded
            .iter()
            .map(|ciphertext| ck.decrypt(ciphertext))
            .collect::<Vec<_>>();
        assert_eq!(msgs, decrypted);
    }
}
