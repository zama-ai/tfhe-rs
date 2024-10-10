use super::{Degree, NoiseLevel};
use crate::conformance::{ListSizeConstraint, ParameterSetConformant};
use crate::core_crypto::algorithms::verify_lwe_compact_ciphertext_list;
use crate::core_crypto::prelude::LweCiphertextListParameters;
use crate::shortint::backward_compatibility::ciphertext::ProvenCompactCiphertextListVersions;
use crate::shortint::ciphertext::CompactCiphertextList;
use crate::shortint::parameters::{
    CarryModulus, CiphertextListConformanceParams, CiphertextModulus,
    CompactCiphertextListExpansionKind, CompactPublicKeyEncryptionParameters, LweDimension,
    MessageModulus, ShortintCompactCiphertextListCastingMode,
};
use crate::shortint::{Ciphertext, CompactPublicKey};
use crate::zk::{
    CompactPkeCrs, CompactPkeProof, CompactPkePublicParams, ZkMSBZeroPaddingBitCount,
    ZkVerificationOutCome,
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

impl CompactPkeCrs {
    /// Construct the CRS that corresponds to the given parameters
    ///
    /// max_num_message is how many message a single proof can prove
    pub fn from_shortint_params<P, E>(params: P, max_num_message: usize) -> crate::Result<Self>
    where
        P: TryInto<CompactPublicKeyEncryptionParameters, Error = E>,
        crate::Error: From<E>,
    {
        let params: CompactPublicKeyEncryptionParameters = params.try_into()?;
        let (size, noise_distribution) = (
            params.encryption_lwe_dimension,
            params.encryption_noise_distribution,
        );

        let mut plaintext_modulus = (params.message_modulus.0 * params.carry_modulus.0) as u64;
        // Our plaintext modulus does not take into account the bit of padding
        plaintext_modulus *= 2;

        // 1 padding bit for the PBS
        // Note that if we want to we can prove carry bits are 0 should we need it
        crate::shortint::engine::ShortintEngine::with_thread_local_mut(|engine| {
            Self::new(
                size,
                max_num_message,
                noise_distribution,
                params.ciphertext_modulus,
                plaintext_modulus,
                ZkMSBZeroPaddingBitCount(1),
                &mut engine.random_generator,
            )
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
        public_params: &CompactPkePublicParams,
        public_key: &CompactPublicKey,
        metadata: &[u8],
        casting_mode: ShortintCompactCiphertextListCastingMode<'_>,
    ) -> crate::Result<Vec<Ciphertext>> {
        let not_all_valid = self.proved_lists.par_iter().any(|(ct_list, proof)| {
            verify_lwe_compact_ciphertext_list(
                &ct_list.ct_list,
                &public_key.key,
                proof,
                public_params,
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
        public_params: &CompactPkePublicParams,
        public_key: &CompactPublicKey,
        metadata: &[u8],
    ) -> ZkVerificationOutCome {
        let all_valid = self.proved_lists.par_iter().all(|(ct_list, proof)| {
            verify_lwe_compact_ciphertext_list(
                &ct_list.ct_list,
                &public_key.key,
                proof,
                public_params,
                metadata,
            )
            .is_valid()
        });

        if all_valid {
            ZkVerificationOutCome::Valid
        } else {
            ZkVerificationOutCome::Invalid
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
        } = parameter_set;

        let max_elements_per_compact_list = *max_lwe_count_per_compact_list;

        let mut remaining_len = *total_expected_lwe_count;

        for (compact_ct_list, _proof) in proved_lists {
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
                noise_level: NoiseLevel::NOMINAL,
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
    use crate::shortint::parameters::{
        ShortintCompactCiphertextListCastingMode, PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    };
    use crate::shortint::{ClientKey, CompactPublicKey};
    use crate::zk::{CompactPkeCrs, ZkComputeLoad};
    use rand::random;

    #[test]
    fn test_zk_ciphertext_encryption_ci_run_filter() {
        let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

        let crs = CompactPkeCrs::from_shortint_params(params, 4).unwrap();
        let cks = ClientKey::new(params);
        let pk = CompactPublicKey::new(&cks);

        let metadata = [b's', b'h', b'o', b'r', b't', b'i', b'n', b't'];

        let msg = random::<u64>() % params.message_modulus.0 as u64;
        // No packing
        let encryption_modulus = params.message_modulus.0 as u64;

        let proven_ct = pk
            .encrypt_and_prove(
                msg,
                crs.public_params(),
                &metadata,
                ZkComputeLoad::Proof,
                encryption_modulus,
            )
            .unwrap();

        {
            let unproven_ct = proven_ct
                .expand_without_verification(ShortintCompactCiphertextListCastingMode::NoCasting);
            assert!(unproven_ct.is_ok());
            let unproven_ct = unproven_ct.unwrap();

            let decrypted = cks.decrypt(&unproven_ct[0]);
            assert_eq!(msg, decrypted);
        }

        let proven_ct = proven_ct.verify_and_expand(
            crs.public_params(),
            &pk,
            &metadata,
            ShortintCompactCiphertextListCastingMode::NoCasting,
        );
        assert!(proven_ct.is_ok());
        let proven_ct = proven_ct.unwrap();

        let decrypted = cks.decrypt(&proven_ct[0]);
        assert_eq!(msg, decrypted);
    }

    #[test]
    fn test_zk_compact_ciphertext_list_encryption_ci_run_filter() {
        let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

        let crs = CompactPkeCrs::from_shortint_params(params, 512).unwrap();
        let cks = ClientKey::new(params);
        let pk = CompactPublicKey::new(&cks);

        let metadata = [b's', b'h', b'o', b'r', b't', b'i', b'n', b't'];

        let msgs = (0..512)
            .map(|_| random::<u64>() % params.message_modulus.0 as u64)
            .collect::<Vec<_>>();

        let proven_ct = pk
            .encrypt_and_prove_slice(
                &msgs,
                crs.public_params(),
                &metadata,
                ZkComputeLoad::Proof,
                params.message_modulus.0 as u64,
            )
            .unwrap();
        assert!(proven_ct
            .verify(crs.public_params(), &pk, &metadata)
            .is_valid());

        let expanded = proven_ct
            .verify_and_expand(
                crs.public_params(),
                &pk,
                &metadata,
                ShortintCompactCiphertextListCastingMode::NoCasting,
            )
            .unwrap();
        let decrypted = expanded
            .iter()
            .map(|ciphertext| cks.decrypt(ciphertext))
            .collect::<Vec<_>>();
        assert_eq!(msgs, decrypted);
    }
}
