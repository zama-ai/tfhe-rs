use crate::core_crypto::algorithms::verify_lwe_compact_ciphertext_list;
use crate::core_crypto::prelude::verify_lwe_ciphertext;
use crate::shortint::ciphertext::CompactCiphertextList;
use crate::shortint::{Ciphertext, CompactPublicKey, EncryptionKeyChoice};
use crate::zk::{CompactPkeCrs, CompactPkeProof, CompactPkePublicParams, ZkVerificationOutCome};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

impl CompactPkeCrs {
    /// Construct the CRS that corresponds to the given parameters
    ///
    /// max_num_message is how many message a single proof can prove
    pub fn from_shortint_params(
        params: impl Into<crate::shortint::PBSParameters>,
        max_num_message: usize,
    ) -> crate::Result<Self> {
        let params = params.into();
        let (size, noise_distribution) = match params.encryption_key_choice() {
            EncryptionKeyChoice::Big => {
                let size = params
                    .glwe_dimension()
                    .to_equivalent_lwe_dimension(params.polynomial_size());
                (size, params.glwe_noise_distribution())
            }
            EncryptionKeyChoice::Small => (params.lwe_dimension(), params.lwe_noise_distribution()),
        };

        let mut plaintext_modulus = (params.message_modulus().0 * params.carry_modulus().0) as u64;
        // Our plaintext modulus does not take into account the bit of padding
        plaintext_modulus *= 2;

        crate::shortint::engine::ShortintEngine::with_thread_local_mut(|engine| {
            Self::new(
                size,
                max_num_message,
                noise_distribution,
                params.ciphertext_modulus(),
                plaintext_modulus,
                &mut engine.random_generator,
            )
        })
    }
}

/// A Ciphertext tied to a zero-knowledge proof
///
/// The proof can only be generated during the encryption with a [CompactPublicKey]
pub struct ProvenCiphertext {
    pub(crate) ciphertext: Ciphertext,
    pub(crate) proof: CompactPkeProof,
}

impl ProvenCiphertext {
    pub fn ciphertext(&self) -> &Ciphertext {
        &self.ciphertext
    }

    pub fn verify(
        &self,
        public_params: &CompactPkePublicParams,
        public_key: &CompactPublicKey,
    ) -> ZkVerificationOutCome {
        verify_lwe_ciphertext(
            &self.ciphertext.ct,
            &public_key.key,
            &self.proof,
            public_params,
        )
    }
}

/// A List of CompactCiphertext with their zero-knowledge proofs
///
/// The proofs can only be generated during the encryption with a [CompactPublicKey]
#[derive(Clone, Serialize, Deserialize)]
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
    ) -> crate::Result<Vec<Ciphertext>> {
        let not_all_valid = self.proved_lists.par_iter().any(|(ct_list, proof)| {
            verify_lwe_compact_ciphertext_list(
                &ct_list.ct_list,
                &public_key.key,
                proof,
                public_params,
            )
            .is_invalid()
        });

        if not_all_valid {
            return Err(crate::ErrorKind::InvalidZkProof.into());
        }

        let expanded = self
            .proved_lists
            .iter()
            .flat_map(|(ct_list, _proof)| ct_list.expand())
            .collect();

        Ok(expanded)
    }

    pub fn verify(
        &self,
        public_params: &CompactPkePublicParams,
        public_key: &CompactPublicKey,
    ) -> ZkVerificationOutCome {
        let all_valid = self.proved_lists.par_iter().all(|(ct_list, proof)| {
            verify_lwe_compact_ciphertext_list(
                &ct_list.ct_list,
                &public_key.key,
                proof,
                public_params,
            )
            .is_valid()
        });

        if all_valid {
            ZkVerificationOutCome::Valid
        } else {
            ZkVerificationOutCome::Invalid
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M40;
    use crate::shortint::{ClientKey, CompactPublicKey};
    use crate::zk::{CompactPkeCrs, ZkComputeLoad};
    use rand::random;

    #[test]
    fn test_zk_ciphertext_encryption_ci_run_filter() {
        let params = PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M40;

        let crs = CompactPkeCrs::from_shortint_params(params, 4).unwrap();
        let cks = ClientKey::new(params);
        let pk = CompactPublicKey::new(&cks);

        let msg = random::<u64>() % params.message_modulus.0 as u64;

        let proven_ct = pk
            .encrypt_and_prove(msg, crs.public_params(), ZkComputeLoad::Proof)
            .unwrap();
        assert!(proven_ct.verify(crs.public_params(), &pk).is_valid());

        let decrypted = cks.decrypt(proven_ct.ciphertext());
        assert_eq!(msg, decrypted);
    }

    #[test]
    fn test_zk_compact_ciphertext_list_encryption_ci_run_filter() {
        let params = PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M40;

        let crs = CompactPkeCrs::from_shortint_params(params, 512).unwrap();
        let cks = ClientKey::new(params);
        let pk = CompactPublicKey::new(&cks);

        let msgs = (0..512)
            .map(|_| random::<u64>() % params.message_modulus.0 as u64)
            .collect::<Vec<_>>();

        let proven_ct = pk
            .encrypt_and_prove_slice(&msgs, crs.public_params(), ZkComputeLoad::Proof)
            .unwrap();
        assert!(proven_ct.verify(crs.public_params(), &pk).is_valid());

        let expanded = proven_ct
            .verify_and_expand(crs.public_params(), &pk)
            .unwrap();
        let decrypted = expanded
            .iter()
            .map(|ciphertext| cks.decrypt(ciphertext))
            .collect::<Vec<_>>();
        assert_eq!(msgs, decrypted);
    }
}
