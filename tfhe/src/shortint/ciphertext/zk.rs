use crate::core_crypto::algorithms::verify_lwe_compact_ciphertext_list;
use crate::shortint::ciphertext::CompactCiphertextList;
use crate::shortint::parameters::{
    CompactPublicKeyEncryptionParameters, ShortintCompactCiphertextListCastingMode,
};
use crate::shortint::{Ciphertext, CompactPublicKey};
use crate::zk::{CompactPkeCrs, CompactPkeProof, CompactPkePublicParams, ZkVerificationOutCome};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

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

        crate::shortint::engine::ShortintEngine::with_thread_local_mut(|engine| {
            Self::new(
                size,
                max_num_message,
                noise_distribution,
                params.ciphertext_modulus,
                plaintext_modulus,
                &mut engine.random_generator,
            )
        })
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
        casting_mode: ShortintCompactCiphertextListCastingMode<'_>,
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
            .map(|(ct_list, _proof)| ct_list.expand(casting_mode))
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

        let msg = random::<u64>() % params.message_modulus.0 as u64;
        // No packing
        let encryption_modulus = params.message_modulus.0 as u64;

        let proven_ct = pk
            .encrypt_and_prove(
                msg,
                crs.public_params(),
                ZkComputeLoad::Proof,
                encryption_modulus,
            )
            .unwrap();
        let proven_ct = proven_ct.verify_and_expand(
            crs.public_params(),
            &pk,
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

        let msgs = (0..512)
            .map(|_| random::<u64>() % params.message_modulus.0 as u64)
            .collect::<Vec<_>>();

        let proven_ct = pk
            .encrypt_and_prove_slice(
                &msgs,
                crs.public_params(),
                ZkComputeLoad::Proof,
                params.message_modulus.0 as u64,
            )
            .unwrap();
        assert!(proven_ct.verify(crs.public_params(), &pk).is_valid());

        let expanded = proven_ct
            .verify_and_expand(
                crs.public_params(),
                &pk,
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
