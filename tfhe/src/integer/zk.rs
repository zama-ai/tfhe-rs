use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::encryption::KnowsMessageModulus;
use crate::integer::public_key::CompactPublicKey;
use crate::integer::IntegerRadixCiphertext;
use crate::zk::{CompactPkePublicParams, ZkComputeLoad, ZkVerificationOutCome};
use serde::{Deserialize, Serialize};

impl CompactPublicKey {
    pub fn encrypt_and_prove_radix_compact<T: DecomposableInto<u64>>(
        &self,
        messages: &[T],
        num_blocks_per_integer: usize,
        public_params: &CompactPkePublicParams,
        load: ZkComputeLoad,
    ) -> crate::Result<ProvenCompactCiphertextList> {
        let messages = messages
            .iter()
            .copied()
            .flat_map(|message| {
                BlockDecomposer::new(message, self.key.message_modulus().0.ilog2())
                    .iter_as::<u64>()
                    .take(num_blocks_per_integer)
            })
            .collect::<Vec<_>>();

        let proved_list = self
            .key
            .encrypt_and_prove_slice(&messages, public_params, load)?;

        Ok(ProvenCompactCiphertextList {
            proved_list,
            num_blocks_per_integer,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProvenCompactCiphertextList {
    pub(crate) proved_list: crate::shortint::ciphertext::ProvenCompactCiphertextList,
    // Keep track of the num_blocks, as we allow
    // storing many integer that have the same num_blocks
    // into ct_list
    pub(crate) num_blocks_per_integer: usize,
}

impl ProvenCompactCiphertextList {
    pub fn verify_and_expand_one<T: IntegerRadixCiphertext>(
        &self,
        public_params: &CompactPkePublicParams,
        public_key: &CompactPublicKey,
    ) -> crate::Result<T> {
        let blocks = self
            .proved_list
            .verify_and_expand(public_params, &public_key.key)?;
        assert_eq!(blocks.len(), self.num_blocks_per_integer);

        Ok(T::from_blocks(blocks))
    }

    pub fn ciphertext_count(&self) -> usize {
        self.proved_list.ciphertext_count() / self.num_blocks_per_integer
    }

    pub fn verify_and_expand<T: IntegerRadixCiphertext>(
        &self,
        public_params: &CompactPkePublicParams,
        public_key: &CompactPublicKey,
    ) -> crate::Result<Vec<T>> {
        let blocks = self
            .proved_list
            .verify_and_expand(public_params, &public_key.key)?;

        let mut integers = Vec::with_capacity(self.ciphertext_count());
        let mut blocks_iter = blocks.into_iter();
        for _ in 0..self.ciphertext_count() {
            let radix_blocks = blocks_iter
                .by_ref()
                .take(self.num_blocks_per_integer)
                .collect::<Vec<_>>();
            integers.push(T::from_blocks(radix_blocks));
        }
        Ok(integers)
    }

    pub fn verify(
        &self,
        public_params: &CompactPkePublicParams,
        public_key: &CompactPublicKey,
    ) -> ZkVerificationOutCome {
        self.proved_list.verify(public_params, &public_key.key)
    }
}

#[cfg(test)]
mod tests {
    use crate::integer::{ClientKey, CompactPublicKey};
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M40;
    use crate::zk::{CompactPkeCrs, ZkComputeLoad};
    use rand::random;

    #[test]
    fn test_zk_compact_ciphertext_list_encryption_ci_run_filter() {
        let params = PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M40;

        let num_blocks = 4usize;
        let modulus = (params.message_modulus.0 as u64)
            .checked_pow(num_blocks as u32)
            .unwrap();

        let crs = CompactPkeCrs::from_shortint_params(params, 512).unwrap();
        let cks = ClientKey::new(params);
        let pk = CompactPublicKey::new(&cks);

        let msgs = (0..512)
            .map(|_| random::<u64>() % modulus)
            .collect::<Vec<_>>();

        let proven_ct = pk
            .encrypt_and_prove_radix_compact(
                &msgs,
                num_blocks,
                crs.public_params(),
                ZkComputeLoad::Proof,
            )
            .unwrap();
        assert!(proven_ct.verify(crs.public_params(), &pk).is_valid());

        let expanded = proven_ct
            .verify_and_expand(crs.public_params(), &pk)
            .unwrap();
        let decrypted = expanded
            .iter()
            .map(|ciphertext| cks.decrypt_radix::<u64>(ciphertext))
            .collect::<Vec<_>>();
        assert_eq!(msgs, decrypted);
    }
}
