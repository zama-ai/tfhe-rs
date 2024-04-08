use crate::integer::{BooleanBlock, ProvenCompactCiphertextList, RadixCiphertext};
use crate::named::Named;
use crate::shortint::ciphertext::Degree;
use crate::zk::{CompactPkePublicParams, ZkComputeLoad, ZkVerificationOutCome};
use crate::{CompactPublicKey, FheBool};
use serde::{Deserialize, Serialize};

/// A `CompactFheBool` tied to a Zero-Knowledge proof
///
/// The zero-knowledge proof allows to verify that the ciphertext is correctly
/// encrypted.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProvenCompactFheBool {
    inner: ProvenCompactCiphertextList,
}

impl Named for ProvenCompactFheBool {
    const NAME: &'static str = "high_level_api::ProvenCompactFheBool";
}

impl ProvenCompactFheBool {
    /// Encrypts the message while also generating the zero-knowledge proof
    pub fn try_encrypt(
        value: bool,
        public_params: &CompactPkePublicParams,
        key: &CompactPublicKey,
        load: ZkComputeLoad,
    ) -> crate::Result<Self> {
        let value = value as u8;
        let inner = key.key.key.encrypt_and_prove_radix_compact(
            &[value],
            1, /* num blocks */
            public_params,
            load,
        )?;
        Ok(Self { inner })
    }

    /// Verifies the ciphertext and the proof
    ///
    /// If the proof and ciphertext are valid, it returns an `Ok` with
    /// the underlying `FheBool`.
    pub fn verify_and_expand(
        self,
        public_params: &CompactPkePublicParams,
        public_key: &CompactPublicKey,
    ) -> crate::Result<FheBool> {
        let mut radix = self
            .inner
            .verify_and_expand_one::<RadixCiphertext>(public_params, &public_key.key.key)?;
        assert_eq!(radix.blocks.len(), 1);
        radix.blocks[0].degree = Degree::new(1);
        Ok(FheBool::new(BooleanBlock::new_unchecked(
            radix.blocks.pop().unwrap(),
        )))
    }

    pub fn verify(
        &self,
        public_params: &CompactPkePublicParams,
        public_key: &CompactPublicKey,
    ) -> ZkVerificationOutCome {
        self.inner.verify(public_params, &public_key.key.key)
    }
}

/// A `CompactFheBoolList` tied to a Zero-Knowledge proof
///
/// The zero-knowledge proof allows to verify that the ciphertext list is correctly
/// encrypted.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProvenCompactFheBoolList {
    inner: ProvenCompactCiphertextList,
}

impl Named for ProvenCompactFheBoolList {
    const NAME: &'static str = "high_level_api::ProvenCompactFheBoolList";
}

impl ProvenCompactFheBoolList {
    /// Encrypts the message while also generating the zero-knowledge proof
    pub fn try_encrypt(
        values: &[bool],
        public_params: &CompactPkePublicParams,
        key: &CompactPublicKey,
        load: ZkComputeLoad,
    ) -> crate::Result<Self> {
        let values = values.iter().copied().map(u8::from).collect::<Vec<_>>();
        let inner = key.key.key.encrypt_and_prove_radix_compact(
            &values,
            1, /* num_blocks */
            public_params,
            load,
        )?;
        Ok(Self { inner })
    }

    pub fn len(&self) -> usize {
        self.inner.ciphertext_count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Verifies the ciphertext and the proof
    ///
    /// If the proof and ciphertext are valid, it returns an `Ok` with
    /// the underlying `FheBool`s.
    pub fn verify_and_expand(
        &self,
        public_params: &CompactPkePublicParams,
        public_key: &CompactPublicKey,
    ) -> crate::Result<Vec<FheBool>> {
        Ok(self
            .inner
            .verify_and_expand::<RadixCiphertext>(public_params, &public_key.key.key)?
            .into_iter()
            .map(|mut radix| {
                assert_eq!(radix.blocks.len(), 1);
                radix.blocks[0].degree = Degree::new(1);
                FheBool::new(BooleanBlock::new_unchecked(radix.blocks.pop().unwrap()))
            })
            .collect())
    }

    pub fn verify(
        &self,
        public_params: &CompactPkePublicParams,
        public_key: &CompactPublicKey,
    ) -> ZkVerificationOutCome {
        self.inner.verify(public_params, &public_key.key.key)
    }
}
