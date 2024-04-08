use super::FheUintId;
use crate::core_crypto::commons::math::random::{Deserialize, Serialize};
use crate::core_crypto::prelude::UnsignedNumeric;
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::{ProvenCompactCiphertextList, RadixCiphertext};
use crate::named::Named;
use crate::zk::{CompactPkePublicParams, ZkComputeLoad, ZkVerificationOutCome};
use crate::{CompactPublicKey, FheUint};

/// A `CompactFheUint` tied to a Zero-Knowledge proof
///
/// The zero-knowledge proof allows to verify that the ciphertext is correctly
/// encrypted.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProvenCompactFheUint<Id: FheUintId> {
    inner: ProvenCompactCiphertextList,
    _id: Id,
}

impl<Id: FheUintId> Named for ProvenCompactFheUint<Id> {
    const NAME: &'static str = "high_level_api::ProvenCompactFheUint";
}

impl<Id> ProvenCompactFheUint<Id>
where
    Id: FheUintId,
{
    /// Encrypts the message while also generating the zero-knowledge proof
    pub fn try_encrypt<Clear>(
        value: Clear,
        public_params: &CompactPkePublicParams,
        key: &CompactPublicKey,
        load: ZkComputeLoad,
    ) -> crate::Result<Self>
    where
        Clear: DecomposableInto<u64> + UnsignedNumeric,
    {
        let inner = key.key.key.encrypt_and_prove_radix_compact(
            &[value],
            Id::num_blocks(key.key.key.key.parameters.message_modulus()),
            public_params,
            load,
        )?;
        Ok(Self {
            inner,
            _id: Id::default(),
        })
    }

    /// Verifies the ciphertext and the proof
    ///
    /// If the proof and ciphertext are valid, it returns an `Ok` with
    /// the underlying `FheUint`
    pub fn verify_and_expand(
        self,
        public_params: &CompactPkePublicParams,
        public_key: &CompactPublicKey,
    ) -> crate::Result<FheUint<Id>> {
        let expanded_inner = self
            .inner
            .verify_and_expand_one::<RadixCiphertext>(public_params, &public_key.key.key)?;
        Ok(FheUint::new(expanded_inner))
    }

    pub fn verify(
        &self,
        public_params: &CompactPkePublicParams,
        public_key: &CompactPublicKey,
    ) -> ZkVerificationOutCome {
        self.inner.verify(public_params, &public_key.key.key)
    }
}

/// A `CompactFheUintList` tied to a Zero-Knowledge proof
///
/// The zero-knowledge proof allows to verify that the ciphertext list is correctly
/// encrypted.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProvenCompactFheUintList<Id: FheUintId> {
    inner: ProvenCompactCiphertextList,
    _id: Id,
}

impl<Id: FheUintId> Named for ProvenCompactFheUintList<Id> {
    const NAME: &'static str = "high_level_api::ProvenCompactFheUintList";
}

impl<Id> ProvenCompactFheUintList<Id>
where
    Id: FheUintId,
{
    /// Encrypts the message while also generating the zero-knowledge proof
    pub fn try_encrypt<Clear>(
        values: &[Clear],
        public_params: &CompactPkePublicParams,
        key: &CompactPublicKey,
        load: ZkComputeLoad,
    ) -> crate::Result<Self>
    where
        Clear: DecomposableInto<u64> + UnsignedNumeric,
    {
        let inner = key.key.key.encrypt_and_prove_radix_compact(
            values,
            Id::num_blocks(key.key.key.key.parameters.message_modulus()),
            public_params,
            load,
        )?;
        Ok(Self {
            inner,
            _id: Id::default(),
        })
    }

    pub fn len(&self) -> usize {
        self.inner.ciphertext_count()
    }

    /// Verifies the ciphertext and the proof
    ///
    /// If the proof and ciphertext are valid, it returns an `Ok` with
    /// the underlying `FheUint`s.
    pub fn verify_and_expand(
        &self,
        public_params: &CompactPkePublicParams,
        public_key: &CompactPublicKey,
    ) -> crate::Result<Vec<FheUint<Id>>> {
        let expanded_inners = self
            .inner
            .verify_and_expand::<RadixCiphertext>(public_params, &public_key.key.key)?;
        Ok(expanded_inners.into_iter().map(FheUint::new).collect())
    }

    pub fn verify(
        &self,
        public_params: &CompactPkePublicParams,
        public_key: &CompactPublicKey,
    ) -> ZkVerificationOutCome {
        self.inner.verify(public_params, &public_key.key.key)
    }
}
