use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use crate::shortint::ciphertext::{Ciphertext, NoiseLevel};
use crate::shortint::client_key::ClientKey;
use crate::shortint::oprf::OprfSeed;
use crate::shortint::server_key::ServerKey;
use crate::transciphering::backward_compatibility::OneTimePadFheSecretMaskVersions;
use crate::transciphering::ciphers::one_time_pad::plain::OneTimePadPlainSecretMask;
use crate::transciphering::ciphers::pack_bits_lsb_first;
use crate::transciphering::{
    FheKeyStream, InsufficientKeystream, StreamCipherKind, Transcipherer, TranscipheringServerKey,
};

#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(OneTimePadFheSecretMaskVersions)]
pub struct OneTimePadFheSecretMask {
    /// Collection of encrypted random bits, from which one can pull secret bits to hide sensitive
    /// values by XOR-ing them together.
    secret_mask: Vec<Ciphertext>,
}

impl OneTimePadFheSecretMask {
    /// `secret_mask` must hold exactly one [`Ciphertext`] per bit, each a clean single-bit
    /// encryption (degree <= 1, with at most nominal noise), conformant with the [`ServerKey`]
    /// parameters that will be used for transciphering.
    pub fn try_new(secret_mask: Vec<Ciphertext>) -> Result<Self, &'static str> {
        for ct in &secret_mask {
            if ct.degree.get() > 1 {
                return Err("Mask ciphertexts must encrypt single bits (degree <= 1).");
            }
            if ct.noise_level() > NoiseLevel::NOMINAL {
                return Err("Mask ciphertexts must have at most nominal noise.");
            }
        }

        Ok(Self { secret_mask })
    }

    /// # Panics
    ///
    /// Panics if `secret_mask` contains a ciphertext that is not a clean boolean encryption
    /// (degree <= 1, noise <= NOMINAL).
    pub fn new(secret_mask: Vec<Ciphertext>) -> Self {
        Self::try_new(secret_mask).unwrap()
    }

    pub fn new_random(
        seed: impl OprfSeed,
        transciphering_key: &TranscipheringServerKey,
        sks: &ServerKey,
        n_bits: u64,
    ) -> Self {
        let encrypted_bits = transciphering_key
            .oprf_key()
            .generate_random_boolean_sequence(seed, n_bits, sks);

        Self::new(encrypted_bits)
    }

    /// Single bit per [`Ciphertext`].
    fn bit_count(&self) -> usize {
        self.secret_mask.len()
    }

    /// Borrow the pad bits, one single-bit shortint ciphertext per bit.
    pub fn ciphertexts(&self) -> &[Ciphertext] {
        &self.secret_mask
    }

    /// Decrypt the pad bits. Inverse of [`OneTimePadPlainSecretMask::encrypt`],
    /// so the recovered mask drives a [`OneTimePadPlainState`] that stays in
    /// step with the [`OneTimePadFheState`] built from `self`.
    ///
    /// [`OneTimePadPlainState`]: super::OneTimePadPlainState
    pub fn decrypt(&self, client_key: &ClientKey) -> OneTimePadPlainSecretMask {
        let bits: Vec<bool> = self
            .secret_mask
            .iter()
            .map(|ct| client_key.decrypt(ct) != 0)
            .collect();

        let mut bytes = vec![0u8; bits.len().div_ceil(8)];
        pack_bits_lsb_first(&bits, &mut bytes);

        OneTimePadPlainSecretMask::new(bytes, bits.len())
    }
}

pub struct OneTimePadFheState {
    secret_mask: OneTimePadFheSecretMask,
    /// Current keystream bit position.
    current_counter: u64,
}

impl OneTimePadFheState {
    pub fn new(secret_mask: OneTimePadFheSecretMask) -> Self {
        Self {
            secret_mask,
            current_counter: 0,
        }
    }

    pub fn remaining_bits(&self) -> u64 {
        let bit_count_u64: u64 = self.secret_mask.bit_count().try_into().unwrap();
        bit_count_u64.saturating_sub(self.current_counter)
    }
}

impl Transcipherer for OneTimePadFheState {
    fn kind(&self) -> StreamCipherKind {
        StreamCipherKind::OneTimePad
    }

    fn next_keystream_bits(
        &mut self,
        _sks: &ServerKey,
        n_bits: usize,
    ) -> Result<FheKeyStream, InsufficientKeystream> {
        if n_bits == 0 {
            return Ok(FheKeyStream::from_raw_parts(vec![]));
        }

        let n_bits_u64: u64 = n_bits.try_into().unwrap();

        let remaining_bits = self.remaining_bits();
        if remaining_bits < n_bits_u64 {
            return Err(InsufficientKeystream);
        }

        let start_ciphertext_idx: usize = self.current_counter.try_into().unwrap();
        let stop_ciphertext_idx = start_ciphertext_idx + n_bits;

        self.current_counter = self.current_counter.checked_add(n_bits_u64).unwrap();

        Ok(FheKeyStream::from_raw_parts(
            self.secret_mask.secret_mask[start_ciphertext_idx..stop_ciphertext_idx].to_vec(),
        ))
    }

    fn seek(&mut self, _sks: &ServerKey, target_counter: u64) {
        // setting a counter that is greater than the pad size will return an error at keystream
        // generation time
        self.current_counter = target_counter;
    }

    fn current_counter(&self) -> u64 {
        self.current_counter
    }
}
