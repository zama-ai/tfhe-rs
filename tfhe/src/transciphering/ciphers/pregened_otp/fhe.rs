use crate::shortint::ciphertext::{Ciphertext, NoiseLevel};
use crate::shortint::server_key::ServerKey;
use crate::transciphering::{FheKeyStream, StreamCipherKind, Transcipherer};

pub struct PreGenedOtpFheSecretMask {
    /// Collection of encrypted random bits, from which one can pull secret bits to hide sensitive
    /// values by XOR-ing them together.
    secret_mask: Vec<Ciphertext>,
}

impl PreGenedOtpFheSecretMask {
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

    /// Single bit per [`Ciphertext`].
    fn bit_count(&self) -> usize {
        self.secret_mask.len()
    }
}

pub struct PreGenedOtpFheState {
    secret_mask: PreGenedOtpFheSecretMask,
    /// Current keystream bit position.
    current_counter: u64,
}

impl PreGenedOtpFheState {
    pub fn new(secret_mask: PreGenedOtpFheSecretMask) -> Self {
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

impl Transcipherer for PreGenedOtpFheState {
    fn kind(&self) -> StreamCipherKind {
        StreamCipherKind::PreGenedOtp
    }

    fn next_keystream_bits(&mut self, _sks: &ServerKey, n_bits: usize) -> FheKeyStream {
        if n_bits == 0 {
            return FheKeyStream::from_raw_parts(vec![]);
        }

        let n_bits_u64: u64 = n_bits.try_into().unwrap();

        let remaining_bits = self.remaining_bits();
        assert!(
            remaining_bits >= n_bits_u64,
            "Requested more bits ({n_bits_u64}) than remaining ({remaining_bits})."
        );

        let start_ciphertext_idx: usize = self.current_counter.try_into().unwrap();
        let stop_ciphertext_idx = start_ciphertext_idx + n_bits;

        self.current_counter = self.current_counter.checked_add(n_bits_u64).unwrap();

        FheKeyStream::from_raw_parts(
            self.secret_mask.secret_mask[start_ciphertext_idx..stop_ciphertext_idx].to_vec(),
        )
    }

    fn seek(&mut self, _sks: &ServerKey, target_counter: u64) {
        let bit_count_u64: u64 = self.secret_mask.bit_count().try_into().unwrap();
        assert!(
            target_counter <= bit_count_u64,
            "Requested seek ({target_counter}), beyond maximum bit count ({bit_count_u64})"
        );

        self.current_counter = target_counter;
    }

    fn current_counter(&self) -> u64 {
        self.current_counter
    }
}
