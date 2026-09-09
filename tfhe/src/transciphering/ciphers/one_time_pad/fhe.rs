use rayon::iter::{IntoParallelIterator, ParallelIterator};
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
    FheKeyStream, FheKeyStreamError, InsufficientKeystream, KeyStreamLayout, StreamCipherKind,
    Transcipherer, TranscipheringServerKey,
};

#[derive(Debug)]
pub struct InvalidMaskSize;

impl std::fmt::Display for InvalidMaskSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "The requested mask size is invalid")
    }
}

impl std::error::Error for InvalidMaskSize {}

#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(OneTimePadFheSecretMaskVersions)]
pub struct OneTimePadFheSecretMask {
    /// Collection of encrypted random bits, from which one can pull secret bits to hide sensitive
    /// values by XOR-ing them together.
    secret_mask: Vec<Ciphertext>,
}

impl OneTimePadFheSecretMask {
    /// `secret_mask` must hold exactly one [`Ciphertext`] per bit, each a fresh single-bit
    /// encryption (degree <= 1, nominal noise, not trivial), conformant with the [`ServerKey`]
    /// parameters that will be used for transciphering.
    pub fn try_new(secret_mask: Vec<Ciphertext>) -> Result<Self, &'static str> {
        for ct in &secret_mask {
            if ct.degree.get() > 1 {
                return Err("Mask ciphertexts must encrypt single bits (degree <= 1).");
            }
            if ct.noise_level() != NoiseLevel::NOMINAL {
                return Err("Mask ciphertexts must have nominal noise.");
            }
        }

        Ok(Self { secret_mask })
    }

    /// # Panics
    ///
    /// Panics if `secret_mask` contains a ciphertext that is not a fresh boolean encryption
    /// (degree <= 1, nominal noise, not trivial).
    pub fn new(secret_mask: Vec<Ciphertext>) -> Self {
        Self::try_new(secret_mask).unwrap()
    }

    /// Generate a mask of `n_bits` encrypted random bits with the OPRF of `transciphering_key`.
    ///
    /// The mask is generated in counter mode: the ciphertext at index `i` is generated
    /// independently, from `seed ‖ i`, with `i` as a little-endian `u32`. As a result, the mask
    /// generated for a given seed with some number of bits is a prefix of all the masks generated
    /// with the same seed and more bits. This allows a mask to be decrypted and regenerated with
    /// different lengths, as long as the regenerated length is shorter.
    ///
    /// The same seed should never be used to encrypt different data, since the generated masks
    /// would share their bits.
    pub fn new_random(
        seed: impl OprfSeed,
        transciphering_key: &TranscipheringServerKey,
        sks: &ServerKey,
        n_bits: u64,
    ) -> Result<Self, InvalidMaskSize> {
        let seed = seed.into_vec();

        let oprf_key = transciphering_key.oprf_key();

        // Generate mask bits following RFC030:
        // Each call to the prf generates only 1 ciphertext, and the seed is suffixed
        // by the ciphertext index stored on 32bits.
        let n_blocks = u32::try_from(n_bits).map_err(|_| InvalidMaskSize)?;
        let secret_mask = (0..n_blocks)
            .into_par_iter()
            .map(|i| {
                let mut block_seed = seed.clone();
                block_seed.extend_from_slice(&(i).to_le_bytes());
                oprf_key
                    .generate_random_boolean_sequence(block_seed, 1, sks)
                    .pop()
                    .unwrap()
            })
            .collect();

        Ok(Self::new(secret_mask))
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
    ) -> Result<FheKeyStream, FheKeyStreamError> {
        if n_bits == 0 {
            return FheKeyStream::try_new(vec![], KeyStreamLayout::single_bit());
        }

        let n_bits_u64: u64 = n_bits.try_into().unwrap();

        let remaining_bits = self.remaining_bits();
        if remaining_bits < n_bits_u64 {
            return Err(InsufficientKeystream.into());
        }

        let start_ciphertext_idx: usize = self.current_counter.try_into().unwrap();
        let stop_ciphertext_idx = start_ciphertext_idx + n_bits;

        let keystream = FheKeyStream::try_new(
            self.secret_mask.secret_mask[start_ciphertext_idx..stop_ciphertext_idx].to_vec(),
            KeyStreamLayout::single_bit(),
        )?;

        self.current_counter = self.current_counter.checked_add(n_bits_u64).unwrap();

        Ok(keystream)
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
