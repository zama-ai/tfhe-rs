use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use crate::conformance::ParameterSetConformant;
use crate::named::Named;
use crate::shortint::ciphertext::{Ciphertext, Degree, DegreeConformance, NoiseLevel};
use crate::shortint::client_key::ClientKey;
use crate::shortint::oprf::OprfSeed;
use crate::shortint::parameters::CiphertextConformanceParams;
use crate::shortint::server_key::ServerKey;
use crate::transciphering::backward_compatibility::OneTimePadFheSecretMaskVersions;
use crate::transciphering::ciphers::one_time_pad::plain::OneTimePadPlainSecretMask;
use crate::transciphering::ciphers::pack_bits_lsb_first;
use crate::transciphering::{
    FheKeyStream, FheKeyStreamError, InsufficientKeystream, KeyStreamLayout,
    KeyStreamLayoutConformanceParams, StreamCipherKind, Transcipherer, TranscipheringServerKey,
};

#[derive(Debug)]
pub enum MaskGenerationError {
    InvalidMaskSize,
    IncompatibleParameters,
}

impl std::fmt::Display for MaskGenerationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMaskSize => write!(f, "The requested mask size is invalid"),
            Self::IncompatibleParameters => {
                write!(
                    f,
                    "The parameter set in use is not compatible with otp mask generation"
                )
            }
        }
    }
}

impl std::error::Error for MaskGenerationError {}

#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(OneTimePadFheSecretMaskVersions)]
pub struct OneTimePadFheSecretMask {
    /// Collection of encrypted random bits, from which one can pull secret bits to hide sensitive
    /// values by XOR-ing them together.
    secret_mask: Vec<Ciphertext>,
    /// Number of mask bits in each ciphertext
    layout: KeyStreamLayout,
}

impl OneTimePadFheSecretMask {
    /// `secret_mask` must hold Ciphertexts following `layout`, each a fresh encryption of
    /// `layout.bits_per_ct()` bits.
    pub fn try_new(secret_mask: Vec<Ciphertext>, layout: KeyStreamLayout) -> crate::Result<Self> {
        let expected_degree = (1u64 << layout.bits_per_ct().get()) - 1;
        for ct in &secret_mask {
            if ct.degree.get() != expected_degree {
                return Err(crate::error!(
                    "Mask ciphertexts does not follow the required layout (got {}, expected \
                    {expected_degree}).",
                    ct.degree.get(),
                ));
            }
            if ct.noise_level() != NoiseLevel::NOMINAL {
                return Err(crate::error!("Mask ciphertexts must have nominal noise."));
            }
        }

        Ok(Self {
            secret_mask,
            layout,
        })
    }

    /// # Panics
    ///
    /// Panics if `secret_mask` contains a ciphertext that is not a fresh encryption of
    /// `layout.bits_per_ct()` bits (degree == 2^bits_per_ct - 1, nominal noise).
    pub fn new(secret_mask: Vec<Ciphertext>, layout: KeyStreamLayout) -> Self {
        Self::try_new(secret_mask, layout).unwrap()
    }

    /// Generate a mask of `n_bits` encrypted random bits with the OPRF of `transciphering_key`.
    ///
    /// This will use the full message space + carry space for mask bits.
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
    ) -> Result<Self, MaskGenerationError> {
        let layout = KeyStreamLayout::full_space(sks.message_modulus, sks.carry_modulus)
            .ok_or(MaskGenerationError::IncompatibleParameters)?;

        Self::new_random_with_layout(seed, transciphering_key, sks, n_bits, layout)
    }

    pub fn new_random_with_layout(
        seed: impl OprfSeed,
        transciphering_key: &TranscipheringServerKey,
        sks: &ServerKey,
        n_bits: u64,
        layout: KeyStreamLayout,
    ) -> Result<Self, MaskGenerationError> {
        let bits_per_ct = u64::from(layout.bits_per_ct.get());

        if !layout.can_fit(sks.message_modulus, sks.carry_modulus) {
            return Err(MaskGenerationError::IncompatibleParameters);
        }

        if !n_bits.is_multiple_of(bits_per_ct) {
            return Err(MaskGenerationError::InvalidMaskSize);
        }

        let seed = seed.into_vec();
        let oprf_key = transciphering_key.oprf_key();

        // Generate mask bits following RFC030:
        // Each call to the prf generates only 1 ciphertext, and the seed is suffixed
        // by the ciphertext index stored on 32bits.
        let n_blocks = u32::try_from(n_bits / bits_per_ct)
            .map_err(|_| MaskGenerationError::InvalidMaskSize)?;
        let secret_mask = (0..n_blocks)
            .into_par_iter()
            .map(|i| {
                let mut block_seed = seed.clone();
                block_seed.extend_from_slice(&(i).to_le_bytes());
                oprf_key
                    .inner
                    .generate_pseudo_random_bits_chunks(
                        block_seed,
                        &[bits_per_ct],
                        bits_per_ct,
                        sks,
                    )
                    .pop()
                    .unwrap()
                    .pop()
                    .unwrap()
            })
            .collect();

        Ok(Self::new(secret_mask, layout))
    }

    /// Number of input bits this mask can encrypt
    fn bit_count(&self) -> usize {
        self.secret_mask.len() * usize::from(self.layout.bits_per_ct.get())
    }

    pub fn layout(&self) -> &KeyStreamLayout {
        &self.layout
    }

    /// Borrow the mask bits as lwe ciphertexts
    pub fn ciphertexts(&self) -> &[Ciphertext] {
        &self.secret_mask
    }

    /// Decrypt the pad bits. Inverse of [`OneTimePadPlainSecretMask::encrypt`],
    /// so the recovered mask drives a [`OneTimePadPlainState`] that stays in
    /// step with the [`OneTimePadFheState`] built from `self`.
    ///
    /// [`OneTimePadPlainState`]: super::OneTimePadPlainState
    pub fn decrypt(&self, client_key: &ClientKey) -> OneTimePadPlainSecretMask {
        let bits_per_ct = usize::from(self.layout.bits_per_ct().get());

        let bits: Vec<bool> = self
            .secret_mask
            .iter()
            .flat_map(|ct| {
                let val = client_key.decrypt_message_and_carry(ct);
                (0..bits_per_ct).map(move |i| (val >> i) & 1 != 0)
            })
            .collect();

        let mut bytes = vec![0u8; bits.len().div_ceil(8)];
        pack_bits_lsb_first(&bits, &mut bytes);

        OneTimePadPlainSecretMask::new(bytes, bits.len())
    }
}

impl ParameterSetConformant for OneTimePadFheSecretMask {
    type ParameterSet = CiphertextConformanceParams;

    fn is_conformant(&self, params: &Self::ParameterSet) -> bool {
        let Self {
            secret_mask,
            layout,
        } = self;

        let layout_params = KeyStreamLayoutConformanceParams {
            message_modulus: params.message_modulus,
            carry_modulus: params.carry_modulus,
        };
        if !layout.is_conformant(&layout_params) {
            return false;
        }

        // Mask ciphertexts use the carry space, so their degree is above the one of a fresh
        // encryption
        let ct_params = CiphertextConformanceParams {
            degree: DegreeConformance::Exact(Degree::new((1u64 << layout.bits_per_ct().get()) - 1)),
            ..*params
        };

        secret_mask
            .iter()
            .all(|ct| ct.is_conformant(&ct_params) && ct.noise_level() == NoiseLevel::NOMINAL)
    }
}

impl Named for OneTimePadFheSecretMask {
    const NAME: &'static str = "transciphering::OneTimePadFheSecretMask";
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
        let bits_per_ct = u64::from(self.secret_mask.layout.bits_per_ct().get());
        if !self.current_counter.is_multiple_of(bits_per_ct) {
            return Err(FheKeyStreamError::InvalidStreamCipherState);
        }

        if n_bits == 0 {
            return FheKeyStream::try_new(vec![], self.secret_mask.layout().clone());
        }

        let n_bits = u64::try_from(n_bits).unwrap();
        let n_blocks = n_bits.div_ceil(bits_per_ct);

        let remaining_bits = self.remaining_bits();
        if remaining_bits < n_bits {
            return Err(InsufficientKeystream.into());
        }

        // We checked above that we will not start in the middle of an already produced ciphertext
        let start_ciphertext_idx = usize::try_from(self.current_counter / bits_per_ct).unwrap();
        let stop_ciphertext_idx = start_ciphertext_idx + usize::try_from(n_blocks).unwrap();

        // Validate the keystream before advancing the counter, so a rejected draw can be retried
        let keystream = FheKeyStream::try_new(
            self.secret_mask.secret_mask[start_ciphertext_idx..stop_ciphertext_idx].to_vec(),
            self.secret_mask.layout.clone(),
        )?;

        self.current_counter = self.current_counter.checked_add(n_bits).unwrap();

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
