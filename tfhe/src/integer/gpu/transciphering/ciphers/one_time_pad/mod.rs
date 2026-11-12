//! Server side of the one time pad on GPU. The client side stays on CPU.
//!
//! ```text
//!   seed --OPRF--> CudaOneTimePadFheSecretMask = Enc(k)
//!                        |
//!                        | CudaOneTimePadState::next_keystream_bits,
//!                        | a copy of the next mask blocks
//!                        v
//!   m ^ k --apply_keystream--> Enc(m)
//! ```

#[cfg(test)]
mod test;

use std::slice;

use crate::core_crypto::gpu::vec::GpuIndex;
use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::squashed_noise::CudaSquashedNoiseRadixCiphertext;
use crate::integer::gpu::ciphertext::{
    CudaCompressedSquashedNoiseCiphertextList, CudaIntegerRadixCiphertext,
    CudaUnsignedRadixCiphertext,
};
use crate::integer::gpu::list_compression::server_keys::CudaNoiseSquashingCompressionKey;
use crate::integer::gpu::noise_squashing::keys::CudaNoiseSquashingKey;
use crate::integer::gpu::transciphering::{CudaFheKeyStream, CudaIntegerTranscipherer};
use crate::integer::gpu::{
    cuda_backend_copy_radix_ciphertext_slice, CudaOprfServerKey, CudaServerKey,
};
use crate::integer::RadixCiphertext;
use crate::shortint::oprf::OprfSeed;
use crate::transciphering::{
    CompressedSquashedNoiseOneTimePadFheSecretMask, FheKeyStreamError, InsufficientKeystream,
    KeyStreamLayout, MaskGenerationError, OneTimePadFheSecretMask,
    SquashedNoiseOneTimePadFheSecretMask, StreamCipherKind,
};

/// GPU counterpart of [OneTimePadFheSecretMask]. The radix is only a container, its blocks are the
/// mask ciphertexts with [KeyStreamLayout::bits_per_ct] bits each.
pub struct CudaOneTimePadFheSecretMask {
    secret_mask: CudaUnsignedRadixCiphertext,
    layout: KeyStreamLayout,
}

impl CudaOneTimePadFheSecretMask {
    /// Same bits as [OneTimePadFheSecretMask::new_random] for the same seed and OPRF key. The mask
    /// sent to the KMS and the one used for transciphering may come from different devices.
    pub fn new_random(
        seed: impl OprfSeed,
        oprf_key: &CudaOprfServerKey,
        sks: &CudaServerKey,
        n_bits: u64,
        streams: &CudaStreams,
    ) -> Result<Self, MaskGenerationError> {
        let layout = KeyStreamLayout::full_space(sks.message_modulus, sks.carry_modulus)
            .ok_or(MaskGenerationError::IncompatibleParameters)?;

        Self::new_random_with_layout(seed, oprf_key, sks, n_bits, layout, streams)
    }

    /// [Self::new_random] with a chosen layout, same bits as
    /// [OneTimePadFheSecretMask::new_random_with_layout].
    pub fn new_random_with_layout(
        seed: impl OprfSeed,
        oprf_key: &CudaOprfServerKey,
        sks: &CudaServerKey,
        n_bits: u64,
        layout: KeyStreamLayout,
        streams: &CudaStreams,
    ) -> Result<Self, MaskGenerationError> {
        let block_seeds = OneTimePadFheSecretMask::block_seeds(
            seed,
            n_bits,
            &layout,
            sks.message_modulus,
            sks.carry_modulus,
        )?;

        let secret_mask = oprf_key.generate_oblivious_pseudo_random_blocks(
            &block_seeds,
            u64::from(layout.bits_per_ct().get()),
            sks,
            streams,
        );

        Ok(Self {
            secret_mask,
            layout,
        })
    }

    /// For decryption and serialization, which only exist on CPU.
    pub fn to_cpu(&self, streams: &CudaStreams) -> OneTimePadFheSecretMask {
        let blocks = self.secret_mask.to_radix_ciphertext(streams).blocks;
        OneTimePadFheSecretMask::new(blocks, self.layout.clone())
    }

    /// For a mask encrypted by a client or deserialized, both on CPU
    pub fn from_cpu(mask: &OneTimePadFheSecretMask, streams: &CudaStreams) -> Self {
        let radix = RadixCiphertext::from(mask.ciphertexts().to_vec());
        Self {
            secret_mask: CudaUnsignedRadixCiphertext::from_radix_ciphertext(&radix, streams),
            layout: mask.layout().clone(),
        }
    }

    pub fn gpu_indexes(&self) -> &[GpuIndex] {
        self.secret_mask.gpu_indexes()
    }

    pub fn duplicate(&self, streams: &CudaStreams) -> Self {
        Self {
            secret_mask: self.secret_mask.duplicate(streams),
            layout: self.layout.clone(),
        }
    }

    /// GPU counterpart of [OneTimePadFheSecretMask::squash_noise], first step towards the KMS
    pub fn squash_noise(
        &self,
        nsk: &CudaNoiseSquashingKey,
        sks: &CudaServerKey,
        streams: &CudaStreams,
    ) -> crate::Result<CudaSquashedNoiseOneTimePadFheSecretMask> {
        let secret_mask =
            nsk.checked_squash_blocks_noise(self.secret_mask.as_ref(), sks, streams)?;
        Ok(CudaSquashedNoiseOneTimePadFheSecretMask {
            secret_mask,
            layout: self.layout.clone(),
        })
    }

    /// Number of input bits this mask can encrypt
    fn bit_count(&self) -> u64 {
        let ct_count = self.secret_mask.as_ref().d_blocks.lwe_ciphertext_count().0;
        u64::try_from(ct_count).unwrap() * u64::from(self.layout.bits_per_ct().get())
    }
}

/// GPU counterpart of [SquashedNoiseOneTimePadFheSecretMask]. The radix is only a container, its
/// blocks are the squashed mask ciphertexts, one each since the mask uses its carry space.
pub struct CudaSquashedNoiseOneTimePadFheSecretMask {
    secret_mask: CudaSquashedNoiseRadixCiphertext,
    layout: KeyStreamLayout,
}

impl CudaSquashedNoiseOneTimePadFheSecretMask {
    pub fn gpu_indexes(&self) -> &[GpuIndex] {
        self.secret_mask.gpu_indexes()
    }

    /// For decryption, which only exists on CPU
    pub fn to_cpu(&self, streams: &CudaStreams) -> SquashedNoiseOneTimePadFheSecretMask {
        let blocks = self
            .secret_mask
            .to_squashed_noise_radix_ciphertext(streams)
            .packed_blocks;
        SquashedNoiseOneTimePadFheSecretMask::try_new(blocks, self.layout.clone())
            .expect("squashed blocks keep the degrees of the mask")
    }

    /// Same list as [SquashedNoiseOneTimePadFheSecretMask::compress], built on GPU. The result is
    /// the CPU type, since it is what the KMS receives.
    pub fn compress(
        &self,
        comp_key: &CudaNoiseSquashingCompressionKey,
        streams: &CudaStreams,
    ) -> crate::Result<CompressedSquashedNoiseOneTimePadFheSecretMask> {
        let packed_list = comp_key.compress_noise_squashed_ciphertexts_into_list(
            slice::from_ref(&self.secret_mask),
            streams,
        );
        let list = CudaCompressedSquashedNoiseCiphertextList {
            packed_list,
            info: Vec::new(),
        }
        .to_compressed_squashed_noise_ciphertext_list(streams)?
        .list;

        Ok(
            CompressedSquashedNoiseOneTimePadFheSecretMask::from_compressed_list(
                list,
                self.layout.clone(),
            ),
        )
    }
}

/// GPU counterpart of [OneTimePadFheState](crate::transciphering::OneTimePadFheState). Drawing
/// keystream is a copy without PBS, the cost of the one time pad is in apply_keystream.
pub struct CudaOneTimePadState {
    secret_mask: CudaOneTimePadFheSecretMask,
    /// In bits. May go past the end of the mask after a skip.
    current_counter: u64,
}

impl CudaOneTimePadState {
    pub fn new(secret_mask: CudaOneTimePadFheSecretMask) -> Self {
        Self {
            secret_mask,
            current_counter: 0,
        }
    }

    pub fn remaining_bits(&self) -> u64 {
        self.secret_mask
            .bit_count()
            .saturating_sub(self.current_counter)
    }
}

impl CudaIntegerTranscipherer for CudaOneTimePadState {
    fn kind(&self) -> StreamCipherKind {
        StreamCipherKind::OneTimePad
    }

    /// Checked in the CPU order, so that an invalid draw gets the CPU error.
    fn next_keystream_bits(
        &mut self,
        sks: &CudaServerKey,
        n_bits: usize,
        streams: &CudaStreams,
    ) -> Result<CudaFheKeyStream, FheKeyStreamError> {
        let layout = self.secret_mask.layout.clone();
        let bits_per_ct = u64::from(layout.bits_per_ct().get());
        if !self.current_counter.is_multiple_of(bits_per_ct) {
            return Err(FheKeyStreamError::UnalignedCounter);
        }

        if n_bits == 0 {
            let empty = sks.create_trivial_zero_radix(0, streams);
            return Ok(CudaFheKeyStream::from_raw_parts(empty, layout));
        }

        let n_bits = u64::try_from(n_bits).unwrap();
        if self.remaining_bits() < n_bits {
            return Err(InsufficientKeystream.into());
        }

        // The counter is aligned, so the keystream starts with a whole mask ciphertext
        let start = u32::try_from(self.current_counter / bits_per_ct).unwrap();
        let n_cts = usize::try_from(n_bits.div_ceil(bits_per_ct)).unwrap();

        let mut keystream: CudaUnsignedRadixCiphertext =
            sks.create_trivial_zero_radix(n_cts, streams);
        unsafe {
            cuda_backend_copy_radix_ciphertext_slice(
                keystream.as_mut(),
                self.secret_mask.secret_mask.as_ref(),
                start,
                streams,
            );
        }

        self.current_counter = self.current_counter.checked_add(n_bits).unwrap();

        Ok(CudaFheKeyStream::from_raw_parts(keystream, layout))
    }

    fn skip(&mut self, _sks: &CudaServerKey, n_bits: usize, _streams: &CudaStreams) {
        // As on CPU, a counter past the end of the mask is only an error when drawing keystream
        self.current_counter = self
            .current_counter
            .saturating_add(u64::try_from(n_bits).unwrap());
    }

    fn current_counter(&self) -> u64 {
        self.current_counter
    }
}
