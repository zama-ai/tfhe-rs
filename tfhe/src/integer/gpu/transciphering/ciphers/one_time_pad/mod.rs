//! Server side of the one time pad on GPU. The client side stays on CPU.
//!
//! ```text
//!   entity    status      held by
//!   ------------------------------------------------------------
//!   seed      clear       server
//!   mask      encrypted   server, the client has it in clear
//!   message   clear       client, never sent
//!   input     clear       client, message XOR mask
//!   output    encrypted   server, the message
//!
//!   seed --OPRF--> mask (CudaOneTimePadFheSecretMask)
//!                    |
//!                    | CudaOneTimePadState::next_keystream_bits,
//!                    | a copy of the next mask blocks
//!                    v
//!   input --apply_keystream--> output
//! ```

#[cfg(test)]
mod test;

use std::num::NonZeroUsize;
use std::slice;

use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::GpuIndex;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::LweCiphertextCount;
use crate::integer::ciphertext::DataKind;
use crate::integer::gpu::ciphertext::compressed_ciphertext_list::CudaCompressedCiphertextList;
use crate::integer::gpu::ciphertext::info::CudaRadixCiphertextInfo;
use crate::integer::gpu::ciphertext::squashed_noise::CudaSquashedNoiseRadixCiphertext;
use crate::integer::gpu::ciphertext::{
    CudaCompressedSquashedNoiseCiphertextList, CudaIntegerRadixCiphertext,
    CudaUnsignedRadixCiphertext,
};
use crate::integer::gpu::list_compression::server_keys::{
    CudaCompressionKey, CudaDecompressionKey, CudaNoiseSquashingCompressionKey,
    CudaPackedGlweCiphertextList,
};
use crate::integer::gpu::noise_squashing::keys::CudaNoiseSquashingKey;
use crate::integer::gpu::transciphering::{CudaFheKeyStream, CudaIntegerTranscipherer};
use crate::integer::gpu::{
    cuda_backend_copy_radix_ciphertext_slice, CudaOprfServerKey, CudaServerKey,
};
use crate::integer::RadixCiphertext;
use crate::shortint::oprf::OprfSeed;
use crate::transciphering::{
    packed_squashed_layout, CompressedOneTimePadFheSecretMask,
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
    /// Same checks as [OneTimePadFheSecretMask::try_new], on the degree and noise level of each
    /// block
    pub fn try_new(
        secret_mask: CudaUnsignedRadixCiphertext,
        layout: KeyStreamLayout,
    ) -> crate::Result<Self> {
        OneTimePadFheSecretMask::check_ciphertexts(
            secret_mask
                .as_ref()
                .info
                .blocks
                .iter()
                .map(|block| (block.degree, block.noise_level)),
            &layout,
        )?;

        Ok(Self {
            secret_mask,
            layout,
        })
    }

    /// Same bits as [OneTimePadFheSecretMask::new_random] for the same seed and OPRF key. The mask
    /// sent to the KMS and the one used for transciphering may come from different devices.
    pub fn new_random(
        seed: impl OprfSeed,
        oprf_key: &CudaOprfServerKey,
        sks: &CudaServerKey,
        n_bits: u64,
        streams: &CudaStreams,
    ) -> Result<Self, MaskGenerationError> {
        let layout = KeyStreamLayout::message_space(sks.message_modulus)
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
        // The backend counts the bits of a call on 32 bits. Checked first, block_seeds allocates
        // a seed per mask ciphertext.
        if u32::try_from(n_bits).is_err() {
            return Err(MaskGenerationError::InvalidMaskSize);
        }

        let block_seeds = OneTimePadFheSecretMask::block_seeds(
            seed,
            n_bits,
            &layout,
            sks.message_modulus,
            sks.carry_modulus,
        )?;

        let secret_mask = oprf_key.generate_oblivious_pseudo_random_blocks(
            &block_seeds,
            u32::from(layout.bits_per_ct().get()),
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

    /// For a mask encrypted by a client or deserialized, both on CPU. The copy to the GPU reads
    /// the LWE size in the first ciphertext, so the radix of an empty mask comes from sks.
    pub fn from_cpu(
        mask: &OneTimePadFheSecretMask,
        sks: &CudaServerKey,
        streams: &CudaStreams,
    ) -> Self {
        let secret_mask = if mask.ciphertexts().is_empty() {
            sks.create_trivial_zero_radix(0, streams)
        } else {
            let radix = RadixCiphertext::from(mask.ciphertexts().to_vec());
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&radix, streams)
        };

        Self {
            secret_mask,
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

    /// Same list as [OneTimePadFheSecretMask::compress], built on GPU. The result is the CPU type,
    /// since it is what gets stored. A mask compressed on one device can then be decompressed on
    /// the other.
    pub fn compress(
        &self,
        comp_key: &CudaCompressionKey,
        streams: &CudaStreams,
    ) -> crate::Result<CompressedOneTimePadFheSecretMask> {
        let blocks = self.secret_mask.as_ref();
        // As on CPU, an empty mask is compressed into an empty list without any check
        let ciphertexts = match blocks.info.blocks.first() {
            Some(first) => {
                OneTimePadFheSecretMask::check_compressible(
                    &self.layout,
                    first.message_modulus,
                    first.carry_modulus,
                )?;
                slice::from_ref(blocks)
            }
            None => &[],
        };

        let packed_list = comp_key.compress_ciphertexts_into_list(ciphertexts, streams);
        let list = CudaCompressedCiphertextList {
            packed_list,
            info: Vec::new(),
        }
        .to_compressed_ciphertext_list(streams)?
        .packed_list;

        Ok(CompressedOneTimePadFheSecretMask::from_compressed_list(
            list,
            self.layout.clone(),
        ))
    }

    /// GPU counterpart of [CompressedOneTimePadFheSecretMask::decompress]. All the mask
    /// ciphertexts are decompressed in one call to the backend.
    pub fn decompress(
        compressed: &CompressedOneTimePadFheSecretMask,
        decomp_key: &CudaDecompressionKey,
        streams: &CudaStreams,
    ) -> crate::Result<Self> {
        let packed_list = CudaPackedGlweCiphertextList::from_compressed_ciphertext_list(
            compressed.compressed_list(),
            streams,
        );

        let secret_mask = match NonZeroUsize::new(packed_list.bodies_count()) {
            Some(ct_count) => CudaUnsignedRadixCiphertext {
                ciphertext: decomp_key.unpack(
                    &packed_list,
                    DataKind::Unsigned(ct_count),
                    0,
                    ct_count.get() - 1,
                    streams,
                )?,
            },
            // The backend cannot decompress an empty list
            None => CudaUnsignedRadixCiphertext::new(
                CudaLweCiphertextList::new(
                    decomp_key.blind_rotate_key.output_lwe_dimension(),
                    LweCiphertextCount(0),
                    decomp_key.ciphertext_modulus,
                    streams,
                ),
                CudaRadixCiphertextInfo { blocks: Vec::new() },
            ),
        };

        Self::try_new(secret_mask, compressed.layout().clone())
    }

    /// GPU counterpart of [OneTimePadFheSecretMask::squash_noise], first step towards the KMS.
    /// Same choice as on CPU, a mask that uses the message space is packed by pairs when the
    /// parameters allow it, any other mask is squashed block by block.
    pub fn squash_noise(
        &self,
        nsk: &CudaNoiseSquashingKey,
        sks: &CudaServerKey,
        streams: &CudaStreams,
    ) -> crate::Result<CudaSquashedNoiseOneTimePadFheSecretMask> {
        let packed_layout = packed_squashed_layout(
            &self.layout,
            sks.message_modulus,
            sks.carry_modulus,
            sks.max_noise_level,
        );

        let Some(layout) = packed_layout else {
            let secret_mask =
                nsk.checked_squash_blocks_noise(self.secret_mask.as_ref(), sks, streams)?;
            return Ok(CudaSquashedNoiseOneTimePadFheSecretMask {
                secret_mask,
                layout: self.layout.clone(),
            });
        };

        let ct_count = self.secret_mask.as_ref().d_blocks.lwe_ciphertext_count().0;
        if !ct_count.is_multiple_of(2) {
            return Err(crate::error!(
                "This mask is squashed by pairs of ciphertexts, so it must hold a multiple of {} \
                bits (got {})",
                layout.bits_per_ct(),
                self.bit_count(),
            ));
        }

        let secret_mask =
            nsk.checked_squash_ciphertext_noise(self.secret_mask.as_ref(), sks, streams)?;
        Ok(CudaSquashedNoiseOneTimePadFheSecretMask {
            secret_mask,
            layout,
        })
    }

    /// Number of input bits this mask can encrypt
    fn bit_count(&self) -> u64 {
        let ct_count = self.secret_mask.as_ref().d_blocks.lwe_ciphertext_count().0;
        u64::try_from(ct_count).unwrap() * u64::from(self.layout.bits_per_ct().get())
    }
}

/// GPU counterpart of [SquashedNoiseOneTimePadFheSecretMask]. The radix is only a container, its
/// blocks are the squashed mask ciphertexts, with the layout chosen by
/// [CudaOneTimePadFheSecretMask::squash_noise].
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
        SquashedNoiseOneTimePadFheSecretMask::from_squashed_ciphertexts(blocks, self.layout.clone())
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
            return CudaFheKeyStream::try_new(empty, layout);
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

        let keystream = CudaFheKeyStream::try_new(keystream, layout)?;

        self.current_counter = self.current_counter.checked_add(n_bits).unwrap();

        Ok(keystream)
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
