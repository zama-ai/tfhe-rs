use crate::core_crypto::prelude::Numeric;
use crate::high_level_api::compact_list::{
    CompactCiphertextListExpander, InnerCompactCiphertextListExpander,
};
use crate::high_level_api::compressed_ciphertext_list::HlExpandable;
use crate::high_level_api::errors::UninitializedServerKey;
use crate::high_level_api::global_state::try_with_internal_keys;
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::traits::Tagged;
use crate::integer::block_decomposition::{BlockRecomposer, DecomposableInto, RecomposableFrom};
use crate::integer::ciphertext::Expandable;
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::compressed_ciphertext_list::CudaExpandable;
#[cfg(feature = "gpu")]
use crate::integer::gpu::server_key::radix::CudaKreyviumStream;
#[cfg(feature = "gpu")]
use crate::integer::gpu::transciphering::{CudaIntegerTranscipherer, CudaTranscipherSession};
use crate::integer::transciphering::{
    IntegerStreamCipher, IntegerStreamCiphertext, IntegerStreamCiphertextKind,
    IntegerStreamCiphertextList, IntegerTranscipherer,
};
use crate::transciphering::{StreamCipher, Transcipherer};

mod aes;
mod kreyvium;
mod one_time_pad;
mod stream_ciphertext;
mod stream_ciphertext_list;

pub use aes::AesFheKey;
pub use kreyvium::KreyviumFheKey;
pub use one_time_pad::{
    CompressedSquashedNoiseOneTimePadFheSecretMask,
    CompressedSquashedNoiseOneTimePadFheSecretMaskConformanceParams, OneTimePadFheSecretMask,
    OneTimePadFheSecretMaskConformanceParams, SquashedNoiseOneTimePadFheSecretMask,
};
pub use stream_ciphertext::StreamCiphertext;
pub use stream_ciphertext_list::{
    HlStreamPackable, StreamCiphertextList, StreamCiphertextListBuilder,
};

/// Types encryptable by [`HlStreamCipher`].
pub trait HlStreamEncryptable {
    /// `self` should encrypt itself using the `cipher`
    ///
    /// `n_bits` is a hint on the number of bits to encrypt
    ///     - None => encrypt all the bits of the `Self` type
    ///     - Some(n) => encrypt `n` bits, truncating or padding if necessary
    fn hl_stream_encrypt<C>(
        self,
        cipher: &mut C,
        n_bits: Option<usize>,
    ) -> crate::Result<StreamCiphertext>
    where
        C: StreamCipher + ?Sized;
}

impl HlStreamEncryptable for bool {
    fn hl_stream_encrypt<C>(
        self,
        cipher: &mut C,
        n_bits: Option<usize>,
    ) -> crate::Result<StreamCiphertext>
    where
        C: StreamCipher + ?Sized,
    {
        if let Some(n_bits) = n_bits {
            if n_bits != 1 {
                return Err(crate::error!(
                    "HlStreamCipher: bool inputs must have n_bits == 1",
                ));
            }
        }

        cipher
            .encrypt_bool(self)
            .map(StreamCiphertext::from_raw_parts)
            .map_err(|e| crate::error!("{e}"))
    }
}

impl<T> HlStreamEncryptable for T
where
    T: DecomposableInto<u8> + Numeric + std::ops::Shl<usize, Output = T>,
{
    fn hl_stream_encrypt<C>(
        self,
        cipher: &mut C,
        n_bits: Option<usize>,
    ) -> crate::Result<StreamCiphertext>
    where
        C: StreamCipher + ?Sized,
    {
        match n_bits {
            None => cipher.encrypt_integer(self),
            Some(n) => cipher.encrypt_integer_with_num_bits(self, n),
        }
        .map(StreamCiphertext::from_raw_parts)
        .map_err(|e| crate::error!("{e}"))
    }
}

/// Types decryptable by [`HlStreamCipher::try_decrypt`]. Mirror of
/// [`HlStreamEncryptable`], reconstructing the plaintext from the raw
/// keystream-XORed bytes returned by [`StreamCipher::decrypt`].
pub trait HlStreamDecryptable: Sized {
    fn hl_stream_decrypt<C>(cipher: &mut C, encrypted: &StreamCiphertext) -> crate::Result<Self>
    where
        C: StreamCipher + ?Sized;
}

impl HlStreamDecryptable for bool {
    fn hl_stream_decrypt<C>(cipher: &mut C, encrypted: &StreamCiphertext) -> crate::Result<Self>
    where
        C: StreamCipher + ?Sized,
    {
        if encrypted.kind() != IntegerStreamCiphertextKind::Boolean {
            return Err(crate::error!(
                "cannot decrypt bool from a {:?} stream ciphertext",
                encrypted.kind()
            ));
        }
        let bytes = cipher
            .decrypt(encrypted.integer().inner())
            .map_err(|e| crate::error!("{e}"))?;
        Ok(bytes.first().copied().unwrap_or(0) & 1 == 1)
    }
}

impl<T> HlStreamDecryptable for T
where
    T: RecomposableFrom<u8>
        + Numeric
        + std::ops::Shl<usize, Output = T>
        + std::ops::Shr<usize, Output = T>,
{
    fn hl_stream_decrypt<C>(cipher: &mut C, encrypted: &StreamCiphertext) -> crate::Result<Self>
    where
        C: StreamCipher + ?Sized,
    {
        // Runtime signedness detection, same trick as encrypt.
        let is_signed = (T::ONE << (T::BITS - 1)) < T::ZERO;
        let expected_kind = if is_signed {
            IntegerStreamCiphertextKind::Signed
        } else {
            IntegerStreamCiphertextKind::Unsigned
        };
        if encrypted.kind() != expected_kind {
            return Err(crate::error!(
                "stream ciphertext kind mismatch: expected {expected_kind:?}, got {:?}",
                encrypted.kind()
            ));
        }

        let bytes = cipher
            .decrypt(encrypted.integer().inner())
            .map_err(|e| crate::error!("{e}"))?;
        let n_bits = encrypted.n_bits();
        let value = BlockRecomposer::<T>::recompose_unsigned_with_size(
            bytes.iter().copied(),
            8,
            n_bits as u32,
        );

        // For a signed T narrower than n_bits, no extension is needed; for the
        // reverse (T wider than the encoded value) we arithmetic-shift to
        // sign-extend from bit `n_bits-1`.
        if is_signed && n_bits < T::BITS {
            let shift = T::BITS - n_bits;
            Ok((value << shift) >> shift)
        } else {
            Ok(value)
        }
    }
}

/// Client-side extension of [`StreamCipher`] that produces
/// [`StreamCiphertext`] values with a unified generic API — dispatches
/// unsigned / signed / bool by inspecting `T` via [`HlStreamEncryptable`] /
/// [`HlStreamDecryptable`].
///
/// Blanket-implemented for every [`StreamCipher`].
pub trait HlStreamCipher {
    /// Encrypt `input` at its natural bit-width (`T::BITS`, or 1 for `bool`).
    ///
    /// Errors if the cipher's keystream is exhausted (e.g. a one-time pad with
    /// fewer bits remaining than requested).
    fn try_encrypt<T: HlStreamEncryptable>(&mut self, input: T) -> crate::Result<StreamCiphertext>;

    /// Encrypt `input` at exactly `n_bits`. If `n_bits > T::BITS` the value is
    /// sign- or zero-extended, if `n_bits < T::BITS` it is truncated.
    ///
    /// For integers, the server only accepts an `n_bits` that is a multiple of the number of
    /// message bits per block of its parameters (2 with the default parameters).
    ///
    /// Errors if the cipher's keystream is exhausted.
    ///
    /// # Panics
    /// * If `n_bits == 0`.
    /// * If `T` is `bool` and `n_bits != 1`.
    fn try_encrypt_with_num_bits<T: HlStreamEncryptable>(
        &mut self,
        input: T,
        n_bits: usize,
    ) -> crate::Result<StreamCiphertext>;

    /// Decrypt a [`StreamCiphertext`] into a value of type `T`.
    ///
    /// Errors if `T`'s signedness / shape does not match the ciphertext's tag.
    /// If `T::BITS > encrypted.n_bits()` the value is sign- or zero-extended
    /// as appropriate; if `T::BITS < encrypted.n_bits()` the value is truncated.
    fn try_decrypt<T: HlStreamDecryptable>(
        &mut self,
        encrypted: &StreamCiphertext,
    ) -> crate::Result<T>;
}

impl<C: StreamCipher + ?Sized> HlStreamCipher for C {
    fn try_encrypt<T: HlStreamEncryptable>(&mut self, input: T) -> crate::Result<StreamCiphertext> {
        input.hl_stream_encrypt(self, None)
    }

    fn try_encrypt_with_num_bits<T: HlStreamEncryptable>(
        &mut self,
        input: T,
        n_bits: usize,
    ) -> crate::Result<StreamCiphertext> {
        input.hl_stream_encrypt(self, Some(n_bits))
    }

    fn try_decrypt<T: HlStreamDecryptable>(
        &mut self,
        encrypted: &StreamCiphertext,
    ) -> crate::Result<T> {
        T::hl_stream_decrypt(self, encrypted)
    }
}

/// Trait for transciphering to HLAPI types like FheUint,FheInt,FheBool
pub trait HlTranscipherer {
    fn transcipher<T>(&mut self, input: &StreamCiphertext) -> crate::Result<T>
    where
        T: HlExpandable + Tagged;

    fn transcipher_list(
        &mut self,
        input: &StreamCiphertextList,
    ) -> crate::Result<CompactCiphertextListExpander>;
}

impl<X: Transcipherer> HlTranscipherer for X {
    fn transcipher<T>(&mut self, input: &StreamCiphertext) -> crate::Result<T>
    where
        T: HlExpandable + Tagged,
    {
        try_with_internal_keys(|keys| match keys {
            Some(InternalServerKey::Cpu(cpu_key)) => {
                cpu_transcipher(self, input.integer(), cpu_key)
            }
            #[cfg(feature = "gpu")]
            Some(InternalServerKey::Cuda(_)) => Err(crate::Error::new(
                "CPU Transcipherer used while a CUDA server key is set".to_owned(),
            )),
            #[cfg(feature = "hpu")]
            Some(InternalServerKey::Hpu(_)) => Err(crate::Error::new(
                "Transciphering is not supported on HPU".to_owned(),
            )),
            None => Err(UninitializedServerKey.into()),
        })
    }

    fn transcipher_list(
        &mut self,
        input: &StreamCiphertextList,
    ) -> crate::Result<CompactCiphertextListExpander> {
        try_with_internal_keys(|keys| match keys {
            Some(InternalServerKey::Cpu(cpu_key)) => {
                cpu_transcipher_list(self, input.integer(), cpu_key)
            }
            #[cfg(feature = "gpu")]
            Some(InternalServerKey::Cuda(_)) => Err(crate::Error::new(
                "CPU Transcipherer used while a CUDA server key is set".to_owned(),
            )),
            #[cfg(feature = "hpu")]
            Some(InternalServerKey::Hpu(_)) => Err(crate::Error::new(
                "Transciphering is not supported on HPU".to_owned(),
            )),
            None => Err(UninitializedServerKey.into()),
        })
    }
}

pub struct TranscipherSession {
    inner: InnerTranscipherSession,
}

enum InnerTranscipherSession {
    Cpu(crate::transciphering::TranscipherSession),
    #[cfg(feature = "gpu")]
    Gpu(CudaTranscipherSession),
}

impl TranscipherSession {
    fn new_cpu(inner: crate::transciphering::TranscipherSession) -> Self {
        Self {
            inner: InnerTranscipherSession::Cpu(inner),
        }
    }

    #[cfg(feature = "gpu")]
    fn new_gpu(inner: CudaTranscipherSession) -> Self {
        Self {
            inner: InnerTranscipherSession::Gpu(inner),
        }
    }
}

impl From<crate::transciphering::TranscipherSession> for TranscipherSession {
    fn from(inner: crate::transciphering::TranscipherSession) -> Self {
        Self::new_cpu(inner)
    }
}

#[cfg(feature = "gpu")]
impl From<CudaTranscipherSession> for TranscipherSession {
    fn from(inner: CudaTranscipherSession) -> Self {
        Self::new_gpu(inner)
    }
}

#[cfg(feature = "gpu")]
impl From<CudaKreyviumStream> for TranscipherSession {
    fn from(inner: CudaKreyviumStream) -> Self {
        Self::new_gpu(CudaTranscipherSession::Kreyvium(Box::new(inner)))
    }
}

impl HlTranscipherer for TranscipherSession {
    fn transcipher<T>(&mut self, input: &StreamCiphertext) -> crate::Result<T>
    where
        T: HlExpandable + Tagged,
    {
        try_with_internal_keys(|keys| match (&mut self.inner, keys) {
            (InnerTranscipherSession::Cpu(inner), Some(InternalServerKey::Cpu(cpu_key))) => {
                cpu_transcipher(inner, input.integer(), cpu_key)
            }
            #[cfg(feature = "gpu")]
            (InnerTranscipherSession::Gpu(inner), Some(InternalServerKey::Cuda(cuda_key))) => {
                gpu_transcipher(inner, input.integer(), cuda_key)
            }
            (_, None) => Err(UninitializedServerKey.into()),
            #[cfg(any(feature = "gpu", feature = "hpu"))]
            _ => Err(crate::Error::new(
                "TranscipherSession device does not match the current server key device".to_owned(),
            )),
        })
    }

    fn transcipher_list(
        &mut self,
        input: &StreamCiphertextList,
    ) -> crate::Result<CompactCiphertextListExpander> {
        try_with_internal_keys(|keys| match (&mut self.inner, keys) {
            (InnerTranscipherSession::Cpu(inner), Some(InternalServerKey::Cpu(cpu_key))) => {
                cpu_transcipher_list(inner, input.integer(), cpu_key)
            }
            #[cfg(feature = "gpu")]
            (InnerTranscipherSession::Gpu(inner), Some(InternalServerKey::Cuda(cuda_key))) => {
                gpu_transcipher_list(inner, input.integer(), cuda_key)
            }
            (_, None) => Err(UninitializedServerKey.into()),
            #[cfg(any(feature = "gpu", feature = "hpu"))]
            _ => Err(crate::Error::new(
                "TranscipherSession device does not match the current server key device".to_owned(),
            )),
        })
    }
}

fn cpu_transcipher<X, T>(
    session: &mut X,
    input: &IntegerStreamCiphertext,
    cpu_key: &crate::high_level_api::keys::ServerKey,
) -> crate::Result<T>
where
    X: Transcipherer + ?Sized,
    T: Expandable + Tagged,
{
    let integer_sks = &cpu_key.key.key;
    let layout = input
        .output_layout(cpu_key.message_modulus())
        .map_err(|e| crate::error!("{e}"))?;
    let blocks = Transcipherer::transcipher(session, &integer_sks.key, input.inner(), &layout)
        .map_err(|e| crate::error!("{e}"))?;
    let kind = input.kind().to_data_kind(blocks.len())?;
    let mut out = T::from_expanded_blocks(blocks, kind)?;
    out.tag_mut().set_data(cpu_key.tag.data());
    Ok(out)
}

fn cpu_transcipher_list<X>(
    session: &mut X,
    input: &IntegerStreamCiphertextList,
    cpu_key: &crate::high_level_api::keys::ServerKey,
) -> crate::Result<CompactCiphertextListExpander>
where
    X: Transcipherer,
{
    let expander = IntegerTranscipherer::transcipher_list(session, &cpu_key.key.key, input)
        .map_err(|e| crate::error!("{e}"))?;
    Ok(CompactCiphertextListExpander {
        inner: InnerCompactCiphertextListExpander::Cpu(expander),
        tag: cpu_key.tag.clone(),
    })
}

#[cfg(feature = "gpu")]
fn gpu_transcipher<X, T>(
    session: &mut X,
    input: &IntegerStreamCiphertext,
    cuda_key: &crate::high_level_api::CudaServerKey,
) -> crate::Result<T>
where
    X: CudaIntegerTranscipherer + ?Sized,
    T: CudaExpandable + Tagged,
{
    let layout = input
        .output_layout(cuda_key.message_modulus())
        .map_err(|e| crate::error!("{e}"))?;
    let blocks = CudaIntegerTranscipherer::transcipher(
        session,
        cuda_key.pbs_key(),
        input.inner(),
        &layout,
        &cuda_key.streams,
    )
    .map_err(|e| crate::error!("{e}"))?;
    let n_blocks = blocks.d_blocks.lwe_ciphertext_count().0;
    let kind = input.kind().to_data_kind(n_blocks)?;
    let mut out = T::from_expanded_blocks(blocks, kind)?;
    out.tag_mut().set_data(cuda_key.tag.data());
    Ok(out)
}

#[cfg(feature = "gpu")]
fn gpu_transcipher_list<X>(
    session: &mut X,
    input: &IntegerStreamCiphertextList,
    cuda_key: &crate::high_level_api::CudaServerKey,
) -> crate::Result<CompactCiphertextListExpander>
where
    X: CudaIntegerTranscipherer,
{
    let expander = session
        .transcipher_list(cuda_key.pbs_key(), input, &cuda_key.streams)
        .map_err(|e| crate::error!("{e}"))?;
    Ok(CompactCiphertextListExpander {
        inner: InnerCompactCiphertextListExpander::Cuda(expander),
        tag: cuda_key.tag.clone(),
    })
}

#[cfg(test)]
mod test {
    use tfhe_safe_serialize::{safe_deserialize, safe_serialize};

    use crate::shortint::parameters::{OprfParameters, TranscipheringParameters};
    use crate::shortint::prelude::LweDimension;
    use crate::{FheUint64, HlStreamCipher};

    const SIZE_LIMIT: u64 = 1024 * 1024 * 1024;

    #[cfg(feature = "gpu")]
    fn gpu_config() -> crate::ConfigBuilder {
        crate::ConfigBuilder::with_custom_parameters(
            crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )
    }

    #[test]
    fn test_kreyvium() {
        use super::{HlStreamCipher, HlTranscipherer, KreyviumFheKey, TranscipherSession};
        use crate::prelude::*;
        use crate::transciphering::{KreyviumPlainKey, KreyviumPlainState};
        use crate::{generate_keys, set_server_key, ConfigBuilder};
        use rand::Rng;

        let (client_key, server_key) = generate_keys(ConfigBuilder::default());
        set_server_key(server_key);

        // Client: pick a symmetric key + IV and encrypt a u64 with plain Kreyvium.
        let mut rng = rand::thread_rng();
        let key_bits: [bool; 128] = std::array::from_fn(|_| rng.gen());
        let iv_bits: [bool; 128] = std::array::from_fn(|_| rng.gen());
        let mut sym = KreyviumPlainState::new(key_bits, iv_bits);

        let input: u64 = rng.gen();
        let sym_cipher = sym.try_encrypt(input).unwrap();

        // Client → server: ship the FHE-encrypted Kreyvium key (one-time setup).
        let plain_key = KreyviumPlainKey::from(key_bits);
        let fhe_kreyv_key = KreyviumFheKey::encrypt(plain_key, &client_key);

        // The key crosses the wire: round-trip it through versioned serialization.
        let mut serialized = vec![];
        safe_serialize(&fhe_kreyv_key, &mut serialized, SIZE_LIMIT).unwrap();
        let fhe_kreyv_key: KreyviumFheKey =
            safe_deserialize(serialized.as_slice(), SIZE_LIMIT).unwrap();

        // Server: warm up the FHE-side Kreyvium stream and transcipher.
        let mut fhe_stream = TranscipherSession::kreyvium(fhe_kreyv_key, iv_bits).unwrap();
        let transciphered: FheUint64 = fhe_stream.transcipher(&sym_cipher).unwrap();

        // Client: decrypt to recover `input`.
        let recovered: u64 = transciphered.decrypt(&client_key);
        assert_eq!(recovered, input);
    }

    /// Two values packed back-to-back against a single pad: the second input
    /// starts at pad bit 64, so client and server must agree on the offset.
    #[test]
    fn test_one_time_pad() {
        use super::{HlStreamCipher, HlTranscipherer, OneTimePadFheSecretMask, TranscipherSession};
        use crate::prelude::*;
        use crate::transciphering::{OneTimePadPlainSecretMask, OneTimePadPlainState};
        use crate::{generate_keys, set_server_key, ConfigBuilder, FheUint32};
        use rand::Rng;

        let (client_key, server_key) = generate_keys(ConfigBuilder::default());
        set_server_key(server_key);

        let mut rng = rand::thread_rng();
        let n_bits = 64 + 32;
        let pad_bytes: Vec<u8> = (0..n_bits / 8).map(|_| rng.gen()).collect();

        // Client → server: ship the FHE-encrypted pad.
        let fhe_mask = OneTimePadFheSecretMask::try_encrypt(
            OneTimePadPlainSecretMask::new(pad_bytes.clone(), n_bits),
            &client_key,
        )
        .unwrap();

        // The pad crosses the wire: round-trip it through versioned serialization.
        let mut serialized = vec![];
        safe_serialize(&fhe_mask, &mut serialized, SIZE_LIMIT).unwrap();
        let fhe_mask: OneTimePadFheSecretMask =
            safe_deserialize(serialized.as_slice(), SIZE_LIMIT).unwrap();

        // Client: consume the same pad, in order, for both inputs.
        let mut sym = OneTimePadPlainState::new(OneTimePadPlainSecretMask::new(pad_bytes, n_bits));
        let input_a: u64 = rng.gen();
        let input_b: u32 = rng.gen();
        let sym_a = sym.try_encrypt(input_a).unwrap();
        let sym_b = sym.try_encrypt(input_b).unwrap();

        // Server: transcipher both against the same session.
        let mut fhe_stream = TranscipherSession::one_time_pad(fhe_mask).unwrap();
        let transciphered_a: FheUint64 = fhe_stream.transcipher(&sym_a).unwrap();
        let transciphered_b: FheUint32 = fhe_stream.transcipher(&sym_b).unwrap();

        let recovered_a: u64 = transciphered_a.decrypt(&client_key);
        let recovered_b: u32 = transciphered_b.decrypt(&client_key);
        assert_eq!(recovered_a, input_a);
        assert_eq!(recovered_b, input_b);

        // The pad is spent: a further draw must fail rather than reuse bits.
        assert!(sym.try_encrypt(1u8).is_err());
    }

    /// Squash the noise of a pad and compress it, so that it can be decrypted by the KMS.
    #[test]
    fn test_one_time_pad_squashed_noise() {
        use super::{
            CompressedSquashedNoiseOneTimePadFheSecretMask,
            CompressedSquashedNoiseOneTimePadFheSecretMaskConformanceParams,
            OneTimePadFheSecretMask,
        };
        use crate::conformance::ParameterSetConformant;
        use crate::prelude::*;
        use crate::shortint::parameters::current_params::{
            V1_9_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            V1_9_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            V1_9_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        };
        use crate::transciphering::{KeyStreamLayout, OneTimePadPlainSecretMask};
        use crate::{
            generate_keys, set_server_key, CompressedSquashedNoiseCiphertextListConformanceParams,
            ConfigBuilder,
        };
        use rand::Rng;

        let config = ConfigBuilder::with_custom_parameters(
            V1_9_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )
        .enable_noise_squashing(V1_9_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
        .enable_noise_squashing_compression(
            V1_9_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )
        .build();
        let (client_key, server_key) = generate_keys(config);
        let conformance_params =
            CompressedSquashedNoiseOneTimePadFheSecretMaskConformanceParams::try_from(&server_key)
                .unwrap();
        // The pad is generated with the full space layout, so another layout is refused
        let single_bit_params =
            CompressedSquashedNoiseOneTimePadFheSecretMaskConformanceParams::new(
                CompressedSquashedNoiseCiphertextListConformanceParams::try_from(&server_key)
                    .unwrap(),
                KeyStreamLayout::single_bit(),
            );
        set_server_key(server_key);

        let mut rng = rand::thread_rng();
        let n_bits = 64;
        let pad_bytes: Vec<u8> = (0..n_bits / 8).map(|_| rng.gen()).collect();
        let plain_mask = OneTimePadPlainSecretMask::new(pad_bytes, n_bits);

        let squashed = OneTimePadFheSecretMask::try_encrypt(plain_mask.clone(), &client_key)
            .unwrap()
            .squash_noise()
            .unwrap();
        assert!(squashed.decrypt(&client_key) == plain_mask);

        let compressed = squashed.compress().unwrap();

        // The compressed pad crosses the wire to the KMS
        let mut serialized = vec![];
        safe_serialize(&compressed, &mut serialized, SIZE_LIMIT).unwrap();
        let compressed: CompressedSquashedNoiseOneTimePadFheSecretMask =
            safe_deserialize(serialized.as_slice(), SIZE_LIMIT).unwrap();
        assert!(compressed.is_conformant(&conformance_params));
        assert!(!compressed.is_conformant(&single_bit_params));
        assert!(compressed.decrypt(&client_key) == plain_mask);

        // Decompression requires no key, and the result is decrypted with the compression key
        let decompressed = compressed.decompress().unwrap();
        assert!(decompressed.decrypt(&client_key) == plain_mask);

        // A decompressed mask is under the compression key, so it cannot be compressed again
        assert!(decompressed.compress().is_err());
    }

    #[test]
    fn test_stream_ciphertext_list() {
        use super::{
            HlTranscipherer, OneTimePadFheSecretMask, StreamCiphertextList, TranscipherSession,
        };
        use crate::prelude::*;
        use crate::transciphering::{OneTimePadPlainSecretMask, OneTimePadPlainState};
        use crate::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheInt8, FheUint4};
        use rand::Rng;

        let (client_key, server_key) = generate_keys(ConfigBuilder::default());
        set_server_key(server_key);

        let mut rng = rand::thread_rng();
        let input_a: u64 = rng.gen();
        let input_b: bool = rng.gen();
        let input_c: i8 = rng.gen();
        let input_d: u8 = rng.gen_range(0..16);

        let mut builder = StreamCiphertextList::builder();
        builder
            .push(input_a)
            .push(input_b)
            .push(input_c)
            .push_with_num_bits(input_d, 4);
        // Each value starts on a byte boundary
        let n_bits = builder.n_bits();
        assert_eq!(n_bits, 64 + 8 + 8 + 8);

        let pad_bytes: Vec<u8> = (0..n_bits / 8).map(|_| rng.gen()).collect();
        let pad = OneTimePadPlainSecretMask::new(pad_bytes, n_bits);

        // Client: encrypt the values with the pad
        let list = builder
            .build(&mut OneTimePadPlainState::new(pad.clone()))
            .unwrap();

        let mut serialized = vec![];
        safe_serialize(&list, &mut serialized, SIZE_LIMIT).unwrap();
        let list: StreamCiphertextList =
            safe_deserialize(serialized.as_slice(), SIZE_LIMIT).unwrap();

        assert_eq!(list.n_bits(), n_bits);

        // Server: transcipher the whole list with the FHE pad
        let fhe_mask = OneTimePadFheSecretMask::try_encrypt(pad, &client_key).unwrap();
        let mut fhe_stream = TranscipherSession::one_time_pad(fhe_mask).unwrap();
        let expander = fhe_stream.transcipher_list(&list).unwrap();
        assert_eq!(expander.len(), 4);

        let a: FheUint64 = expander.get(0).unwrap().unwrap();
        let b: FheBool = expander.get(1).unwrap().unwrap();
        let c: FheInt8 = expander.get(2).unwrap().unwrap();
        let d: FheUint4 = expander.get(3).unwrap().unwrap();

        let a: u64 = a.decrypt(&client_key);
        let b: bool = b.decrypt(&client_key);
        let c: i8 = c.decrypt(&client_key);
        let d: u8 = d.decrypt(&client_key);
        assert_eq!((a, b, c, d), (input_a, input_b, input_c, input_d));
    }

    #[test]
    fn test_stream_ciphertext_list_conformance() {
        use super::StreamCiphertextList;
        use crate::conformance::ParameterSetConformant;
        use crate::integer::transciphering::{
            IntegerStreamCiphertextListConformanceParams, IntegerStreamCiphertextPart,
        };
        use crate::shortint::parameters::current_params::V1_9_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        use crate::shortint::MessageModulus;
        use crate::transciphering::{KreyviumPlainKey, KreyviumPlainState, StreamCipherKind};

        let mut cipher = KreyviumPlainState::new(KreyviumPlainKey::from([7u8; 16]), [3u8; 16]);
        let list = StreamCiphertextList::builder()
            .push(42u32)
            .push(true)
            .build(&mut cipher)
            .unwrap();

        let matching = IntegerStreamCiphertextListConformanceParams::from_parameters_and_max_n_bits(
            V1_9_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            StreamCipherKind::Kreyvium,
            40,
        );
        assert!(list.is_conformant(&matching));

        for mismatched in [
            IntegerStreamCiphertextListConformanceParams {
                cipher_kind: StreamCipherKind::OneTimePad,
                ..matching
            },
            IntegerStreamCiphertextListConformanceParams {
                max_n_bits: 39,
                ..matching
            },
            // 32 bits do not fill whole 3-bit blocks
            IntegerStreamCiphertextListConformanceParams {
                message_modulus: MessageModulus(8),
                ..matching
            },
        ] {
            assert!(!list.is_conformant(&mismatched));
        }

        // Simulate an attacker sending parts that do not describe the stream bits
        {
            #[derive(serde::Serialize)]
            struct Tampered {
                inner: crate::transciphering::StreamCiphertext,
                info: Vec<IntegerStreamCiphertextPart>,
            }

            let tampered = bincode::serialize(&Tampered {
                inner: list.integer().inner().clone(),
                info: vec![
                    IntegerStreamCiphertextPart::Unsigned(32.try_into().unwrap()),
                    IntegerStreamCiphertextPart::Unsigned(16.try_into().unwrap()),
                ],
            })
            .unwrap();
            let tampered: StreamCiphertextList = bincode::deserialize(&tampered).unwrap();

            assert!(!tampered.is_conformant(&matching));
        }
    }

    #[test]
    fn test_stream_ciphertext_conformance() {
        use super::HlStreamCipher;
        use crate::conformance::ParameterSetConformant;
        use crate::integer::transciphering::{
            IntegerStreamCiphertextConformanceParams, IntegerStreamCiphertextKind,
        };
        use crate::transciphering::{KreyviumPlainKey, KreyviumPlainState, StreamCipherKind};

        let mut cipher = KreyviumPlainState::new(KreyviumPlainKey::from([7u8; 16]), [3u8; 16]);
        let ct = cipher.try_encrypt(42u64).unwrap();

        let matching = IntegerStreamCiphertextConformanceParams {
            cipher_kind: StreamCipherKind::Kreyvium,
            kind: IntegerStreamCiphertextKind::Unsigned,
            n_bits: 64,
        };
        assert!(ct.is_conformant(&matching));

        // Simulate an attacker building a tampered ciphertext
        {
            #[derive(serde::Serialize)]
            struct Tampered {
                kind: StreamCipherKind,
                encryption_counter: u64,
                n_bits: usize,
                bytes: Vec<u8>,
            }

            let tampered = bincode::serialize(&Tampered {
                kind: StreamCipherKind::Kreyvium,
                encryption_counter: 0,
                n_bits: 64,
                bytes: vec![0; 4],
            })
            .unwrap();
            let tampered: crate::transciphering::StreamCiphertext =
                bincode::deserialize(&tampered).unwrap();
            let tampered = super::StreamCiphertext::from_raw_parts(
                crate::integer::transciphering::IntegerStreamCiphertext::from_raw_parts(
                    tampered,
                    IntegerStreamCiphertextKind::Unsigned,
                ),
            );

            assert_eq!(tampered.n_bits(), 64);
            assert!(!tampered.is_conformant(&matching));
        }

        for mismatched in [
            IntegerStreamCiphertextConformanceParams {
                cipher_kind: StreamCipherKind::Aes,
                ..matching
            },
            IntegerStreamCiphertextConformanceParams {
                kind: IntegerStreamCiphertextKind::Signed,
                ..matching
            },
            IntegerStreamCiphertextConformanceParams {
                n_bits: 32,
                ..matching
            },
        ] {
            assert!(!ct.is_conformant(&mismatched), "{mismatched:?}");
        }
    }

    /// A ciphertext tagged as Boolean but carrying more than 1 bit must be rejected before any
    /// keystream is consumed, otherwise the resulting FheBool could encrypt a value > 1.
    #[test]
    fn test_forged_boolean_is_rejected() {
        use super::{HlTranscipherer, OneTimePadFheSecretMask, TranscipherSession};
        use crate::integer::transciphering::{
            IntegerStreamCiphertext, IntegerStreamCiphertextKind,
        };
        use crate::prelude::*;
        use crate::transciphering::{
            OneTimePadPlainSecretMask, OneTimePadPlainState, StreamCipher,
        };
        use crate::{generate_keys, set_server_key, ConfigBuilder, FheBool};
        use rand::Rng;

        let mut rng = rand::thread_rng();

        let (client_key, server_key) = generate_keys(ConfigBuilder::default());
        set_server_key(server_key);

        let pad_bytes = vec![0b1010_0110u8];
        let fhe_mask = OneTimePadFheSecretMask::try_encrypt(
            OneTimePadPlainSecretMask::new(pad_bytes.clone(), 8),
            &client_key,
        )
        .unwrap();
        let mut fhe_stream = TranscipherSession::one_time_pad(fhe_mask).unwrap();

        // Malicious client: encrypt 2 bits (value 3) and tag them as a Boolean.
        let mut sym =
            OneTimePadPlainState::new(OneTimePadPlainSecretMask::new(pad_bytes.clone(), 8));
        let forged = sym.encrypt_bits(&[0b11], 2).unwrap();
        let forged = super::StreamCiphertext::from_raw_parts(
            IntegerStreamCiphertext::from_raw_parts(forged, IntegerStreamCiphertextKind::Boolean),
        );

        let res: crate::Result<FheBool> = fhe_stream.transcipher(&forged);
        assert!(res.is_err());

        // The rejected input must not have consumed keystream: an honest bool at the same
        // position still transciphers.
        let mut sym = OneTimePadPlainState::new(OneTimePadPlainSecretMask::new(pad_bytes, 8));
        let val: bool = rng.gen();
        let honest = sym.try_encrypt(val).unwrap();
        let transciphered: FheBool = fhe_stream.transcipher(&honest).unwrap();
        assert_eq!(val, transciphered.decrypt(&client_key));
    }

    /// Integers whose bit count does not fill whole blocks are rejected before any keystream is
    /// consumed: a partial top block would decode wrongly for signed values.
    #[test]
    fn test_radix_partial_block_is_rejected() {
        use super::{HlStreamCipher, HlTranscipherer, OneTimePadFheSecretMask, TranscipherSession};
        use crate::prelude::*;
        use crate::transciphering::{OneTimePadPlainSecretMask, OneTimePadPlainState};
        use crate::{generate_keys, set_server_key, ConfigBuilder, FheInt14, FheUint14};

        let (client_key, server_key) = generate_keys(ConfigBuilder::default());
        set_server_key(server_key);

        let pad_bytes = vec![0x5a, 0xc3];
        let new_pad = || OneTimePadPlainSecretMask::new(pad_bytes.clone(), 16);
        let fhe_mask = OneTimePadFheSecretMask::try_encrypt(new_pad(), &client_key).unwrap();
        let mut fhe_stream = TranscipherSession::one_time_pad(fhe_mask).unwrap();

        // 13 bits do not fill whole 2-bit blocks with the default parameters
        let mut sym = OneTimePadPlainState::new(new_pad());
        let signed = sym.try_encrypt_with_num_bits(-1i16, 13).unwrap();
        let res: crate::Result<FheInt14> = fhe_stream.transcipher(&signed);
        assert!(res.is_err());

        let mut sym = OneTimePadPlainState::new(new_pad());
        let unsigned = sym.try_encrypt_with_num_bits(100u16, 13).unwrap();
        let res: crate::Result<FheUint14> = fhe_stream.transcipher(&unsigned);
        assert!(res.is_err());

        // The rejected inputs must not have consumed keystream, and a bit count that fills
        // whole blocks keeps its sign.
        let mut sym = OneTimePadPlainState::new(new_pad());
        let signed = sym.try_encrypt_with_num_bits(-1i16, 14).unwrap();
        let transciphered: FheInt14 = fhe_stream.transcipher(&signed).unwrap();
        let recovered: i16 = transciphered.decrypt(&client_key);
        assert_eq!(recovered, -1);
    }

    /// The pad picks up the tag of the key set it was generated under and keeps it across the
    /// wire, and what it transciphers is tagged like any other ciphertext of that key set.
    #[test]
    fn test_tag_propagation() {
        use super::{HlStreamCipher, HlTranscipherer, OneTimePadFheSecretMask, TranscipherSession};
        use crate::prelude::*;
        use crate::safe_serialization::{safe_deserialize, safe_serialize};
        use crate::shortint::parameters::TranscipheringParameters;
        use crate::transciphering::OneTimePadPlainState;
        use crate::{set_server_key, ClientKey, ConfigBuilder, Seed, ServerKey};

        const KEY_SET: u64 = 0x00C0_FFEE;

        let config =
            ConfigBuilder::default().enable_transciphering(TranscipheringParameters::SameAsCompute);
        let mut client_key = ClientKey::generate(config);
        client_key.tag_mut().set_u64(KEY_SET);
        let server_key = ServerKey::new(&client_key);
        set_server_key(server_key);

        // Server: the OPRF-generated pad inherits the server key's tag, so a pad travelling on its
        // own still says which key set it belongs to.
        // Do not use static seed in production
        let fhe_mask = OneTimePadFheSecretMask::new_random(Seed(0), 64).unwrap();
        assert_eq!(fhe_mask.tag().as_u64(), KEY_SET);

        // The tag survives the wire.
        let mut serialized = vec![];
        safe_serialize(&fhe_mask, &mut serialized, SIZE_LIMIT).unwrap();
        let fhe_mask: OneTimePadFheSecretMask =
            safe_deserialize(serialized.as_slice(), SIZE_LIMIT).unwrap();
        assert_eq!(fhe_mask.tag().as_u64(), KEY_SET);

        let mut sym = OneTimePadPlainState::new(fhe_mask.decrypt(&client_key));
        let sym_cipher = sym.try_encrypt(42u64).unwrap();

        // The transciphered output is tagged from the server key, like every other HL operation:
        // it is the key set that bootstrapped it that decides which client key decrypts it.
        let mut fhe_stream = TranscipherSession::one_time_pad(fhe_mask).unwrap();
        let transciphered: FheUint64 = fhe_stream.transcipher(&sym_cipher).unwrap();
        assert_eq!(transciphered.tag().as_u64(), KEY_SET);

        let recovered: u64 = transciphered.decrypt(&client_key);
        assert_eq!(recovered, 42);
    }

    /// The pad is generated server-side by the OPRF, then decrypted by the
    /// client, which is the direction the transciphering protocol uses.
    #[test]
    fn test_one_time_pad_using_oprf() {
        for params in [
            TranscipheringParameters::SameAsCompute,
            TranscipheringParameters::DedicatedOprf(OprfParameters {
                lwe_dimension: LweDimension(600),
            }),
        ] {
            test_one_time_pad_using_oprf_impl(params)
        }
    }

    fn test_one_time_pad_using_oprf_impl(params: TranscipheringParameters) {
        use super::{HlStreamCipher, HlTranscipherer, OneTimePadFheSecretMask, TranscipherSession};
        use crate::prelude::*;
        use crate::transciphering::{OneTimePadPlainSecretMask, OneTimePadPlainState};
        use crate::{generate_keys, set_server_key, ConfigBuilder, Seed};
        use rand::Rng;

        let mut rng = rand::thread_rng();

        let (client_key, server_key) =
            generate_keys(ConfigBuilder::default().enable_transciphering(params));
        set_server_key(server_key);

        // Server: generate a random FHE pad.
        let seed = rng.gen();
        let fhe_mask = OneTimePadFheSecretMask::new_random(Seed(seed), 64).unwrap();

        // The pad crosses the wire: round-trip it through versioned serialization.
        let mut serialized = vec![];
        safe_serialize(&fhe_mask, &mut serialized, SIZE_LIMIT).unwrap();
        let fhe_mask: OneTimePadFheSecretMask =
            safe_deserialize(serialized.as_slice(), SIZE_LIMIT).unwrap();

        // Client: decrypt the pad, then encrypt with it.
        let plain_mask: OneTimePadPlainSecretMask = fhe_mask.decrypt(&client_key);
        let mut sym = OneTimePadPlainState::new(plain_mask);

        let input: u64 = rng.gen();
        let sym_cipher = sym.try_encrypt(input).unwrap();

        // Server: re-generate the pad using the same seed and transcipher.
        let fhe_mask = OneTimePadFheSecretMask::new_random(Seed(seed), 64).unwrap();
        let mut fhe_stream = TranscipherSession::one_time_pad(fhe_mask).unwrap();
        let transciphered: FheUint64 = fhe_stream.transcipher(&sym_cipher).unwrap();

        let recovered: u64 = transciphered.decrypt(&client_key);
        assert_eq!(recovered, input);
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn test_gpu_one_time_pad_using_oprf() {
        for params in [
            TranscipheringParameters::SameAsCompute,
            TranscipheringParameters::DedicatedOprf(OprfParameters {
                lwe_dimension: LweDimension(600),
            }),
        ] {
            test_gpu_one_time_pad_using_oprf_impl(params)
        }
    }

    /// The CPU scenario with a server key on GPU. The pad also goes through each conversion of
    /// its GPU variant: decryption, serialization (which clones it), encryption. The pad sent to
    /// the client and the one used to transcipher may come from different devices, so a seed must
    /// give the same pad on CPU and on GPU.
    #[cfg(feature = "gpu")]
    fn test_gpu_one_time_pad_using_oprf_impl(params: TranscipheringParameters) {
        use super::{HlStreamCipher, HlTranscipherer, OneTimePadFheSecretMask, TranscipherSession};
        use crate::prelude::*;
        use crate::transciphering::{OneTimePadPlainSecretMask, OneTimePadPlainState};
        use crate::{set_server_key, ClientKey, CompressedServerKey, Seed};
        use rand::Rng;

        const KEY_SET: u64 = 0x00C0_FFEE;

        let mut rng = rand::thread_rng();

        let mut client_key = ClientKey::generate(gpu_config().enable_transciphering(params));
        client_key.tag_mut().set_u64(KEY_SET);
        let compressed_server_key = CompressedServerKey::new(&client_key);

        // Server: generate a random FHE pad on CPU, then on GPU with the same seed
        let seed = rng.gen();
        set_server_key(compressed_server_key.decompress());
        let cpu_mask = OneTimePadFheSecretMask::new_random(Seed(seed), 64).unwrap();
        set_server_key(compressed_server_key.decompress_to_gpu());
        let fhe_mask = OneTimePadFheSecretMask::new_random(Seed(seed), 64).unwrap();
        assert_eq!(fhe_mask.tag().as_u64(), KEY_SET);

        let plain_mask: OneTimePadPlainSecretMask = fhe_mask.decrypt(&client_key);
        assert!(cpu_mask.decrypt(&client_key) == plain_mask);

        // Serialization brings the pad back to the CPU
        let mut serialized = vec![];
        safe_serialize(&fhe_mask, &mut serialized, SIZE_LIMIT).unwrap();
        let deserialized: OneTimePadFheSecretMask =
            safe_deserialize(serialized.as_slice(), SIZE_LIMIT).unwrap();
        assert!(deserialized.decrypt(&client_key) == plain_mask);
        assert_eq!(deserialized.tag().as_u64(), KEY_SET);

        // With a server key on GPU, an encrypted pad goes to the GPU
        let encrypted =
            OneTimePadFheSecretMask::try_encrypt(plain_mask.clone(), &client_key).unwrap();
        assert!(encrypted.decrypt(&client_key) == plain_mask);

        // Client: encrypt with the pad
        let mut sym = OneTimePadPlainState::new(plain_mask);
        let input: u64 = rng.gen();
        let sym_cipher = sym.try_encrypt(input).unwrap();

        // Server: re-generate the pad using the same seed and transcipher, on GPU
        let fhe_mask = OneTimePadFheSecretMask::new_random(Seed(seed), 64).unwrap();
        let mut fhe_stream = TranscipherSession::one_time_pad(fhe_mask).unwrap();
        let transciphered: FheUint64 = fhe_stream.transcipher(&sym_cipher).unwrap();
        assert_eq!(transciphered.tag().as_u64(), KEY_SET);

        let recovered: u64 = transciphered.decrypt(&client_key);
        assert_eq!(recovered, input);
    }

    /// The server side errors of the CPU tests, with a server key on GPU. Each input is rejected
    /// before drawing any pad bit, so the honest input at the end still gets the start of the pad.
    #[cfg(feature = "gpu")]
    #[test]
    fn test_gpu_one_time_pad_rejected_inputs() {
        use super::{
            HlStreamCipher, HlTranscipherer, OneTimePadFheSecretMask, StreamCiphertext,
            TranscipherSession,
        };
        use crate::integer::transciphering::{
            IntegerStreamCiphertext, IntegerStreamCiphertextKind,
        };
        use crate::prelude::*;
        use crate::transciphering::{
            KreyviumPlainKey, KreyviumPlainState, OneTimePadPlainSecretMask, OneTimePadPlainState,
            StreamCipher,
        };
        use crate::{
            set_server_key, ClientKey, CompressedServerKey, FheBool, FheInt14, FheUint16,
            FheUint32, FheUint8,
        };
        use rand::Rng;

        let client_key = ClientKey::generate(gpu_config());
        set_server_key(CompressedServerKey::new(&client_key).decompress_to_gpu());

        let mut rng = rand::thread_rng();
        let pad_bytes: Vec<u8> = (0..2).map(|_| rng.gen()).collect();
        let new_pad = || OneTimePadPlainSecretMask::new(pad_bytes.clone(), 16);

        let fhe_mask = OneTimePadFheSecretMask::try_encrypt(new_pad(), &client_key).unwrap();
        let mut fhe_stream = TranscipherSession::one_time_pad(fhe_mask).unwrap();

        // 2 bits tagged as a Boolean
        let forged = OneTimePadPlainState::new(new_pad())
            .encrypt_bits(&[0b11], 2)
            .unwrap();
        let forged = StreamCiphertext::from_raw_parts(IntegerStreamCiphertext::from_raw_parts(
            forged,
            IntegerStreamCiphertextKind::Boolean,
        ));
        assert!(fhe_stream.transcipher::<FheBool>(&forged).is_err());

        // 13 bits do not fill whole 2 bit blocks
        let partial = OneTimePadPlainState::new(new_pad())
            .try_encrypt_with_num_bits(-1i16, 13)
            .unwrap();
        assert!(fhe_stream.transcipher::<FheInt14>(&partial).is_err());

        // Encrypted by another cipher
        let kreyvium = KreyviumPlainState::new(KreyviumPlainKey::from([7u8; 16]), [3u8; 16])
            .try_encrypt(42u16)
            .unwrap();
        assert!(fhe_stream.transcipher::<FheUint16>(&kreyvium).is_err());

        // Encrypted after the counter of the session
        let mut sym = OneTimePadPlainState::new(new_pad());
        sym.try_encrypt(0u8).unwrap();
        let ahead = sym.try_encrypt(1u8).unwrap();
        assert!(fhe_stream.transcipher::<FheUint8>(&ahead).is_err());

        // Longer than the pad of the session
        let mut longer_pad_bytes = pad_bytes.clone();
        longer_pad_bytes.extend([rng.gen::<u8>(), rng.gen()]);
        let long = OneTimePadPlainState::new(OneTimePadPlainSecretMask::new(longer_pad_bytes, 32))
            .try_encrypt(rng.gen::<u32>())
            .unwrap();
        assert!(fhe_stream.transcipher::<FheUint32>(&long).is_err());

        let input: u16 = rng.gen();
        let honest = OneTimePadPlainState::new(new_pad())
            .try_encrypt(input)
            .unwrap();
        let transciphered: FheUint16 = fhe_stream.transcipher(&honest).unwrap();
        let recovered: u16 = transciphered.decrypt(&client_key);
        assert_eq!(recovered, input);
    }

    /// The CPU test with a server key on GPU, plus an empty list. The backend cannot take one, it
    /// must still give an empty expander as on CPU.
    #[cfg(feature = "gpu")]
    #[test]
    fn test_gpu_stream_ciphertext_list() {
        use super::{
            HlTranscipherer, OneTimePadFheSecretMask, StreamCiphertextList, TranscipherSession,
        };
        use crate::prelude::*;
        use crate::transciphering::{OneTimePadPlainSecretMask, OneTimePadPlainState};
        use crate::{set_server_key, ClientKey, CompressedServerKey, FheBool, FheInt8, FheUint4};
        use rand::Rng;

        let client_key = ClientKey::generate(gpu_config());
        set_server_key(CompressedServerKey::new(&client_key).decompress_to_gpu());

        let mut rng = rand::thread_rng();
        let input_a: u64 = rng.gen();
        let input_b: bool = rng.gen();
        let input_c: i8 = rng.gen();
        let input_d: u8 = rng.gen_range(0..16);

        let mut builder = StreamCiphertextList::builder();
        builder
            .push(input_a)
            .push(input_b)
            .push(input_c)
            .push_with_num_bits(input_d, 4);
        let n_bits = builder.n_bits();

        let pad_bytes: Vec<u8> = (0..n_bits / 8).map(|_| rng.gen()).collect();
        let pad = OneTimePadPlainSecretMask::new(pad_bytes, n_bits);

        // Client: encrypt the values with the pad, then an empty list with what remains of it
        let mut sym = OneTimePadPlainState::new(pad.clone());
        let list = builder.build(&mut sym).unwrap();
        let empty_list = StreamCiphertextList::builder().build(&mut sym).unwrap();

        // Server: transcipher both lists with the FHE pad, on GPU
        let fhe_mask = OneTimePadFheSecretMask::try_encrypt(pad, &client_key).unwrap();
        let mut fhe_stream = TranscipherSession::one_time_pad(fhe_mask).unwrap();
        let expander = fhe_stream.transcipher_list(&list).unwrap();
        assert_eq!(expander.len(), 4);

        let a: FheUint64 = expander.get(0).unwrap().unwrap();
        let b: FheBool = expander.get(1).unwrap().unwrap();
        let c: FheInt8 = expander.get(2).unwrap().unwrap();
        let d: FheUint4 = expander.get(3).unwrap().unwrap();

        let a: u64 = a.decrypt(&client_key);
        let b: bool = b.decrypt(&client_key);
        let c: i8 = c.decrypt(&client_key);
        let d: u8 = d.decrypt(&client_key);
        assert_eq!((a, b, c, d), (input_a, input_b, input_c, input_d));

        let empty_expander = fhe_stream.transcipher_list(&empty_list).unwrap();
        assert_eq!(empty_expander.len(), 0);
    }
}
