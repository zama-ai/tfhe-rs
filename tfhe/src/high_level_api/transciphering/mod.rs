use crate::core_crypto::prelude::Numeric;
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
use crate::integer::gpu::transciphering::CudaIntegerTranscipherer;
use crate::integer::transciphering::{
    IntegerStreamCipher, IntegerStreamCiphertext, IntegerStreamCiphertextKind,
};
use crate::transciphering::{StreamCipher, Transcipherer};

mod aes;
mod kreyvium;
mod one_time_pad;
mod stream_ciphertext;

pub use aes::AesFheKey;
pub use kreyvium::KreyviumFheKey;
pub use one_time_pad::OneTimePadFheSecretMask;
pub use stream_ciphertext::StreamCiphertext;

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
        assert!(
            n_bits.is_none_or(|n| n == 1),
            "HlStreamCipher: bool inputs must have n_bits == 1"
        );
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

// dbg! if T is signed then recompose_unsigned_with_size can have problems
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
}

pub enum TranscipherSession {
    Cpu(crate::transciphering::TranscipherSession),
    #[cfg(feature = "gpu")] // TODO: kreyvium???
    Gpu(CudaKreyviumStream),
}

impl From<crate::transciphering::TranscipherSession> for TranscipherSession {
    fn from(inner: crate::transciphering::TranscipherSession) -> Self {
        Self::Cpu(inner)
    }
}

#[cfg(feature = "gpu")]
impl From<CudaKreyviumStream> for TranscipherSession {
    fn from(inner: CudaKreyviumStream) -> Self {
        Self::Gpu(inner)
    }
}

impl HlTranscipherer for TranscipherSession {
    fn transcipher<T>(&mut self, input: &StreamCiphertext) -> crate::Result<T>
    where
        T: HlExpandable + Tagged,
    {
        try_with_internal_keys(|keys| match (self, keys) {
            (Self::Cpu(inner), Some(InternalServerKey::Cpu(cpu_key))) => {
                cpu_transcipher(inner, input.integer(), cpu_key)
            }
            #[cfg(feature = "gpu")]
            (Self::Gpu(inner), Some(InternalServerKey::Cuda(cuda_key))) => {
                gpu_transcipher::<T>(inner, input.integer(), cuda_key)
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
    let blocks = Transcipherer::transcipher(session, &integer_sks.key, input.inner())
        .map_err(|e| crate::error!("{e}"))?;
    let kind = input.kind().to_data_kind(blocks.len())?;
    let mut out = T::from_expanded_blocks(blocks, kind)?;
    out.tag_mut().set_data(cpu_key.tag.data());
    Ok(out)
}

#[cfg(feature = "gpu")]
fn gpu_transcipher<T>(
    session: &mut CudaKreyviumStream,
    input: &IntegerStreamCiphertext,
    cuda_key: &crate::high_level_api::CudaServerKey,
) -> crate::Result<T>
where
    T: CudaExpandable + Tagged,
{
    let blocks = CudaIntegerTranscipherer::transcipher(
        session,
        cuda_key.pbs_key(),
        input.inner(),
        &cuda_key.streams,
    )
    .map_err(|e| crate::error!("{e}"))?;
    let n_blocks = blocks.d_blocks.lwe_ciphertext_count().0;
    let kind = input.kind().to_data_kind(n_blocks)?;
    let mut out = T::from_expanded_blocks(blocks, kind)?;
    out.tag_mut().set_data(cuda_key.tag.data());
    Ok(out)
}

#[cfg(test)]
mod test {
    use crate::FheUint64;

    #[test]
    fn test_kreyvium() {
        use super::{HlStreamCipher, HlTranscipherer, KreyviumFheKey, TranscipherSession};
        use crate::prelude::*;
        use crate::transciphering::{KreyviumPlainKey, KreyviumPlainState};
        use crate::{generate_keys, set_server_key, ConfigBuilder};
        use rand::Rng;
        use tfhe_versionable::{Unversionize, Versionize};

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
        let serialized = bincode::serialize(&fhe_kreyv_key.versionize()).unwrap();
        let fhe_kreyv_key =
            KreyviumFheKey::unversionize(bincode::deserialize(&serialized).unwrap()).unwrap();

        // Server: warm up the FHE-side Kreyvium stream and transcipher.
        let mut fhe_stream = TranscipherSession::kreyvium(fhe_kreyv_key, iv_bits).unwrap();
        let transciphered: FheUint64 = fhe_stream.transcipher(&sym_cipher).unwrap();

        // Client: decrypt to recover `input`.
        let recovered: u64 = transciphered.decrypt(&client_key);
        assert_eq!(recovered, input);
    }

    #[test]
    fn test_using_otp() {
        use super::{HlStreamCipher, HlTranscipherer, KreyviumFheKey, TranscipherSession};
        use crate::prelude::*;
        use crate::shortint::parameters::TranscipheringParameters;
        use crate::transciphering::KreyviumPlainState;
        use crate::{generate_keys, set_server_key, ConfigBuilder, Seed};
        use rand::Rng;

        let (client_key, server_key) = generate_keys(
            ConfigBuilder::default().enable_transciphering(TranscipheringParameters::SameAsCompute),
        );
        set_server_key(server_key);

        let seed = Seed(0);

        // Server: Generate some random kreyvium key:
        let fhe_kreyv_key = KreyviumFheKey::random(seed).unwrap();
        let mut rng = rand::thread_rng();
        let iv_bits: [bool; 128] = std::array::from_fn(|_| rng.gen());

        // Client: decrypts the key, get iv and start encrypting stuff
        let krey_key = fhe_kreyv_key.decrypt(&client_key);
        let mut sym = KreyviumPlainState::new(krey_key, iv_bits);

        let input: u64 = rng.gen();
        let sym_cipher = sym.try_encrypt(input).unwrap();

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
        use tfhe_versionable::{Unversionize, Versionize};

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
        let serialized = bincode::serialize(&fhe_mask.versionize()).unwrap();
        let fhe_mask =
            OneTimePadFheSecretMask::unversionize(bincode::deserialize(&serialized).unwrap())
                .unwrap();

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

    /// The pad is generated server-side by the OPRF, then decrypted by the
    /// client, which is the direction the transciphering protocol uses.
    #[test]
    fn test_one_time_pad_using_oprf() {
        use super::{HlStreamCipher, HlTranscipherer, OneTimePadFheSecretMask, TranscipherSession};
        use crate::prelude::*;
        use crate::shortint::parameters::TranscipheringParameters;
        use crate::transciphering::{OneTimePadPlainSecretMask, OneTimePadPlainState};
        use crate::{generate_keys, set_server_key, ConfigBuilder, Seed};
        use rand::Rng;

        let (client_key, server_key) = generate_keys(
            ConfigBuilder::default().enable_transciphering(TranscipheringParameters::SameAsCompute),
        );
        set_server_key(server_key);

        // Server: generate a random FHE pad.
        let fhe_mask = OneTimePadFheSecretMask::random(Seed(0), 64).unwrap();

        // Client: decrypt the pad, then encrypt with it.
        let plain_mask: OneTimePadPlainSecretMask = fhe_mask.decrypt(&client_key);
        let mut sym = OneTimePadPlainState::new(plain_mask);

        let mut rng = rand::thread_rng();
        let input: u64 = rng.gen();
        let sym_cipher = sym.try_encrypt(input).unwrap();

        // Server: transcipher against the pad it generated.
        let mut fhe_stream = TranscipherSession::one_time_pad(fhe_mask).unwrap();
        let transciphered: FheUint64 = fhe_stream.transcipher(&sym_cipher).unwrap();

        let recovered: u64 = transciphered.decrypt(&client_key);
        assert_eq!(recovered, input);
    }
}
