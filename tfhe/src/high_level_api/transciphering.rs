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
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
#[cfg(feature = "gpu")]
use crate::integer::gpu::server_key::radix::CudaKreyviumStream;
#[cfg(feature = "gpu")]
use crate::integer::gpu::transciphering::CudaIntegerTranscipherer;
//dbg!("Should we crate a small hlapi wrapper for this to make backward compat simpler?")
pub use crate::integer::transciphering::IntegerStreamCiphertext;
use crate::integer::transciphering::{IntegerStreamCipher, IntegerStreamKind};
#[cfg(feature = "gpu")]
use crate::integer::RadixCiphertext;
use crate::prelude::{FheDecrypt, FheTryEncrypt};
use crate::shortint::oprf::OprfSeed;
use crate::transciphering::{
    AesFheKey as ShortintAesFheKey, AesFheRoundKeys, AesFheState, AesIv, AesPlainKey,
    KreyviumFheKey as ShortintKreyviumFheKey, KreyviumFheState, KreyviumIV, KreyviumPlainKey,
    StreamCipher, Transcipherer,
};
use crate::ClientKey;

/// Types encryptable by [`HlStreamCipher`].
pub trait HlStreamEncryptable {
    /// `self` should encrypt itself using the `cipher`
    ///
    /// `n_bits` is a hint on the number of bits to encrypt
    ///     - None => encrypt all the bits of the `Self` type
    ///     - Some(n) => encrypt `n` bits, truncating or padding if necessary
    fn hl_stream_encrypt<C>(self, cipher: &mut C, n_bits: Option<usize>) -> IntegerStreamCiphertext
    where
        C: StreamCipher + ?Sized;
}

impl HlStreamEncryptable for bool {
    fn hl_stream_encrypt<C>(self, cipher: &mut C, n_bits: Option<usize>) -> IntegerStreamCiphertext
    where
        C: StreamCipher + ?Sized,
    {
        assert!(
            n_bits.is_none_or(|n| n == 1),
            "HlStreamCipher: bool inputs must have n_bits == 1"
        );
        cipher.encrypt_bool(self)
    }
}

impl<T> HlStreamEncryptable for T
where
    T: DecomposableInto<u8> + Numeric + std::ops::Shl<usize, Output = T>,
{
    fn hl_stream_encrypt<C>(self, cipher: &mut C, n_bits: Option<usize>) -> IntegerStreamCiphertext
    where
        C: StreamCipher + ?Sized,
    {
        match n_bits {
            None => cipher.encrypt_integer(self),
            Some(n) => cipher.encrypt_integer_with_num_bits(self, n),
        }
    }
}

/// Types decryptable by [`HlStreamCipher::decrypt`]. Mirror of
/// [`HlStreamEncryptable`], reconstructing the plaintext from the raw
/// keystream-XORed bytes returned by [`StreamCipher::decrypt`].
pub trait HlStreamDecryptable: Sized {
    fn hl_stream_decrypt<C>(
        cipher: &mut C,
        encrypted: &IntegerStreamCiphertext,
    ) -> crate::Result<Self>
    where
        C: StreamCipher + ?Sized;
}

impl HlStreamDecryptable for bool {
    fn hl_stream_decrypt<C>(
        cipher: &mut C,
        encrypted: &IntegerStreamCiphertext,
    ) -> crate::Result<Self>
    where
        C: StreamCipher + ?Sized,
    {
        if encrypted.kind() != IntegerStreamKind::Boolean {
            return Err(crate::error!(
                "cannot decrypt bool from a {:?} stream ciphertext",
                encrypted.kind()
            ));
        }
        let bytes = cipher
            .decrypt(encrypted.inner())
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
    fn hl_stream_decrypt<C>(
        cipher: &mut C,
        encrypted: &IntegerStreamCiphertext,
    ) -> crate::Result<Self>
    where
        C: StreamCipher + ?Sized,
    {
        // Runtime signedness detection, same trick as encrypt.
        let is_signed = (T::ONE << (T::BITS - 1)) < T::ZERO;
        let expected_kind = if is_signed {
            IntegerStreamKind::Signed
        } else {
            IntegerStreamKind::Unsigned
        };
        if encrypted.kind() != expected_kind {
            return Err(crate::error!(
                "stream ciphertext kind mismatch: expected {expected_kind:?}, got {:?}",
                encrypted.kind()
            ));
        }

        let bytes = cipher
            .decrypt(encrypted.inner())
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
/// [`IntegerStreamCiphertext`] values with a unified generic API — dispatches
/// unsigned / signed / bool by inspecting `T` via [`HlStreamEncryptable`] /
/// [`HlStreamDecryptable`].
///
/// Blanket-implemented for every [`StreamCipher`].
pub trait HlStreamCipher {
    /// Encrypt `input` at its natural bit-width (`T::BITS`, or 1 for `bool`).
    fn encrypt<T: HlStreamEncryptable>(&mut self, input: T) -> IntegerStreamCiphertext;

    /// Encrypt `input` at exactly `n_bits`. If `n_bits > T::BITS` the value is
    /// sign- or zero-extended, if `n_bits < T::BITS` it is truncated.
    ///
    /// # Panics
    /// * If `n_bits == 0`.
    /// * If `T` is `bool` and `n_bits != 1`.
    fn encrypt_with_num_bits<T: HlStreamEncryptable>(
        &mut self,
        input: T,
        n_bits: usize,
    ) -> IntegerStreamCiphertext;

    /// Decrypt an [`IntegerStreamCiphertext`] into a value of type `T`.
    ///
    /// Errors if `T`'s signedness / shape does not match the ciphertext's tag.
    /// If `T::BITS > encrypted.n_bits()` the value is sign- or zero-extended
    /// as appropriate; if `T::BITS < encrypted.n_bits()` the value is truncated.
    fn decrypt<T: HlStreamDecryptable>(
        &mut self,
        encrypted: &IntegerStreamCiphertext,
    ) -> crate::Result<T>;
}

impl<C: StreamCipher + ?Sized> HlStreamCipher for C {
    fn encrypt<T: HlStreamEncryptable>(&mut self, input: T) -> IntegerStreamCiphertext {
        input.hl_stream_encrypt(self, None)
    }

    fn encrypt_with_num_bits<T: HlStreamEncryptable>(
        &mut self,
        input: T,
        n_bits: usize,
    ) -> IntegerStreamCiphertext {
        input.hl_stream_encrypt(self, Some(n_bits))
    }

    fn decrypt<T: HlStreamDecryptable>(
        &mut self,
        encrypted: &IntegerStreamCiphertext,
    ) -> crate::Result<T> {
        T::hl_stream_decrypt(self, encrypted)
    }
}

/// Trait for transciphering to HLAPI types like FheUint,FheInt,FheBool
pub trait HlTranscipherer {
    fn transcipher<T>(&mut self, input: &IntegerStreamCiphertext) -> crate::Result<T>
    where
        T: HlExpandable + Tagged;
}

impl<X: Transcipherer> HlTranscipherer for X {
    fn transcipher<T>(&mut self, input: &IntegerStreamCiphertext) -> crate::Result<T>
    where
        T: HlExpandable + Tagged,
    {
        try_with_internal_keys(|keys| match keys {
            Some(InternalServerKey::Cpu(cpu_key)) => cpu_transcipher(self, input, cpu_key),
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

/// Device-polymorphic FHE-encrypted Kreyvium master key.
pub enum KreyviumFheKey {
    Cpu(ShortintKreyviumFheKey),
    #[cfg(feature = "gpu")]
    Cuda(CudaUnsignedRadixCiphertext),
}

impl FheTryEncrypt<KreyviumPlainKey, ClientKey> for KreyviumFheKey {
    type Error = crate::Error;

    fn try_encrypt(plain: KreyviumPlainKey, key: &ClientKey) -> Result<Self, Self::Error> {
        let cpu_key = plain.encrypt(&key.key.key.key);
        try_with_internal_keys(|keys| match keys {
            #[cfg(feature = "gpu")]
            Some(InternalServerKey::Cuda(cuda_key)) => {
                let blocks: Vec<_> = Vec::from(cpu_key.ciphertexts());
                let radix = RadixCiphertext::from(blocks);
                Ok(Self::Cuda(
                    CudaUnsignedRadixCiphertext::from_radix_ciphertext(&radix, &cuda_key.streams),
                ))
            }
            _ => Ok(Self::Cpu(cpu_key)),
        })
    }
}

impl FheDecrypt<KreyviumPlainKey> for KreyviumFheKey {
    fn decrypt(&self, cks: &ClientKey) -> KreyviumPlainKey {
        match self {
            Self::Cpu(key) => key.decrypt(&cks.key.key.key),
            #[cfg(feature = "gpu")]
            _ => todo!(),
        }
    }
}

impl KreyviumFheKey {
    /// Generate a fresh FHE-encrypted Kreyvium master key server-side using
    /// OPRF machinery.
    pub fn random(seed: impl OprfSeed) -> crate::Result<Self> {
        try_with_internal_keys(|keys| match keys {
            Some(InternalServerKey::Cpu(cpu_key)) => {
                let oprf_key = cpu_key.oprf_key();
                let shortint_sks = &cpu_key.key.key.key;
                Ok(Self::Cpu(ShortintKreyviumFheKey::random(
                    seed,
                    &oprf_key.key,
                    shortint_sks,
                )))
            }
            #[cfg(feature = "gpu")]
            Some(InternalServerKey::Cuda(_)) => Err(crate::Error::new(
                "KreyviumFheKey::random is not yet supported on GPU".to_owned(),
            )),
            #[cfg(feature = "hpu")]
            Some(InternalServerKey::Hpu(_)) => Err(crate::Error::new(
                "KreyviumFheKey::random is not supported on HPU".to_owned(),
            )),
            None => Err(UninitializedServerKey.into()),
        })
    }
}

/// Device-polymorphic FHE-encrypted AES-128 master key.
pub enum AesFheKey {
    Cpu(ShortintAesFheKey),
    #[cfg(feature = "gpu")]
    Cuda(CudaUnsignedRadixCiphertext),
}

impl FheTryEncrypt<AesPlainKey, ClientKey> for AesFheKey {
    type Error = crate::Error;

    fn try_encrypt(plain: AesPlainKey, key: &ClientKey) -> Result<Self, Self::Error> {
        let cpu_key = plain.encrypt(&key.key.key.key);
        try_with_internal_keys(|keys| match keys {
            #[cfg(feature = "gpu")]
            Some(InternalServerKey::Cuda(cuda_key)) => {
                let blocks: Vec<_> = Vec::from(cpu_key.ciphertexts());
                let radix = RadixCiphertext::from(blocks);
                Ok(Self::Cuda(
                    CudaUnsignedRadixCiphertext::from_radix_ciphertext(&radix, &cuda_key.streams),
                ))
            }
            _ => Ok(Self::Cpu(cpu_key)),
        })
    }
}

pub enum TranscipherSession {
    Cpu(crate::transciphering::TranscipherSession),
    #[cfg(feature = "gpu")]
    Gpu(CudaKreyviumStream),
}

impl TranscipherSession {
    /// Build a Kreyvium transcipher session bound to the current thread-local
    /// server key.
    ///
    /// `key` must match the current server key device.
    pub fn kreyvium(key: KreyviumFheKey, iv: impl Into<KreyviumIV>) -> crate::Result<Self> {
        try_with_internal_keys(|keys| match (key, keys) {
            (KreyviumFheKey::Cpu(k), Some(InternalServerKey::Cpu(cpu_key))) => {
                let integer_sks = &cpu_key.key.key;
                let state = KreyviumFheState::new(k, iv, &integer_sks.key);
                Ok(Self::Cpu(
                    crate::transciphering::TranscipherSession::Kreyvium(state),
                ))
            }
            #[cfg(feature = "gpu")]
            (KreyviumFheKey::Cuda(_), Some(InternalServerKey::Cuda(_))) => {
                let _ = iv; // suppress unused-parameter warning
                Err(crate::Error::new(
                    "Kreyvium on GPU is not yet fully wired".to_owned(),
                ))
            }
            (_, None) => Err(UninitializedServerKey.into()),
            #[cfg(any(feature = "gpu", feature = "hpu"))]
            _ => Err(crate::Error::new(
                "KreyviumFheKey device does not match the current server key device".to_owned(),
            )),
        })
    }

    /// Build an AES-128 transcipher session bound to the current thread-local
    /// server key.
    ///
    /// `key` must match the current server key device.
    /// Round key expansion happens internally.
    ///
    /// GPU is not yet supported (no `CudaIntegerTranscipherer` impl for AES).
    pub fn aes(key: AesFheKey, iv: impl Into<AesIv>) -> crate::Result<Self> {
        try_with_internal_keys(|keys| match (key, keys) {
            (AesFheKey::Cpu(k), Some(InternalServerKey::Cpu(cpu_key))) => {
                let integer_sks = &cpu_key.key.key;
                let round_keys = AesFheRoundKeys::new(&integer_sks.key, &k);
                let state = AesFheState::new(round_keys, iv);
                Ok(Self::Cpu(crate::transciphering::TranscipherSession::Aes(
                    Box::new(state),
                )))
            }
            #[cfg(feature = "gpu")]
            (AesFheKey::Cuda(_), Some(InternalServerKey::Cuda(_))) => {
                let _ = iv;
                Err(crate::Error::new(
                    "AES on GPU is not yet available as a Transcipherer".to_owned(),
                ))
            }
            (_, None) => Err(UninitializedServerKey.into()),
            #[cfg(any(feature = "gpu", feature = "hpu"))]
            _ => Err(crate::Error::new(
                "AesFheKey device does not match the current server key device".to_owned(),
            )),
        })
    }
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
    fn transcipher<T>(&mut self, input: &IntegerStreamCiphertext) -> crate::Result<T>
    where
        T: HlExpandable + Tagged,
    {
        try_with_internal_keys(|keys| match (self, keys) {
            (Self::Cpu(inner), Some(InternalServerKey::Cpu(cpu_key))) => {
                cpu_transcipher(inner, input, cpu_key)
            }
            #[cfg(feature = "gpu")]
            (Self::Gpu(inner), Some(InternalServerKey::Cuda(cuda_key))) => {
                gpu_transcipher::<T>(inner, input, cuda_key)
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
    fn test() {
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
        let sym_cipher = sym.encrypt(input);

        // Client → server: ship the FHE-encrypted Kreyvium key (one-time setup).
        let plain_key = KreyviumPlainKey::from(key_bits);
        let fhe_kreyv_key = KreyviumFheKey::encrypt(plain_key, &client_key);

        // Server: warm up the FHE-side Kreyvium stream and transcipher.
        let mut fhe_stream = TranscipherSession::kreyvium(fhe_kreyv_key, iv_bits).unwrap();
        let transciphered: FheUint64 = fhe_stream.transcipher(&sym_cipher).unwrap();

        // Client: decrypt to recover `input`.
        let recovered: u64 = transciphered.decrypt(&client_key);
        assert_eq!(recovered, input);
    }

    #[test]
    fn test_using_oprf() {
        use super::{HlStreamCipher, HlTranscipherer, KreyviumFheKey, TranscipherSession};
        use crate::prelude::*;
        use crate::transciphering::{KreyviumPlainKey, KreyviumPlainState};
        use crate::{generate_keys, set_server_key, ConfigBuilder, Seed};
        use rand::Rng;

        let (client_key, server_key) =
            generate_keys(ConfigBuilder::default().use_dedicated_oprf_key(true));
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
        let sym_cipher = sym.encrypt(input);

        // Server: warm up the FHE-side Kreyvium stream and transcipher.
        let mut fhe_stream = TranscipherSession::kreyvium(fhe_kreyv_key, iv_bits).unwrap();
        let transciphered: FheUint64 = fhe_stream.transcipher(&sym_cipher).unwrap();

        // Client: decrypt to recover `input`.
        let recovered: u64 = transciphered.decrypt(&client_key);
        assert_eq!(recovered, input);
    }
}
