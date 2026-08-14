use super::integers::FheTypes;
use super::keys::TfheClientKey;
use crate::high_level_api as hlapi;
use crate::high_level_api::HlStreamCipher;
use crate::integer::bigint::{StaticSignedBigInt, StaticUnsignedBigInt};
use crate::integer::transciphering::{IntegerStreamCipher, IntegerStreamCiphertextKind};
use crate::js_on_wasm_api::{catch_panic, catch_panic_result, into_js_error};
use crate::prelude::{FheDecrypt, FheTryEncrypt};
use crate::transciphering::{StreamCipher, StreamCipherKind as InternalStreamCipherKind};
use wasm_bindgen::prelude::*;

// Widest common representation for numeric inputs. 2048 bits covers every
// `FheTypes` variant (up to Uint2048/Int2048); smaller widths are handled by
// `encrypt_integer_with_num_bits` truncating / sign-extending as needed.
type BigUnsigned = StaticUnsignedBigInt<32>;
type BigSigned = StaticSignedBigInt<32>;

/// Extract the shape tag and natural bit-width of a wasm [`FheTypes`].
///
/// Returns an error for [`FheTypes::AsciiString`], which has no numeric interpretation.
fn classify(kind: FheTypes) -> Result<(IntegerStreamCiphertextKind, u32), JsError> {
    use IntegerStreamCiphertextKind::{Boolean, Signed, Unsigned};

    // The wasm enum mirrors the discriminants of the hlapi one
    let kind = hlapi::FheTypes::try_from(kind as i32).map_err(into_js_error)?;

    Ok(match hlapi::FheTypeShape::from(kind) {
        hlapi::FheTypeShape::Bool => (Boolean, 1),
        hlapi::FheTypeShape::Unsigned(bits) => (Unsigned, bits),
        hlapi::FheTypeShape::Signed(bits) => (Signed, bits),
        hlapi::FheTypeShape::Variable => {
            return Err(JsError::new(
                "AsciiString is not supported for stream-cipher encryption",
            ))
        }
    })
}

fn encrypt_dispatch<C>(
    cipher: &mut C,
    value: JsValue,
    kind: FheTypes,
    n_bits_override: Option<usize>,
) -> Result<StreamCiphertext, JsError>
where
    C: StreamCipher + ?Sized,
{
    let (stream_kind, natural_bits) = classify(kind)?;
    let inner = match stream_kind {
        IntegerStreamCiphertextKind::Boolean => {
            if !matches!(n_bits_override, None | Some(1)) {
                return Err(JsError::new(
                    "encrypt_with_num_bits: bool inputs require n_bits == 1",
                ));
            }
            let b = value
                .as_bool()
                .ok_or_else(|| JsError::new("expected a boolean value"))?;
            cipher.encrypt_bool(b)
        }
        IntegerStreamCiphertextKind::Unsigned => {
            let width = n_bits_override.unwrap_or(natural_bits as usize);
            let v: BigUnsigned = value.try_into()?;
            cipher.encrypt_integer_with_num_bits(v, width)
        }
        IntegerStreamCiphertextKind::Signed => {
            let width = n_bits_override.unwrap_or(natural_bits as usize);
            let v: BigSigned = value.try_into()?;
            cipher.encrypt_integer_with_num_bits(v, width)
        }
    }
    .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(StreamCiphertext(hlapi::StreamCiphertext::from_raw_parts(
        inner,
    )))
}

fn bytes_to_16_array(bytes: &[u8], name: &str) -> Result<[u8; 16], JsError> {
    <[u8; 16]>::try_from(bytes).map_err(|_| {
        JsError::new(&format!(
            "{name} must be exactly 16 bytes, got {}",
            bytes.len()
        ))
    })
}

/// Decrypt a [`StreamCiphertext`] into a JS value shaped by the
/// ciphertext's tag:
///
/// - `Boolean` → JS `boolean`.
/// - `Unsigned` / `Signed` → JS `BigInt`
fn decrypt_dispatch<C>(cipher: &mut C, encrypted: &StreamCiphertext) -> Result<JsValue, JsError>
where
    C: StreamCipher + ?Sized,
{
    let inner = &encrypted.0;
    // Fully-qualified path — `StreamCipher::decrypt` returns `Vec<u8>` and
    // shadows this trait's method by name.
    let out = match inner.kind() {
        IntegerStreamCiphertextKind::Boolean => {
            let v: bool = <C as HlStreamCipher>::try_decrypt::<bool>(cipher, inner)
                .map_err(|e| JsError::new(&e.to_string()))?;
            JsValue::from_bool(v)
        }
        IntegerStreamCiphertextKind::Unsigned => {
            let v: BigUnsigned = <C as HlStreamCipher>::try_decrypt::<BigUnsigned>(cipher, inner)
                .map_err(|e| JsError::new(&e.to_string()))?;
            v.into()
        }
        IntegerStreamCiphertextKind::Signed => {
            let v: BigSigned = <C as HlStreamCipher>::try_decrypt::<BigSigned>(cipher, inner)
                .map_err(|e| JsError::new(&e.to_string()))?;
            v.into()
        }
    };
    Ok(out)
}

/// Wasm-side [`crate::transciphering::StreamCipherKind`] mirror.
#[wasm_bindgen]
pub enum StreamCipherKind {
    Dynamic = 0,
    Kreyvium = 1,
    Aes = 2,
    OneTimePad = 3,
}

impl From<InternalStreamCipherKind> for StreamCipherKind {
    fn from(value: InternalStreamCipherKind) -> Self {
        match value {
            InternalStreamCipherKind::Dynamic => Self::Dynamic,
            InternalStreamCipherKind::Kreyvium => Self::Kreyvium,
            InternalStreamCipherKind::Aes => Self::Aes,
            InternalStreamCipherKind::OneTimePad => Self::OneTimePad,
        }
    }
}

// -- Kreyvium ----------------------------------------------------------------

#[wasm_bindgen]
pub struct KreyviumPlainKey(pub(crate) crate::transciphering::KreyviumPlainKey);

#[wasm_bindgen]
impl KreyviumPlainKey {
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: &[u8]) -> Result<Self, JsError> {
        let bytes = bytes_to_16_array(bytes, "KreyviumPlainKey")?;
        Ok(Self(bytes.into()))
    }
}

#[wasm_bindgen]
pub struct KreyviumIV(pub(crate) crate::transciphering::KreyviumIV);

#[wasm_bindgen]
impl KreyviumIV {
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: &[u8]) -> Result<Self, JsError> {
        let bytes = bytes_to_16_array(bytes, "KreyviumIV")?;
        Ok(Self(bytes.into()))
    }
}

#[wasm_bindgen]
pub struct KreyviumPlainState(pub(crate) crate::transciphering::KreyviumPlainState);

#[wasm_bindgen]
impl KreyviumPlainState {
    #[wasm_bindgen(constructor)]
    pub fn new(key: &KreyviumPlainKey, iv: &KreyviumIV) -> Result<Self, JsError> {
        catch_panic(|| Self(crate::transciphering::KreyviumPlainState::new(key.0, iv.0)))
    }

    /// Encrypt `value` at its natural bit-width (`kind`'s width, or 1 for `Bool`).
    #[wasm_bindgen]
    pub fn encrypt(&mut self, value: JsValue, kind: FheTypes) -> Result<StreamCiphertext, JsError> {
        encrypt_dispatch(&mut self.0, value, kind, None)
    }

    /// Encrypt `value` at exactly `n_bits` bits. `kind` carries the signedness;
    /// its natural bit-width is ignored. `n_bits == 0` panics; `Bool` requires
    /// `n_bits == 1`.
    #[wasm_bindgen]
    pub fn encrypt_with_num_bits(
        &mut self,
        value: JsValue,
        kind: FheTypes,
        n_bits: usize,
    ) -> Result<StreamCiphertext, JsError> {
        encrypt_dispatch(&mut self.0, value, kind, Some(n_bits))
    }

    /// Decrypt a [`StreamCiphertext`] produced by an earlier call to
    /// [`Self::encrypt`] / [`Self::encrypt_with_num_bits`]. Returns a JS
    /// `bool` for boolean ciphertexts, `BigInt` otherwise.
    #[wasm_bindgen]
    pub fn decrypt(&mut self, encrypted: &StreamCiphertext) -> Result<JsValue, JsError> {
        decrypt_dispatch(&mut self.0, encrypted)
    }
}

#[wasm_bindgen]
pub struct KreyviumFheKey(pub(crate) hlapi::KreyviumFheKey);

#[wasm_bindgen]
impl KreyviumFheKey {
    /// Encrypt a Kreyvium master key under the client key.
    #[wasm_bindgen]
    pub fn encrypt(plain: &KreyviumPlainKey, client_key: &TfheClientKey) -> Result<Self, JsError> {
        catch_panic_result(|| {
            hlapi::KreyviumFheKey::try_encrypt(plain.0, &client_key.0)
                .map(Self)
                .map_err(|e| JsError::new(&e.to_string()))
        })
    }

    /// Recover the key bits, so they can drive a [`KreyviumPlainState`] that
    /// stays in step with the server-side state built from the same key and IV.
    #[wasm_bindgen]
    pub fn decrypt(&self, client_key: &TfheClientKey) -> Result<KreyviumPlainKey, JsError> {
        catch_panic(|| KreyviumPlainKey(self.0.decrypt(&client_key.0)))
    }

    #[wasm_bindgen]
    pub fn safe_serialize(&self, serialized_size_limit: u64) -> Result<Vec<u8>, JsError> {
        let mut buffer = vec![];
        catch_panic_result(|| {
            crate::safe_serialization::SerializationConfig::new(serialized_size_limit)
                .serialize_into(&self.0, &mut buffer)
                .map_err(into_js_error)
        })?;

        Ok(buffer)
    }

    #[wasm_bindgen]
    pub fn safe_deserialize(buffer: &[u8], serialized_size_limit: u64) -> Result<Self, JsError> {
        catch_panic_result(|| {
            crate::safe_serialization::DeserializationConfig::new(serialized_size_limit)
                .disable_conformance()
                .deserialize_from(buffer)
                .map(Self)
                .map_err(into_js_error)
        })
    }
}

// -- AES ---------------------------------------------------------------------

#[wasm_bindgen]
pub struct AesPlainKey(pub(crate) crate::transciphering::AesPlainKey);

#[wasm_bindgen]
impl AesPlainKey {
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: &[u8]) -> Result<Self, JsError> {
        let bytes = bytes_to_16_array(bytes, "AesPlainKey")?;
        Ok(Self(bytes.into()))
    }
}

#[wasm_bindgen]
pub struct AesIv(pub(crate) crate::transciphering::AesIv);

#[wasm_bindgen]
impl AesIv {
    /// Build an AES IV from a 16-byte big-endian counter (NIST convention).
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: &[u8]) -> Result<Self, JsError> {
        let bytes = bytes_to_16_array(bytes, "AesIv")?;
        Ok(Self(bytes.into()))
    }
}

#[wasm_bindgen]
pub struct AesPlainState(pub(crate) crate::transciphering::AesPlainState);

#[wasm_bindgen]
impl AesPlainState {
    #[wasm_bindgen(constructor)]
    pub fn new(key: &AesPlainKey, iv: &AesIv) -> Result<Self, JsError> {
        catch_panic(|| Self(crate::transciphering::AesPlainState::new(key.0, iv.0)))
    }

    #[wasm_bindgen]
    pub fn encrypt(&mut self, value: JsValue, kind: FheTypes) -> Result<StreamCiphertext, JsError> {
        encrypt_dispatch(&mut self.0, value, kind, None)
    }

    #[wasm_bindgen]
    pub fn encrypt_with_num_bits(
        &mut self,
        value: JsValue,
        kind: FheTypes,
        n_bits: usize,
    ) -> Result<StreamCiphertext, JsError> {
        encrypt_dispatch(&mut self.0, value, kind, Some(n_bits))
    }

    #[wasm_bindgen]
    pub fn decrypt(&mut self, encrypted: &StreamCiphertext) -> Result<JsValue, JsError> {
        decrypt_dispatch(&mut self.0, encrypted)
    }
}

#[wasm_bindgen]
pub struct AesFheKey(pub(crate) hlapi::AesFheKey);

#[wasm_bindgen]
impl AesFheKey {
    /// Encrypt an AES-128 master key under the client key.
    #[wasm_bindgen]
    pub fn encrypt(plain: &AesPlainKey, client_key: &TfheClientKey) -> Result<Self, JsError> {
        catch_panic_result(|| {
            hlapi::AesFheKey::try_encrypt(plain.0, &client_key.0)
                .map(Self)
                .map_err(|e| JsError::new(&e.to_string()))
        })
    }

    /// Recover the key bits, so they can drive an [`AesPlainState`] that stays
    /// in step with the server-side state built from the same key and IV.
    #[wasm_bindgen]
    pub fn decrypt(&self, client_key: &TfheClientKey) -> Result<AesPlainKey, JsError> {
        catch_panic(|| AesPlainKey(self.0.decrypt(&client_key.0)))
    }

    #[wasm_bindgen]
    pub fn safe_serialize(&self, serialized_size_limit: u64) -> Result<Vec<u8>, JsError> {
        let mut buffer = vec![];
        catch_panic_result(|| {
            crate::safe_serialization::SerializationConfig::new(serialized_size_limit)
                .serialize_into(&self.0, &mut buffer)
                .map_err(into_js_error)
        })?;

        Ok(buffer)
    }

    #[wasm_bindgen]
    pub fn safe_deserialize(buffer: &[u8], serialized_size_limit: u64) -> Result<Self, JsError> {
        catch_panic_result(|| {
            crate::safe_serialization::DeserializationConfig::new(serialized_size_limit)
                .disable_conformance()
                .deserialize_from(buffer)
                .map(Self)
                .map_err(into_js_error)
        })
    }
}

// -- One-time pad ------------------------------------------------------------

#[wasm_bindgen]
pub struct OneTimePadPlainSecretMask(pub(crate) crate::transciphering::OneTimePadPlainSecretMask);

#[wasm_bindgen]
impl OneTimePadPlainSecretMask {
    /// `bytes` must hold exactly `ceil(bit_count / 8)` bytes.
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: &[u8], bit_count: usize) -> Result<Self, JsError> {
        crate::transciphering::OneTimePadPlainSecretMask::try_new(bytes.to_vec(), bit_count)
            .map(Self)
            .map_err(JsError::new)
    }

    #[wasm_bindgen]
    pub fn safe_serialize(&self, serialized_size_limit: u64) -> Result<Vec<u8>, JsError> {
        let mut buffer = vec![];
        catch_panic_result(|| {
            crate::safe_serialization::SerializationConfig::new(serialized_size_limit)
                .serialize_into(&self.0, &mut buffer)
                .map_err(into_js_error)
        })?;

        Ok(buffer)
    }

    #[wasm_bindgen]
    pub fn safe_deserialize(buffer: &[u8], serialized_size_limit: u64) -> Result<Self, JsError> {
        catch_panic_result(|| {
            crate::safe_serialization::DeserializationConfig::new(serialized_size_limit)
                .disable_conformance()
                .deserialize_from(buffer)
                .map(Self)
                .map_err(into_js_error)
        })
    }

    #[wasm_bindgen]
    pub fn safe_deserialize_conformant(
        buffer: &[u8],
        serialized_size_limit: u64,
        n_bits: usize,
    ) -> Result<Self, JsError> {
        catch_panic_result(|| {
            crate::safe_serialization::DeserializationConfig::new(serialized_size_limit)
                .deserialize_from(
                    buffer,
                    &crate::transciphering::OneTimePadPlainSecretMaskConformanceParams { n_bits },
                )
                .map(Self)
                .map_err(into_js_error)
        })
    }
}

#[wasm_bindgen]
pub struct OneTimePadPlainState(pub(crate) crate::transciphering::OneTimePadPlainState);

#[wasm_bindgen]
impl OneTimePadPlainState {
    /// The pad is the keystream, consumed from bit 0 onwards. There is no IV.
    #[wasm_bindgen(constructor)]
    pub fn new(mask: &OneTimePadPlainSecretMask) -> Result<Self, JsError> {
        catch_panic(|| {
            Self(crate::transciphering::OneTimePadPlainState::new(
                mask.0.clone(),
            ))
        })
    }

    /// Pad bits not yet consumed. Encrypting more than this many bits fails.
    #[wasm_bindgen]
    pub fn remaining_bits(&self) -> u64 {
        self.0.remaining_bits()
    }

    /// Encrypt `value` at its natural bit-width (`kind`'s width, or 1 for `Bool`).
    #[wasm_bindgen]
    pub fn encrypt(&mut self, value: JsValue, kind: FheTypes) -> Result<StreamCiphertext, JsError> {
        encrypt_dispatch(&mut self.0, value, kind, None)
    }

    /// Encrypt `value` at exactly `n_bits` bits. `kind` carries the signedness;
    /// its natural bit-width is ignored. `n_bits == 0` panics; `Bool` requires
    /// `n_bits == 1`.
    #[wasm_bindgen]
    pub fn encrypt_with_num_bits(
        &mut self,
        value: JsValue,
        kind: FheTypes,
        n_bits: usize,
    ) -> Result<StreamCiphertext, JsError> {
        encrypt_dispatch(&mut self.0, value, kind, Some(n_bits))
    }

    /// Decrypt a [`StreamCiphertext`] produced by an earlier call to
    /// [`Self::encrypt`] / [`Self::encrypt_with_num_bits`]. Returns a JS
    /// `bool` for boolean ciphertexts, `BigInt` otherwise.
    #[wasm_bindgen]
    pub fn decrypt(&mut self, encrypted: &StreamCiphertext) -> Result<JsValue, JsError> {
        decrypt_dispatch(&mut self.0, encrypted)
    }
}

#[wasm_bindgen]
pub struct OneTimePadFheSecretMask(pub(crate) hlapi::OneTimePadFheSecretMask);

#[wasm_bindgen]
impl OneTimePadFheSecretMask {
    /// Encrypt a one-time pad under the client key.
    #[wasm_bindgen]
    pub fn encrypt(
        plain: &OneTimePadPlainSecretMask,
        client_key: &TfheClientKey,
    ) -> Result<Self, JsError> {
        catch_panic_result(|| {
            hlapi::OneTimePadFheSecretMask::try_encrypt(plain.0.clone(), &client_key.0)
                .map(Self)
                .map_err(|e| JsError::new(&e.to_string()))
        })
    }

    /// Recover the pad bits, so they can drive a [`OneTimePadPlainState`] that
    /// stays in step with the server-side state built from the same mask.
    #[wasm_bindgen]
    pub fn decrypt(
        &self,
        client_key: &TfheClientKey,
    ) -> Result<OneTimePadPlainSecretMask, JsError> {
        catch_panic(|| OneTimePadPlainSecretMask(self.0.decrypt(&client_key.0)))
    }

    #[wasm_bindgen]
    pub fn safe_serialize(&self, serialized_size_limit: u64) -> Result<Vec<u8>, JsError> {
        let mut buffer = vec![];
        catch_panic_result(|| {
            crate::safe_serialization::SerializationConfig::new(serialized_size_limit)
                .serialize_into(&self.0, &mut buffer)
                .map_err(into_js_error)
        })?;

        Ok(buffer)
    }

    #[wasm_bindgen]
    pub fn safe_deserialize(buffer: &[u8], serialized_size_limit: u64) -> Result<Self, JsError> {
        catch_panic_result(|| {
            crate::safe_serialization::DeserializationConfig::new(serialized_size_limit)
                .disable_conformance()
                .deserialize_from(buffer)
                .map(Self)
                .map_err(into_js_error)
        })
    }
}

// -- StreamCiphertext -------------------------------------------------

#[wasm_bindgen]
pub struct StreamCiphertext(pub(crate) hlapi::StreamCiphertext);

#[wasm_bindgen]
impl StreamCiphertext {
    #[wasm_bindgen]
    pub fn n_bits(&self) -> usize {
        self.0.n_bits()
    }

    #[wasm_bindgen]
    pub fn encryption_counter(&self) -> u64 {
        self.0.encryption_counter()
    }

    #[wasm_bindgen]
    pub fn cipher_kind(&self) -> StreamCipherKind {
        self.0.cipher_kind().into()
    }

    #[wasm_bindgen]
    pub fn safe_serialize(&self, serialized_size_limit: u64) -> Result<Vec<u8>, JsError> {
        let mut buffer = vec![];
        catch_panic_result(|| {
            crate::safe_serialization::SerializationConfig::new(serialized_size_limit)
                .serialize_into(&self.0, &mut buffer)
                .map_err(into_js_error)
        })?;

        Ok(buffer)
    }

    #[wasm_bindgen]
    pub fn safe_deserialize(buffer: &[u8], serialized_size_limit: u64) -> Result<Self, JsError> {
        catch_panic_result(|| {
            crate::safe_serialization::DeserializationConfig::new(serialized_size_limit)
                .disable_conformance()
                .deserialize_from(buffer)
                .map(Self)
                .map_err(into_js_error)
        })
    }
}
