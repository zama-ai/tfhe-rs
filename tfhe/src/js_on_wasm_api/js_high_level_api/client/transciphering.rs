use super::integers::FheTypes;
use super::keys::TfheClientKey;
use crate::high_level_api as hlapi;
use crate::high_level_api::HlStreamCipher;
use crate::integer::bigint::{StaticSignedBigInt, StaticUnsignedBigInt};
use crate::integer::transciphering::{IntegerStreamCipher as _, IntegerStreamKind};
use crate::js_on_wasm_api::{catch_panic, catch_panic_result};
use crate::prelude::FheTryEncrypt;
use crate::transciphering::{StreamCipher, StreamCipherKind as InternalStreamCipherKind};
use wasm_bindgen::prelude::*;

// Widest common representation for numeric inputs. 2048 bits covers every
// `FheTypes` variant (up to Uint2048/Int2048); smaller widths are handled by
// `encrypt_integer_with_num_bits` truncating / sign-extending as needed.
type BigUnsigned = StaticUnsignedBigInt<32>;
type BigSigned = StaticSignedBigInt<32>;

/// Extract the shape tag and natural bit-width of a wasm [`FheTypes`].
///
/// The `u32` payload is the width in bits (1 for `Boolean`). Returns an error
/// for [`FheTypes::AsciiString`], which has no numeric interpretation.
fn classify(kind: FheTypes) -> Result<(IntegerStreamKind, u32), JsError> {
    use FheTypes as F;
    use IntegerStreamKind::{Boolean, Signed, Unsigned};
    let out = match kind {
        F::Bool => (Boolean, 1),
        F::AsciiString => {
            return Err(JsError::new(
                "AsciiString is not supported for stream-cipher encryption",
            ));
        }
        F::Uint2 => (Unsigned, 2),
        F::Uint4 => (Unsigned, 4),
        F::Uint6 => (Unsigned, 6),
        F::Uint8 => (Unsigned, 8),
        F::Uint10 => (Unsigned, 10),
        F::Uint12 => (Unsigned, 12),
        F::Uint14 => (Unsigned, 14),
        F::Uint16 => (Unsigned, 16),
        F::Uint24 => (Unsigned, 24),
        F::Uint32 => (Unsigned, 32),
        F::Uint40 => (Unsigned, 40),
        F::Uint48 => (Unsigned, 48),
        F::Uint56 => (Unsigned, 56),
        F::Uint64 => (Unsigned, 64),
        F::Uint72 => (Unsigned, 72),
        F::Uint80 => (Unsigned, 80),
        F::Uint88 => (Unsigned, 88),
        F::Uint96 => (Unsigned, 96),
        F::Uint104 => (Unsigned, 104),
        F::Uint112 => (Unsigned, 112),
        F::Uint120 => (Unsigned, 120),
        F::Uint128 => (Unsigned, 128),
        F::Uint136 => (Unsigned, 136),
        F::Uint144 => (Unsigned, 144),
        F::Uint152 => (Unsigned, 152),
        F::Uint160 => (Unsigned, 160),
        F::Uint168 => (Unsigned, 168),
        F::Uint176 => (Unsigned, 176),
        F::Uint184 => (Unsigned, 184),
        F::Uint192 => (Unsigned, 192),
        F::Uint200 => (Unsigned, 200),
        F::Uint208 => (Unsigned, 208),
        F::Uint216 => (Unsigned, 216),
        F::Uint224 => (Unsigned, 224),
        F::Uint232 => (Unsigned, 232),
        F::Uint240 => (Unsigned, 240),
        F::Uint248 => (Unsigned, 248),
        F::Uint256 => (Unsigned, 256),
        F::Uint512 => (Unsigned, 512),
        F::Uint1024 => (Unsigned, 1024),
        F::Uint2048 => (Unsigned, 2048),
        F::Int2 => (Signed, 2),
        F::Int4 => (Signed, 4),
        F::Int6 => (Signed, 6),
        F::Int8 => (Signed, 8),
        F::Int10 => (Signed, 10),
        F::Int12 => (Signed, 12),
        F::Int14 => (Signed, 14),
        F::Int16 => (Signed, 16),
        F::Int24 => (Signed, 24),
        F::Int32 => (Signed, 32),
        F::Int40 => (Signed, 40),
        F::Int48 => (Signed, 48),
        F::Int56 => (Signed, 56),
        F::Int64 => (Signed, 64),
        F::Int72 => (Signed, 72),
        F::Int80 => (Signed, 80),
        F::Int88 => (Signed, 88),
        F::Int96 => (Signed, 96),
        F::Int104 => (Signed, 104),
        F::Int112 => (Signed, 112),
        F::Int120 => (Signed, 120),
        F::Int128 => (Signed, 128),
        F::Int136 => (Signed, 136),
        F::Int144 => (Signed, 144),
        F::Int152 => (Signed, 152),
        F::Int160 => (Signed, 160),
        F::Int168 => (Signed, 168),
        F::Int176 => (Signed, 176),
        F::Int184 => (Signed, 184),
        F::Int192 => (Signed, 192),
        F::Int200 => (Signed, 200),
        F::Int208 => (Signed, 208),
        F::Int216 => (Signed, 216),
        F::Int224 => (Signed, 224),
        F::Int232 => (Signed, 232),
        F::Int240 => (Signed, 240),
        F::Int248 => (Signed, 248),
        F::Int256 => (Signed, 256),
        F::Int512 => (Signed, 512),
        F::Int1024 => (Signed, 1024),
        F::Int2048 => (Signed, 2048),
    };
    Ok(out)
}

fn encrypt_dispatch<C>(
    cipher: &mut C,
    value: JsValue,
    kind: FheTypes,
    n_bits_override: Option<usize>,
) -> Result<IntegerStreamCiphertext, JsError>
where
    C: StreamCipher + ?Sized,
{
    let (stream_kind, natural_bits) = classify(kind)?;
    let inner = match stream_kind {
        IntegerStreamKind::Boolean => {
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
        IntegerStreamKind::Unsigned => {
            let width = n_bits_override.unwrap_or(natural_bits as usize);
            let v: BigUnsigned = value.try_into()?;
            cipher.encrypt_integer_with_num_bits(v, width)
        }
        IntegerStreamKind::Signed => {
            let width = n_bits_override.unwrap_or(natural_bits as usize);
            let v: BigSigned = value.try_into()?;
            cipher.encrypt_integer_with_num_bits(v, width)
        }
    };
    Ok(IntegerStreamCiphertext(inner))
}

fn bytes_to_16_array(bytes: &[u8], name: &str) -> Result<[u8; 16], JsError> {
    <[u8; 16]>::try_from(bytes).map_err(|_| {
        JsError::new(&format!(
            "{name} must be exactly 16 bytes, got {}",
            bytes.len()
        ))
    })
}

/// Decrypt an [`IntegerStreamCiphertext`] into a JS value shaped by the
/// ciphertext's tag:
///
/// - `Boolean` → JS `boolean`.
/// - `Unsigned` / `Signed` → JS `BigInt`
fn decrypt_dispatch<C>(
    cipher: &mut C,
    encrypted: &IntegerStreamCiphertext,
) -> Result<JsValue, JsError>
where
    C: StreamCipher + ?Sized,
{
    let inner = &encrypted.0;
    // Fully-qualified path — `StreamCipher::decrypt` returns `Vec<u8>` and
    // shadows this trait's method by name.
    let out = match inner.kind() {
        IntegerStreamKind::Boolean => {
            let v: bool = <C as HlStreamCipher>::decrypt::<bool>(cipher, inner)
                .map_err(|e| JsError::new(&e.to_string()))?;
            JsValue::from_bool(v)
        }
        IntegerStreamKind::Unsigned => {
            let v: BigUnsigned = <C as HlStreamCipher>::decrypt::<BigUnsigned>(cipher, inner)
                .map_err(|e| JsError::new(&e.to_string()))?;
            v.into()
        }
        IntegerStreamKind::Signed => {
            let v: BigSigned = <C as HlStreamCipher>::decrypt::<BigSigned>(cipher, inner)
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
}

impl From<InternalStreamCipherKind> for StreamCipherKind {
    fn from(value: InternalStreamCipherKind) -> Self {
        match value {
            InternalStreamCipherKind::Dynamic => Self::Dynamic,
            InternalStreamCipherKind::Kreyvium => Self::Kreyvium,
            InternalStreamCipherKind::Aes => Self::Aes,
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
    pub fn encrypt(
        &mut self,
        value: JsValue,
        kind: FheTypes,
    ) -> Result<IntegerStreamCiphertext, JsError> {
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
    ) -> Result<IntegerStreamCiphertext, JsError> {
        encrypt_dispatch(&mut self.0, value, kind, Some(n_bits))
    }

    /// Decrypt an [`IntegerStreamCiphertext`] produced by an earlier call to
    /// [`Self::encrypt`] / [`Self::encrypt_with_num_bits`]. Returns a JS
    /// `bool` for boolean ciphertexts, `BigInt` otherwise.
    #[wasm_bindgen]
    pub fn decrypt(&mut self, encrypted: &IntegerStreamCiphertext) -> Result<JsValue, JsError> {
        decrypt_dispatch(&mut self.0, encrypted)
    }
}

#[wasm_bindgen]
pub struct KreyviumFheKey(pub(crate) hlapi::KreyviumFheKey);

#[wasm_bindgen]
impl KreyviumFheKey {
    /// Encrypt a Kreyvium master key under the client key.
    #[wasm_bindgen]
    pub fn encrypt(
        plain: &KreyviumPlainKey,
        client_key: &TfheClientKey,
    ) -> Result<KreyviumFheKey, JsError> {
        catch_panic_result(|| {
            hlapi::KreyviumFheKey::try_encrypt(plain.0, &client_key.0)
                .map(Self)
                .map_err(|e| JsError::new(&e.to_string()))
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
    pub fn encrypt(
        &mut self,
        value: JsValue,
        kind: FheTypes,
    ) -> Result<IntegerStreamCiphertext, JsError> {
        encrypt_dispatch(&mut self.0, value, kind, None)
    }

    #[wasm_bindgen]
    pub fn encrypt_with_num_bits(
        &mut self,
        value: JsValue,
        kind: FheTypes,
        n_bits: usize,
    ) -> Result<IntegerStreamCiphertext, JsError> {
        encrypt_dispatch(&mut self.0, value, kind, Some(n_bits))
    }

    #[wasm_bindgen]
    pub fn decrypt(&mut self, encrypted: &IntegerStreamCiphertext) -> Result<JsValue, JsError> {
        decrypt_dispatch(&mut self.0, encrypted)
    }
}

#[wasm_bindgen]
pub struct AesFheKey(pub(crate) hlapi::AesFheKey);

#[wasm_bindgen]
impl AesFheKey {
    /// Encrypt an AES-128 master key under the client key.  
    #[wasm_bindgen]
    pub fn encrypt(plain: &AesPlainKey, client_key: &TfheClientKey) -> Result<AesFheKey, JsError> {
        catch_panic_result(|| {
            hlapi::AesFheKey::try_encrypt(plain.0, &client_key.0)
                .map(Self)
                .map_err(|e| JsError::new(&e.to_string()))
        })
    }
}

// -- IntegerStreamCiphertext -------------------------------------------------

#[wasm_bindgen]
pub struct IntegerStreamCiphertext(pub(crate) hlapi::IntegerStreamCiphertext);

#[wasm_bindgen]
impl IntegerStreamCiphertext {
    #[wasm_bindgen]
    pub fn n_bits(&self) -> usize {
        self.0.n_bits()
    }

    #[wasm_bindgen]
    pub fn encryption_counter(&self) -> u64 {
        self.0.inner().encryption_counter()
    }

    #[wasm_bindgen]
    pub fn cipher_kind(&self) -> StreamCipherKind {
        self.0.inner().kind().into()
    }
}
