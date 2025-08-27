use super::client_key::ClientKey;
use super::server_key::ServerKey;
use crate::integer::ciphertext::{Compactable, DataKind};
use crate::integer::encryption::{encrypt_words_radix_impl, KnowsMessageModulus};
use crate::integer::{
    ClientKey as IntegerClientKey, IntegerCiphertext, IntegerRadixCiphertext, RadixCiphertext,
    ServerKey as IntegerServerKey,
};
use crate::shortint::ciphertext::NotTrivialCiphertextError;
use crate::shortint::MessageModulus;
use crate::strings::backward_compatibility::{FheAsciiCharVersions, FheStringVersions};
use crate::strings::client_key::EncU16;
use crate::strings::N;
use rayon::iter::{IndexedParallelIterator, ParallelIterator};
use rayon::slice::ParallelSlice;
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use tfhe_versionable::Versionize;

/// Represents a encrypted ASCII character.
#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(FheAsciiCharVersions)]
pub struct FheAsciiChar {
    pub enc_char: RadixCiphertext,
}

/// Represents a encrypted string made up of [`FheAsciiChar`]s.
#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(FheStringVersions)]
pub struct FheString {
    pub enc_string: Vec<FheAsciiChar>,
    pub padded: bool,
}

// For str functions that require unsigned integers as arguments

#[derive(Clone)]
pub enum UIntArg {
    Clear(u16),
    Enc(EncU16),
}

#[derive(Clone)]
pub struct ClearString {
    str: String,
}

impl ClearString {
    pub fn new(str: String) -> Self {
        assert!(str.is_ascii() && !str.contains('\0'));
        assert!(str.len() <= N);

        Self { str }
    }

    pub fn str(&self) -> &str {
        &self.str
    }
}

impl Compactable for &ClearString {
    fn compact_into(
        self,
        messages: &mut Vec<u64>,
        message_modulus: MessageModulus,
        num_blocks: Option<usize>,
    ) -> Option<DataKind> {
        let blocks_per_char = 7u32.div_ceil(message_modulus.0.ilog2());

        if let Some(n) = num_blocks {
            assert!(
                n as u32 % blocks_per_char == 0,
                "Inconsistent num block would split the string inside a a character"
            );
        }

        // How many chars we have to write
        let n_chars = num_blocks.map_or(self.str.len(), |n_blocks| {
            n_blocks / blocks_per_char as usize
        });

        // First, write the chars we have at hand
        let n_real_chars = n_chars.min(self.str().len());
        for byte in &self.str.as_bytes()[..n_real_chars] {
            let mut byte = u64::from(*byte);
            for _ in 0..blocks_per_char {
                messages.push(byte % message_modulus.0);
                byte /= message_modulus.0;
            }
        }

        // Pad if necessary
        let padded = n_real_chars < n_chars;
        for _ in 0..n_chars.saturating_sub(n_real_chars) * blocks_per_char as usize {
            messages.push(0);
        }

        Some(DataKind::String {
            n_chars: n_chars as u32,
            padded,
        })
    }
}

impl crate::integer::ciphertext::CompactCiphertextListBuilder {
    pub fn push_string_with_padding(
        &mut self,
        clear_string: &ClearString,
        padding_count: u32,
    ) -> &mut Self {
        let message_modulus = self.pk.key.message_modulus();
        let blocks_per_char = 7u32.div_ceil(message_modulus.0.ilog2());
        let n = self.messages.len();

        let kind = clear_string
            .compact_into(
                &mut self.messages,
                message_modulus,
                Some((clear_string.str.len() + padding_count as usize) * blocks_per_char as usize),
            )
            .expect("Internal error: compact_into should return a kind");
        self.info.push(kind);

        let added_count = kind.num_blocks(message_modulus);
        assert_eq!(
            n + added_count,
            self.messages.len(),
            "Internal error: Incoherent number of blocks added"
        );

        self
    }

    pub fn push_string_with_fixed_size(
        &mut self,
        clear_string: &ClearString,
        size: u32,
    ) -> &mut Self {
        let message_modulus = self.pk.key.message_modulus();
        let blocks_per_char = 7u32.div_ceil(message_modulus.0.ilog2());
        let n = self.messages.len();

        let kind = clear_string
            .compact_into(
                &mut self.messages,
                message_modulus,
                Some((size * blocks_per_char) as usize),
            )
            .expect("Internal error: compact_into should return a kind");
        self.info.push(kind);

        let added_count = kind.num_blocks(message_modulus);
        assert_eq!(
            n + added_count,
            self.messages.len(),
            "Internal error: Incoherent number of blocks added"
        );

        self
    }
}

impl crate::integer::ciphertext::Expandable for FheString {
    fn from_expanded_blocks(
        mut blocks: Vec<crate::shortint::Ciphertext>,
        kind: DataKind,
    ) -> crate::Result<Self> {
        match kind {
            DataKind::String { n_chars, padded } => {
                if n_chars == 0 {
                    return Ok(Self::empty());
                }

                let Some(first_block) = blocks.first() else {
                    return Err(crate::error!(
                        "Invalid number of blocks for a string of {n_chars} chars, got 0 blocks"
                    ));
                };
                let n_blocks_per_chars = 7u32.div_ceil(first_block.message_modulus.0.ilog2());
                let expected_num_blocks = n_chars * n_blocks_per_chars;
                if expected_num_blocks != blocks.len() as u32 {
                    return Err(crate::error!("Invalid number of blocks for a string of {n_chars} chars, expected {expected_num_blocks}, got {}", blocks.len()));
                }

                let mut chars = Vec::with_capacity(n_chars as usize);
                for _ in 0..n_chars {
                    let char: Vec<_> = blocks.drain(..n_blocks_per_chars as usize).collect();
                    chars.push(FheAsciiChar {
                        enc_char: RadixCiphertext::from(char),
                    });
                }
                Ok(Self {
                    enc_string: chars,
                    padded,
                })
            }
            DataKind::Unsigned(_) => Err(crate::Error::new(
                "Tried to expand a string while a unsigned integer was stored".to_string(),
            )),
            DataKind::Signed(_) => Err(crate::Error::new(
                "Tried to expand a string while a signed integer was stored".to_string(),
            )),
            DataKind::Boolean => Err(crate::Error::new(
                "Tried to expand a string while a boolean was stored".to_string(),
            )),
        }
    }
}

impl crate::integer::ciphertext::Compressible for FheString {
    fn compress_into(self, messages: &mut Vec<crate::shortint::Ciphertext>) -> Option<DataKind> {
        let n_chars = self.chars().len() as u32;
        let padded = self.is_padded();

        for char in self.enc_string {
            for block in char.enc_char.blocks {
                messages.push(block);
            }
        }

        Some(DataKind::String { n_chars, padded })
    }
}

#[derive(Clone)]
pub enum GenericPattern {
    Clear(ClearString),
    Enc(FheString),
}

impl GenericPattern {
    pub fn as_ref(&self) -> GenericPatternRef<'_> {
        match self {
            Self::Clear(clear_string) => GenericPatternRef::Clear(clear_string),
            Self::Enc(fhe_string) => GenericPatternRef::Enc(fhe_string),
        }
    }
}

#[derive(Copy, Clone)]
pub enum GenericPatternRef<'a> {
    Clear(&'a ClearString),
    Enc(&'a FheString),
}

impl<'a> From<&'a ClearString> for GenericPatternRef<'a> {
    fn from(value: &'a ClearString) -> Self {
        Self::Clear(value)
    }
}

impl<'a> From<&'a FheString> for GenericPatternRef<'a> {
    fn from(value: &'a FheString) -> Self {
        Self::Enc(value)
    }
}

impl GenericPatternRef<'_> {
    pub fn to_owned(self) -> GenericPattern {
        match self {
            GenericPatternRef::Clear(clear_string) => GenericPattern::Clear(clear_string.clone()),
            GenericPatternRef::Enc(fhe_string) => GenericPattern::Enc(fhe_string.clone()),
        }
    }
}

impl FheAsciiChar {
    pub fn ciphertext(&self) -> &RadixCiphertext {
        &self.enc_char
    }

    pub fn ciphertext_mut(&mut self) -> &mut RadixCiphertext {
        &mut self.enc_char
    }

    pub fn null<T: Borrow<IntegerServerKey> + Sync>(sk: &ServerKey<T>) -> Self {
        let sk_integer = sk.inner();

        Self {
            enc_char: sk_integer.create_trivial_zero_radix(sk.num_ascii_blocks()),
        }
    }

    pub fn is_trivial(&self) -> bool {
        self.enc_char.is_trivial()
    }

    pub fn decrypt_trivial(&self) -> Result<u8, NotTrivialCiphertextError> {
        self.enc_char.decrypt_trivial()
    }
}

impl FheString {
    #[cfg(test)]
    pub fn new_trivial<T: Borrow<IntegerClientKey>>(
        client_key: &ClientKey<T>,
        str: &str,
        padding: Option<u32>,
    ) -> Self {
        client_key.trivial_encrypt_ascii(str, padding)
    }

    /// Constructs a new `FheString` from a plaintext string, a [`ClientKey`] and an optional
    /// padding length.
    ///
    /// Utilizes [`ClientKey::encrypt_ascii`] for the encryption.
    ///
    /// # Panics
    ///
    /// This function will panic if the provided string is not ASCII.
    pub fn new<T: Borrow<IntegerClientKey>>(
        client_key: &ClientKey<T>,
        str: &str,
        padding: Option<u32>,
    ) -> Self {
        client_key.encrypt_ascii(str, padding)
    }

    #[cfg(test)]
    pub fn print_trivial(&self) {
        print!("pad: {}, chars: [", self.padded);

        for i in &self.enc_string {
            print!("[");
            for j in &i.enc_char.blocks {
                let k = j.decrypt_trivial().unwrap();

                print!("{k},");
            }
            print!("], ");
        }

        println!("]");
    }

    pub fn trivial<T: Borrow<IntegerServerKey> + Sync>(
        server_key: &ServerKey<T>,
        str: &str,
    ) -> Self {
        server_key.trivial_encrypt_ascii(str, None)
    }

    pub fn is_trivial(&self) -> bool {
        self.chars().iter().all(FheAsciiChar::is_trivial)
    }

    pub fn decrypt_trivial(&self) -> Result<String, NotTrivialCiphertextError> {
        let mut bytes = Vec::with_capacity(self.chars().len());
        for enc_char in self.chars() {
            let clear = enc_char.decrypt_trivial()?;
            if clear == b'\0' {
                break;
            }
            bytes.push(clear);
        }
        Ok(String::from_utf8(bytes).expect("String is not valid ASCII"))
    }

    pub fn chars(&self) -> &[FheAsciiChar] {
        &self.enc_string
    }

    pub fn chars_mut(&mut self) -> &mut [FheAsciiChar] {
        &mut self.enc_string
    }

    pub fn chars_vec(&mut self) -> &mut Vec<FheAsciiChar> {
        &mut self.enc_string
    }

    pub fn is_padded(&self) -> bool {
        self.padded
    }

    pub fn set_is_padded(&mut self, to: bool) {
        self.padded = to;
    }

    // Converts a `RadixCiphertext` to a `FheString`, building a `FheAsciiChar` for each
    // num_ascii_blocks blocks.
    pub fn from_uint(uint: RadixCiphertext, padded: bool) -> Self {
        if uint.blocks().is_empty() {
            return Self {
                enc_string: vec![],
                padded,
            };
        }

        assert_eq!(
            uint.blocks()[0].message_modulus.0,
            uint.blocks()[0].carry_modulus.0
        );

        let num_blocks = num_ascii_blocks(uint.blocks()[0].message_modulus);

        assert_eq!(uint.blocks.len() % num_blocks, 0);

        let enc_string = uint
            .into_blocks()
            .par_chunks_exact(num_blocks)
            .rev()
            .map(|bytes| FheAsciiChar {
                enc_char: RadixCiphertext::from_blocks(bytes.to_vec()),
            })
            .collect();

        Self { enc_string, padded }
    }

    // Converts a `FheString` to a `RadixCiphertext`, taking 4 blocks for each `FheAsciiChar`.
    // We can then use a single large uint, that represents a string, in tfhe-rs operations.
    pub fn to_uint(&self) -> RadixCiphertext {
        self.clone().into_uint()
    }

    pub fn into_uint(self) -> RadixCiphertext {
        let blocks: Vec<_> = self
            .enc_string
            .into_iter()
            .rev()
            .flat_map(|c| c.enc_char.into_blocks())
            .collect();

        RadixCiphertext::from_blocks(blocks)
    }

    /// Makes the string padded. Useful for when a string is potentially padded and we need to
    /// ensure it's actually padded.
    pub fn append_null<T: Borrow<IntegerServerKey> + Sync>(&mut self, sk: &ServerKey<T>) {
        let null = FheAsciiChar::null(sk);

        self.enc_string.push(null);

        self.padded = true;
    }

    pub fn len(&self) -> usize {
        self.chars().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0 || (self.is_padded() && self.len() == 1)
    }

    pub fn empty() -> Self {
        Self {
            enc_string: vec![],
            padded: false,
        }
    }
}

pub(super) fn num_ascii_blocks(message_modulus: MessageModulus) -> usize {
    let message_modulus = message_modulus.0;

    assert!(message_modulus.is_power_of_two());

    assert_eq!(8 % message_modulus.ilog2(), 0);

    8 / message_modulus.ilog2() as usize
}

/// Creates a trivial encryption of the ascii string `str`
///
/// * key: typically a shortint::ClientKey/ServerKey
/// * encrypt: the method of the `key` used to create a trivial block
///
/// # Panics
///
/// If the string is not ascii or contains null chars ('\0')
pub(in crate::strings) fn trivial_encrypt_ascii<BlockKey, F>(
    key: &BlockKey,
    encrypt_block: &F,
    str: &str,
    padding: Option<u32>,
) -> FheString
where
    BlockKey: KnowsMessageModulus,
    F: Fn(&BlockKey, u64) -> crate::shortint::Ciphertext,
{
    assert!(str.is_ascii() & !str.contains('\0'));

    let padded = padding.is_some_and(|p| p != 0);

    let num_blocks = num_ascii_blocks(key.message_modulus());

    let mut enc_string: Vec<_> = str
        .bytes()
        .map(|char| FheAsciiChar {
            enc_char: encrypt_words_radix_impl(key, char, num_blocks, encrypt_block),
        })
        .collect();

    // Optional padding
    if let Some(count) = padding {
        let null = (0..count).map(|_| FheAsciiChar {
            enc_char: encrypt_words_radix_impl(key, 0u8, num_blocks, encrypt_block),
        });

        enc_string.extend(null);
    }

    FheString { enc_string, padded }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integer::ClientKey as IntegerClientKey;
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    #[test]
    fn test_uint_conversion() {
        let ck = IntegerClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);

        let ck = ClientKey::new(ck);

        let str =
            "Los Sheikah fueron originalmente criados de la Diosa Hylia antes del sellado del \
            Heraldo de la Muerte.";

        let enc = FheString::new(&ck, str, Some(7));

        let uint = enc.to_uint();

        let converted = FheString::from_uint(uint, true);

        let dec = ck.decrypt_ascii(&converted);

        assert_eq!(dec, str);

        let uint_into = enc.into_uint();

        let converted = FheString::from_uint(uint_into, true);

        let dec = ck.decrypt_ascii(&converted);

        assert_eq!(dec, str);
    }
}
