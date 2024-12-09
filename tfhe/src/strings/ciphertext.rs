use super::client_key::ClientKey;
use super::server_key::ServerKey;
use crate::integer::{
    ClientKey as IntegerClientKey, IntegerCiphertext, IntegerRadixCiphertext, RadixCiphertext,
    ServerKey as IntegerServerKey,
};
use crate::shortint::MessageModulus;
use crate::strings::client_key::EncU16;
use crate::strings::N;
use rayon::iter::{IndexedParallelIterator, ParallelIterator};
use rayon::slice::ParallelSlice;
use std::borrow::Borrow;

/// Represents a encrypted ASCII character.
#[derive(Clone)]
pub struct FheAsciiChar {
    pub enc_char: RadixCiphertext,
}

/// Represents a encrypted string made up of [`FheAsciiChar`]s.
#[derive(Clone)]
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

#[derive(Clone)]
pub enum GenericPattern {
    Clear(ClearString),
    Enc(FheString),
}

impl GenericPattern {
    pub fn as_ref(&self) -> GenericPatternRef {
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

impl<'a> GenericPatternRef<'a> {
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
        assert!(str.is_ascii() & !str.contains('\0'));

        let server_key2 = server_key.inner();

        let enc_string: Vec<_> = str
            .bytes()
            .map(|char| FheAsciiChar {
                enc_char: server_key2.create_trivial_radix(char, server_key.num_ascii_blocks()),
            })
            .collect();

        Self {
            enc_string,
            padded: false,
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integer::ClientKey as IntegerClientKey;
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

    #[test]
    fn test_uint_conversion() {
        let ck = IntegerClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);

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
