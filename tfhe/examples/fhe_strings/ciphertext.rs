use crate::client_key::{ClientKey, EncU16, EncryptOutput};
use crate::server_key::ServerKey;
use crate::N;
use tfhe::integer::{IntegerCiphertext, IntegerRadixCiphertext, RadixCiphertext};

/// Represents a encrypted ASCII character.
#[derive(Clone)]
pub struct FheAsciiChar {
    enc_char: RadixCiphertext,
}

/// Represents a encrypted string made up of [`FheAsciiChar`]s.
#[derive(Clone)]
pub struct FheString {
    enc_string: Vec<FheAsciiChar>,
    padded: bool,
}

// For str functions that require unsigned integers as arguments
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
        assert!(str.len() <= N * 8);

        ClearString { str }
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

impl FheAsciiChar {
    pub fn ciphertext(&self) -> &RadixCiphertext {
        &self.enc_char
    }

    pub fn ciphertext_mut(&mut self) -> &mut RadixCiphertext {
        &mut self.enc_char
    }

    pub fn null(sk: &ServerKey) -> Self {
        FheAsciiChar {
            enc_char: sk.key().create_trivial_zero_radix(4),
        }
    }
}

impl FheString {
    /// Constructs a new `FheString` from a plaintext string, a [`ClientKey`] and an optional
    /// padding length.
    ///
    /// Utilizes [`ClientKey::encrypt_ascii`] for the encryption.
    ///
    /// # Panics
    ///
    /// This function will panic if the provided string is not ASCII.
    pub fn new(client_key: &ClientKey, str: &str, padding: Option<u32>) -> Self {
        let enc_output = client_key.encrypt_ascii(str, padding);

        FheString::from(enc_output)
    }

    /// Constructs a trivial `FheString` from a plaintext string and a [`ServerKey`].
    ///
    /// ## WARNING:
    /// This only formats the value to fit the ciphertext. The result is NOT encrypted.
    pub fn trivial(server_key: &ServerKey, str: &str) -> Self {
        let trivial = server_key
            .trivial_encrypt_ascii(str)
            .value()
            .into_iter()
            .map(|enc_char| FheAsciiChar { enc_char })
            .collect();

        Self {
            enc_string: trivial,
            padded: false,
        }
    }

    /// Constructs a new `FheString` from an [`EncryptOutput`], which is guaranteed to be correct.
    pub fn from(enc_output: EncryptOutput) -> Self {
        let padded = enc_output.is_padded();

        let enc_string = enc_output
            .value()
            .into_iter()
            .map(|enc_char| FheAsciiChar { enc_char })
            .collect();

        Self { enc_string, padded }
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

    // Converts a `RadixCiphertext` to a `FheString`, building a `FheAsciiChar` for each 4 blocks.
    // Panics if the uint doesn't have a number of blocks that is multiple of 4.
    pub fn from_uint(uint: RadixCiphertext) -> FheString {
        let blocks_len = uint.blocks().len();
        assert_eq!(blocks_len % 4, 0);

        let mut ciphertexts = uint.into_blocks().into_iter().rev();

        let mut ascii_vec = vec![];

        for _ in 0..blocks_len / 4 {
            let mut byte_vec: Vec<_> = ciphertexts.by_ref().take(4).collect();
            byte_vec.reverse();

            let byte = RadixCiphertext::from_blocks(byte_vec);

            ascii_vec.push(FheAsciiChar { enc_char: byte })
        }

        FheString {
            enc_string: ascii_vec,
            // We are assuming here there's no padding, so this isn't safe if we don't know it!
            padded: false,
        }
    }

    // Converts a `FheString` to a `RadixCiphertext`, taking 4 blocks for each `FheAsciiChar`.
    // We can then use a single large uint, that represents a string, in tfhe-rs operations.
    pub fn to_uint(&self, sk: &ServerKey) -> RadixCiphertext {
        self.clone().into_uint(sk)
    }

    pub fn into_uint(self, sk: &ServerKey) -> RadixCiphertext {
        let blocks: Vec<_> = self
            .enc_string
            .into_iter()
            .rev()
            .flat_map(|c| c.enc_char.into_blocks())
            .collect();

        let mut uint = RadixCiphertext::from_blocks(blocks);

        if uint.blocks().is_empty() {
            sk.key()
                .extend_radix_with_trivial_zero_blocks_lsb_assign(&mut uint, 4);
        }

        uint
    }

    /// Makes the string padded. Useful for when a string is potentially padded and we need to
    /// ensure it's actually padded.
    pub fn append_null(&mut self, sk: &ServerKey) {
        let null = FheAsciiChar::null(sk);

        self.enc_string.push(null);

        self.padded = true;
    }

    pub fn empty() -> FheString {
        FheString {
            enc_string: vec![],
            padded: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_key::gen_keys;

    #[test]
    fn test_uint_conversion() {
        let (ck, sk) = gen_keys();

        let str =
            "Los Sheikah fueron originalmente criados de la Diosa Hylia antes del sellado del \
            Heraldo de la Muerte.";

        let enc = FheString::new(&ck, str, Some(7));

        let uint = enc.to_uint(&sk);
        let mut converted = FheString::from_uint(uint);
        converted.set_is_padded(true);
        let dec = ck.decrypt_ascii(&converted);

        assert_eq!(dec, str);

        let uint_into = enc.into_uint(&sk);
        let mut converted = FheString::from_uint(uint_into);
        converted.set_is_padded(true);
        let dec = ck.decrypt_ascii(&converted);

        assert_eq!(dec, str);
    }
}
