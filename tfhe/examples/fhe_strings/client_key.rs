use crate::ciphertext::FheString;
use tfhe::integer::{ClientKey as FheClientKey, RadixCiphertext};
use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2;

/// Represents a client key for encryption and decryption of strings.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct ClientKey {
    key: FheClientKey,
}

/// Encrypted u16 value. It contains an optional `max` to restrict the range of the value.
pub struct EncU16 {
    cipher: RadixCiphertext,
    max: Option<u16>,
}

impl EncU16 {
    pub fn cipher(&self) -> &RadixCiphertext {
        &self.cipher
    }

    pub fn max(&self) -> Option<u16> {
        self.max
    }
}

/// Output type returned by [`ClientKey::encrypt_ascii`].
///
/// It is used as an intermediate type to safely build a [`FheString`].
pub struct EncryptOutput {
    output: Vec<RadixCiphertext>,
    padded: bool,
}

impl EncryptOutput {
    /// Extracts the value from the `EncryptOutput`.
    pub fn value(self) -> Vec<RadixCiphertext> {
        self.output
    }

    pub fn is_padded(&self) -> bool {
        self.padded
    }
}

impl ClientKey {
    pub fn new() -> Self {
        Self {
            key: FheClientKey::new(PARAM_MESSAGE_2_CARRY_2),
        }
    }

    pub fn key(&self) -> &FheClientKey {
        &self.key
    }

    /// Encrypts an ASCII string, optionally padding it with the specified amount of 0s, and returns
    /// an [`EncryptOutput`].
    ///
    /// # Panics
    ///
    /// This function will panic if the provided string is not ASCII or contains null characters
    /// "\0".
    pub fn encrypt_ascii(&self, str: &str, padding: Option<u32>) -> EncryptOutput {
        assert!(str.is_ascii() & !str.contains('\0'));

        let padded = padding.map_or(false, |p| p != 0);

        let mut enc_chars: Vec<_> = str
            .bytes()
            .map(|char| self.key.encrypt_radix(char, 4))
            .collect();

        // Optional padding
        if let Some(count) = padding {
            let null = (0..count).map(|_| self.key.encrypt_radix(0u8, 4));

            enc_chars.extend(null);
        }

        EncryptOutput {
            output: enc_chars,
            padded,
        }
    }

    /// Decrypts a `FheString`, removes any padding and returns the ASCII string.
    ///
    /// # Panics
    ///
    /// This function will panic if the decrypted string is not ASCII or the `FheString` padding
    /// flag doesn't match the actual string.
    pub fn decrypt_ascii(&self, enc_str: &FheString) -> String {
        let padded_flag = enc_str.is_padded();
        let mut prev_was_null = false;

        let bytes: Vec<_> = enc_str
            .chars()
            .iter()
            .filter_map(|enc_char| {
                let byte = self.key.decrypt_radix(enc_char.ciphertext());

                if byte == 0 {
                    prev_was_null = true;

                    assert!(padded_flag, "NULL FOUND BUT PADDED FLAG WAS FALSE");
                } else {
                    assert!(!prev_was_null, "NON ZERO CHAR AFTER A NULL");

                    prev_was_null = false;
                }

                if byte != 0 {
                    Some(byte)
                } else {
                    None
                }
            })
            .collect();

        if padded_flag {
            assert!(
                prev_was_null,
                "LAST CHAR WAS NOT NULL BUT PADDING FLAG WAS SET"
            )
        }

        String::from_utf8(bytes).unwrap()
    }

    /// Encrypts a u16 value. It also takes an optional `max` value to restrict the range
    /// of the encrypted u16.
    ///
    /// # Panics
    ///
    /// This function will panic if the u16 value exceeds the provided `max`.
    pub fn encrypt_u16(&self, val: u16, max: Option<u16>) -> EncU16 {
        if let Some(max_val) = max {
            assert!(val <= max_val, "val cannot be greater than max")
        }

        EncU16 {
            cipher: self.key.encrypt_radix(val, 8),
            max,
        }
    }
}
