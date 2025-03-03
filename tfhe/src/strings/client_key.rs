use std::borrow::Borrow;

use crate::integer::{ClientKey as IntegerClientKey, RadixCiphertext};
use crate::strings::ciphertext::{num_ascii_blocks, FheAsciiChar, FheString};

pub struct ClientKey<T>
where
    T: Borrow<IntegerClientKey>,
{
    inner: T,
}

impl<T> ClientKey<T>
where
    T: Borrow<IntegerClientKey>,
{
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &IntegerClientKey {
        self.inner.borrow()
    }
}

#[derive(Clone)]
pub struct EncU16 {
    cipher: RadixCiphertext,
    max: Option<u16>,
}

impl EncU16 {
    pub(crate) fn new(value: RadixCiphertext, max: Option<u16>) -> Self {
        Self { cipher: value, max }
    }
    pub fn cipher(&self) -> &RadixCiphertext {
        &self.cipher
    }

    pub fn max(&self) -> Option<u16> {
        self.max
    }
}

impl<T> ClientKey<T>
where
    T: Borrow<IntegerClientKey>,
{
    #[cfg(test)]
    pub fn trivial_encrypt_ascii(&self, str: &str, padding: Option<u32>) -> FheString {
        let ck = self.inner.borrow();

        super::ciphertext::trivial_encrypt_ascii(
            &ck.key,
            &crate::shortint::ClientKey::create_trivial,
            str,
            padding,
        )
    }

    /// Encrypts an ASCII string, optionally padding it with the specified amount of 0s, and returns
    /// an [`FheString`].
    ///
    /// # Panics
    ///
    /// This function will panic if the provided string is not ASCII or contains null characters
    /// "\0".
    pub fn encrypt_ascii(&self, str: &str, padding: Option<u32>) -> FheString {
        let ck = self.inner.borrow();

        assert!(str.is_ascii() & !str.contains('\0'));

        let padded = padding.is_some_and(|p| p != 0);

        let num_blocks = self.num_ascii_blocks();

        let mut enc_string: Vec<_> = str
            .bytes()
            .map(|char| FheAsciiChar {
                enc_char: ck.encrypt_radix(char, num_blocks),
            })
            .collect();

        // Optional padding
        if let Some(count) = padding {
            let null = (0..count).map(|_| FheAsciiChar {
                enc_char: ck.encrypt_radix(0u8, num_blocks),
            });

            enc_string.extend(null);
        }

        FheString { enc_string, padded }
    }

    fn num_ascii_blocks(&self) -> usize {
        let ck = self.inner.borrow();

        assert_eq!(
            ck.parameters().message_modulus().0,
            ck.parameters().carry_modulus().0
        );

        num_ascii_blocks(ck.parameters().message_modulus())
    }

    /// Decrypts a `FheString`, removes any padding and returns the ASCII string.
    ///
    /// # Panics
    ///
    /// This function will panic if the decrypted string is not ASCII or the `FheString` padding
    /// flag doesn't match the actual string.
    pub fn decrypt_ascii(&self, enc_str: &FheString) -> String {
        let ck = self.inner.borrow();

        let padded_flag = enc_str.is_padded();
        let mut prev_was_null = false;

        let bytes: Vec<_> = enc_str
            .chars()
            .iter()
            .filter_map(|enc_char| {
                let byte = ck.decrypt_radix(enc_char.ciphertext());

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

    #[cfg(test)]
    pub fn trivial_encrypt_u16(&self, val: u16, max: Option<u16>) -> EncU16 {
        let ck = self.inner.borrow();

        if let Some(max_val) = max {
            assert!(val <= max_val, "val cannot be greater than max")
        }

        EncU16 {
            cipher: ck.create_trivial_radix(val, 8),
            max,
        }
    }

    /// Encrypts a u16 value. It also takes an optional `max` value to restrict the range
    /// of the encrypted u16.
    ///
    /// # Panics
    ///
    /// This function will panic if the u16 value exceeds the provided `max`.
    pub fn encrypt_u16(&self, val: u16, max: Option<u16>) -> EncU16 {
        let ck = self.inner.borrow();

        if let Some(max_val) = max {
            assert!(val <= max_val, "val cannot be greater than max")
        }

        EncU16 {
            cipher: ck.encrypt_radix(val, 8),
            max,
        }
    }
}
