//! Module containing the definition of the [`CiphertextModulus`].

use crate::core_crypto::commons::traits::UnsignedInteger;
use std::marker::PhantomData;

#[derive(Clone, Copy, PartialEq, Eq)]
/// A value of 0 is always interpreted as a native modulus, this is useful to work with u128 using
/// the native modulus as $2^{128}$ cannot be stored in a u128 value.
///
/// This also allows to not rely on an enum which would require a discriminant field adding 8 bytes
/// to store 1 bit of information (native variant vs custom variant with u128 payload).
pub struct CiphertextModulus<Scalar: UnsignedInteger>(u128, PhantomData<Scalar>);

#[derive(serde::Serialize, serde::Deserialize)]
struct SerialiazableLweCiphertextModulus {
    pub modulus: u128,
    pub scalar_bits: usize,
}

// Manual impl to be able to carry the UnsignedInteger bitwidth information
impl<Scalar: UnsignedInteger> serde::Serialize for CiphertextModulus<Scalar> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        SerialiazableLweCiphertextModulus {
            modulus: self.get(),
            scalar_bits: Scalar::BITS,
        }
        .serialize(serializer)
    }
}

impl<'de, Scalar: UnsignedInteger> serde::Deserialize<'de> for CiphertextModulus<Scalar> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let thing = SerialiazableLweCiphertextModulus::deserialize(deserializer)
            .map_err(serde::de::Error::custom)?;

        if thing.scalar_bits != Scalar::BITS {
            return Err(serde::de::Error::custom(format!(
                "Expected an unsigned integer with {} bits, \
            found {} bits during deserialization of CiphertextModulus, \
            have you mixed types during deserialization?",
                Scalar::BITS,
                thing.scalar_bits
            )));
        }

        Ok(CiphertextModulus(thing.modulus, PhantomData))
    }
}

impl<Scalar: UnsignedInteger> CiphertextModulus<Scalar> {
    pub const fn try_new(modulus: u128) -> Result<Self, &'static str> {
        if (Scalar::BITS < 128) && (modulus > (1 << Scalar::BITS)) {
            return Err("Modulus is bigger than the maximum value of the associated Scalar type");
        }

        Ok(Self(modulus, PhantomData).canonicalize())
    }

    pub const fn new_native() -> Self {
        Self(0, PhantomData)
    }

    #[cfg(test)]
    pub const fn new_unchecked(modulus: u128) -> Self {
        Self(modulus, PhantomData)
    }

    #[inline]
    /// Return the u128 value storing the modulus. This returns 0 if the modulus is the native
    /// modulus of the associated scalar type.
    pub const fn get(&self) -> u128 {
        self.0
    }

    pub const fn get_non_canonical(&self) -> u128 {
        if self.is_native_modulus() {
            1 << Scalar::BITS
        } else {
            self.get()
        }
    }

    pub const fn canonicalize(self) -> Self {
        if self.is_native_modulus() {
            Self(0, PhantomData)
        } else {
            self
        }
    }

    /// Depending on the Scalar type used in the call, this function will determine whether the
    /// current modulus is the native modulus of the given Scalar type allowing for more efficient
    /// implementations than can rely on wrapping arithmetic operations behavior to compute the
    /// modulus.
    pub const fn is_native_modulus(&self) -> bool {
        if self.0 == 0 {
            return true;
        }

        if Scalar::BITS < 128 {
            return self.0 == (1 << Scalar::BITS);
        }

        false
    }

    pub const fn is_compatible_with_native_modulus(&self) -> bool {
        self.is_native_modulus() || self.is_power_of_two()
    }

    pub const fn is_power_of_two(&self) -> bool {
        self.0.is_power_of_two()
    }

    pub const fn is_odd(&self) -> bool {
        self.0 % 2 == 1
    }
}

impl<Scalar: UnsignedInteger> std::fmt::Display for CiphertextModulus<Scalar> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_native_modulus() {
            write!(f, "CiphertextModulus(2^{})", Scalar::BITS)
        } else {
            write!(f, "CiphertextModulus({})", self.0)
        }
    }
}

impl<Scalar: UnsignedInteger> std::fmt::Debug for CiphertextModulus<Scalar> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Self as std::fmt::Display>::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use crate::core_crypto::prelude::CiphertextModulus;

    #[test]
    fn test_modulus_struct() {
        {
            let mod_32_res = CiphertextModulus::<u32>::try_new(0);
            assert!(mod_32_res.is_ok());

            let mod_32 = mod_32_res.unwrap();
            assert!(mod_32.is_native_modulus());

            let std_fmt = format!("{mod_32}");
            assert_eq!(&std_fmt, "CiphertextModulus(2^32)");

            let dbg_fmt = format!("{mod_32:?}");
            assert_eq!(&dbg_fmt, "CiphertextModulus(2^32)");
        }

        {
            let mod_32_res = CiphertextModulus::<u32>::try_new(1 << 32);
            assert!(mod_32_res.is_ok());

            let mod_32 = mod_32_res.unwrap();
            assert!(mod_32.is_native_modulus());

            let std_fmt = format!("{mod_32}");
            assert_eq!(&std_fmt, "CiphertextModulus(2^32)");

            let dbg_fmt = format!("{mod_32:?}");
            assert_eq!(&dbg_fmt, "CiphertextModulus(2^32)");
        }

        {
            let bad_mod_32 = CiphertextModulus::<u32>::try_new(1 << 64);
            assert!(bad_mod_32.is_err());
            match bad_mod_32 {
                Ok(_) => unreachable!(),
                Err(e) => assert_eq!(
                    e,
                    "Modulus is bigger than the maximum value of the associated Scalar type"
                ),
            }
        }

        {
            let native_mod_128 = CiphertextModulus::<u128>::new_native();
            assert!(native_mod_128.is_native_modulus());
        }

        {
            let mod_128_res = CiphertextModulus::<u128>::try_new(1234567890);
            assert!(mod_128_res.is_ok());

            let mod_128 = mod_128_res.unwrap();
            assert_eq!(mod_128.get(), 1234567890);
        }
    }
}
