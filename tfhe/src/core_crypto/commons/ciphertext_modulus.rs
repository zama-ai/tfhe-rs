//! Module containing the definition of the [`CiphertextModulus`].

use crate::core_crypto::commons::traits::UnsignedInteger;
use core::num::NonZeroU128;
use std::marker::PhantomData;

#[derive(Clone, Copy, PartialEq, Eq)]
/// Private enum to avoid end user mis-instantiating a CiphertextModulus
///
/// NonZeroU128 allows to always have a correct modulus and to have an enum that is no bigger than a
/// u128 with the 0 optimization as the tag then corresponds to the Native variant.
enum CiphertextModulusInner {
    Native,
    Custom(NonZeroU128),
}

#[derive(Clone, Copy, PartialEq, Eq)]
/// Structure representing a [`CiphertextModulus`] often noted $q$.
pub struct CiphertextModulus<Scalar: UnsignedInteger> {
    inner: CiphertextModulusInner,
    _scalar: PhantomData<Scalar>,
}

pub enum CiphertextModulusKind {
    Native,
    NonNativePowerOfTwo,
    NonNative,
}

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
        let modulus = match self.inner {
            CiphertextModulusInner::Native => 0,
            CiphertextModulusInner::Custom(modulus) => modulus.get(),
        };

        SerialiazableLweCiphertextModulus {
            modulus,
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

        let res = if thing.modulus == 0 {
            CiphertextModulus {
                inner: CiphertextModulusInner::Native,
                _scalar: PhantomData,
            }
        } else {
            CiphertextModulus {
                inner: CiphertextModulusInner::Custom(NonZeroU128::new(thing.modulus).ok_or(
                    serde::de::Error::custom(
                        "Got zero modulus for CiphertextModulusInner::Custom variant",
                    ),
                )?),
                _scalar: PhantomData,
            }
        };
        Ok(res.canonicalize())
    }
}

impl<Scalar: UnsignedInteger> CiphertextModulus<Scalar> {
    pub const fn new_native() -> Self {
        Self {
            inner: CiphertextModulusInner::Native,
            _scalar: PhantomData,
        }
    }

    pub const fn try_new_power_of_2(exponent: usize) -> Result<Self, &'static str> {
        if exponent > Scalar::BITS {
            Err("Modulus is bigger than the maximum value of the associated Scalar type")
        } else {
            let res = match 1u128.checked_shl(exponent as u32) {
                Some(modulus) => {
                    let non_zero_modulus = match NonZeroU128::new(modulus) {
                        Some(val) => val,
                        None => {
                            panic!("Got zero modulus for CiphertextModulusInner::Custom variant",)
                        }
                    };
                    Self {
                        inner: CiphertextModulusInner::Custom(non_zero_modulus),
                        _scalar: PhantomData,
                    }
                }
                None => {
                    assert!(exponent == 128);
                    assert!(Scalar::BITS == 128);
                    Self {
                        inner: CiphertextModulusInner::Native,
                        _scalar: PhantomData,
                    }
                }
            };
            Ok(res.canonicalize())
        }
    }

    pub const fn try_new(modulus: u128) -> Result<Self, &'static str> {
        if Scalar::BITS < 128 && modulus > (1 << Scalar::BITS) {
            Err("Modulus is bigger than the maximum value of the associated Scalar type")
        } else {
            let res = match modulus {
                0 => CiphertextModulus::new_native(),
                modulus => {
                    let Some(non_zero_modulus) = NonZeroU128::new(modulus) else {
                            panic!("Got zero modulus for CiphertextModulusInner::Custom variant",)
                    };
                    CiphertextModulus {
                        inner: CiphertextModulusInner::Custom(non_zero_modulus),
                        _scalar: PhantomData,
                    }
                }
            };
            let canonicalized_result = res.canonicalize();
            if Scalar::BITS > 64 && !canonicalized_result.is_compatible_with_native_modulus() {
                return Err("Non power of 2 moduli are not supported for types wider than u64");
            }
            Ok(canonicalized_result)
        }
    }

    pub const fn canonicalize(self) -> Self {
        match self.inner {
            CiphertextModulusInner::Native => self,
            CiphertextModulusInner::Custom(modulus) => {
                if Scalar::BITS < 128 && modulus.get() == (1 << Scalar::BITS) {
                    CiphertextModulus::new_native()
                } else {
                    self
                }
            }
        }
    }

    #[cfg(test)]
    /// # Safety
    /// modulus needs to be able to fit in the associated Scalar type
    pub const unsafe fn new_unchecked(modulus: u128) -> Self {
        let res = match modulus {
            0 => Self {
                inner: CiphertextModulusInner::Native,
                _scalar: PhantomData,
            },
            _ => Self {
                inner: CiphertextModulusInner::Custom(NonZeroU128::new_unchecked(modulus)),
                _scalar: PhantomData,
            },
        };
        res.canonicalize()
    }

    #[track_caller]
    pub fn get_power_of_two_scaling_to_native_torus(&self) -> Scalar {
        match self.inner {
            CiphertextModulusInner::Native => Scalar::ONE,
            CiphertextModulusInner::Custom(modulus) => {
                assert!(
                    modulus.is_power_of_two(),
                    "Cannot get scaling for non power of two modulus {modulus:}"
                );
                Scalar::ONE.wrapping_shl(Scalar::BITS as u32 - modulus.ilog2())
            }
        }
    }

    /// Depending on the Scalar type used in the call, this function will determine whether the
    /// current modulus is the native modulus of the given Scalar type allowing for more efficient
    /// implementations than can rely on wrapping arithmetic operations behavior to compute the
    /// modulus.
    pub const fn is_native_modulus(&self) -> bool {
        matches!(self.inner, CiphertextModulusInner::Native)
    }

    /// Panics if the modulus is not a custom modulus
    pub const fn get_custom_modulus(&self) -> u128 {
        match self.inner {
            CiphertextModulusInner::Native => {
                panic!("Tried getting custom modulus from native modulus")
            }
            CiphertextModulusInner::Custom(modulus) => modulus.get(),
        }
    }

    pub const fn is_compatible_with_native_modulus(&self) -> bool {
        self.is_native_modulus() || self.is_power_of_two()
    }

    pub const fn is_non_native_power_of_two(&self) -> bool {
        match self.inner {
            CiphertextModulusInner::Native => false,
            CiphertextModulusInner::Custom(modulus) => modulus.is_power_of_two(),
        }
    }

    pub const fn is_power_of_two(&self) -> bool {
        match self.inner {
            CiphertextModulusInner::Native => true,
            CiphertextModulusInner::Custom(modulus) => modulus.is_power_of_two(),
        }
    }

    pub const fn kind(&self) -> CiphertextModulusKind {
        match self.inner {
            CiphertextModulusInner::Native => CiphertextModulusKind::Native,
            CiphertextModulusInner::Custom(modulus) => {
                if modulus.is_power_of_two() {
                    CiphertextModulusKind::NonNativePowerOfTwo
                } else {
                    CiphertextModulusKind::NonNative
                }
            }
        }
    }
}

impl<Scalar: UnsignedInteger> std::fmt::Display for CiphertextModulus<Scalar> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.inner {
            CiphertextModulusInner::Native => write!(f, "CiphertextModulus(2^{})", Scalar::BITS),
            CiphertextModulusInner::Custom(modulus) => {
                write!(f, "CiphertextModulus({})", modulus.get())
            }
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
        assert!(std::mem::size_of::<CiphertextModulus<u32>>() == std::mem::size_of::<u128>());
        assert!(std::mem::size_of::<CiphertextModulus<u64>>() == std::mem::size_of::<u128>());
        assert!(std::mem::size_of::<CiphertextModulus<u128>>() == std::mem::size_of::<u128>());
        assert!(std::mem::align_of::<CiphertextModulus<u32>>() == std::mem::align_of::<u128>());
        assert!(std::mem::align_of::<CiphertextModulus<u64>>() == std::mem::align_of::<u128>());
        assert!(std::mem::align_of::<CiphertextModulus<u128>>() == std::mem::align_of::<u128>());

        {
            let mod_32_res = CiphertextModulus::<u32>::try_new_power_of_2(32);
            assert!(mod_32_res.is_ok());

            let mod_32 = mod_32_res.unwrap();
            assert!(mod_32.is_native_modulus());

            let std_fmt = format!("{mod_32}");
            assert_eq!(&std_fmt, "CiphertextModulus(2^32)");

            let dbg_fmt = format!("{mod_32:?}");
            assert_eq!(&dbg_fmt, "CiphertextModulus(2^32)");
        }

        {
            let bad_mod_32 = CiphertextModulus::<u32>::try_new_power_of_2(64);
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

            let ser = bincode::serialize(&native_mod_128).unwrap();
            let deser: CiphertextModulus<u128> = bincode::deserialize(&ser).unwrap();

            assert_eq!(native_mod_128, deser);

            let deser_error: Result<CiphertextModulus<u32>, _> = bincode::deserialize(&ser);
            assert!(deser_error.is_err());
            match deser_error {
                Ok(_) => unreachable!(),
                Err(e) => match *e {
                    bincode::ErrorKind::Custom(err) => {
                        assert_eq!(
                            err.as_str(),
                            "Expected an unsigned integer with 32 bits, \
                    found 128 bits during deserialization of CiphertextModulus, \
                    have you mixed types during deserialization?",
                        );
                    }
                    _ => unreachable!(),
                },
            }
        }

        {
            let mod_128_res = CiphertextModulus::<u128>::try_new_power_of_2(64);
            assert!(mod_128_res.is_ok());

            let mod_128 = mod_128_res.unwrap();
            assert_eq!(mod_128.get_custom_modulus(), 1 << 64);

            let ser = bincode::serialize(&mod_128).unwrap();
            let deser: CiphertextModulus<u128> = bincode::deserialize(&ser).unwrap();

            assert_eq!(mod_128, deser);

            let deser_error: Result<CiphertextModulus<u32>, _> = bincode::deserialize(&ser);
            assert!(deser_error.is_err());
            match deser_error {
                Ok(_) => unreachable!(),
                Err(e) => match *e {
                    bincode::ErrorKind::Custom(err) => {
                        assert_eq!(
                            err.as_str(),
                            "Expected an unsigned integer with 32 bits, \
                    found 128 bits during deserialization of CiphertextModulus, \
                    have you mixed types during deserialization?",
                        );
                    }
                    _ => unreachable!(),
                },
            }
        }
    }
}
