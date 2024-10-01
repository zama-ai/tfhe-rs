//! Module containing the definition of the [`CiphertextModulus`].

use tfhe_versionable::Versionize;

use crate::core_crypto::backward_compatibility::commons::ciphertext_modulus::SerializableCiphertextModulusVersions;
use crate::core_crypto::commons::traits::UnsignedInteger;
use crate::core_crypto::prelude::CastInto;
use core::num::NonZeroU128;
use std::cmp::Ordering;
use std::fmt::Display;
use std::marker::PhantomData;

#[derive(Clone, Copy, PartialEq, Eq)]
/// Private enum to avoid end user instantiating a bad CiphertextModulus
///
/// NonZeroU128 allows to always have a correct modulus and to have an enum that is no bigger than a
/// u128 with the 0 optimization as the tag then corresponds to the Native variant.
enum CiphertextModulusInner {
    Native,
    Custom(NonZeroU128),
}

#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[serde(
    try_from = "SerializableCiphertextModulus",
    into = "SerializableCiphertextModulus"
)]
#[versionize(
    SerializableCiphertextModulusVersions,
    try_from = "SerializableCiphertextModulus",
    into = "SerializableCiphertextModulus"
)]
/// Structure representing a [`CiphertextModulus`] often noted $q$.
pub struct CiphertextModulus<Scalar: UnsignedInteger> {
    inner: CiphertextModulusInner,
    _scalar: PhantomData<Scalar>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CiphertextModulusKind {
    Native,
    NonNativePowerOfTwo,
    Other,
}

#[derive(serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(SerializableCiphertextModulusVersions)]
/// Actual serialized modulus to be able to carry the UnsignedInteger bitwidth information
pub struct SerializableCiphertextModulus {
    pub modulus: u128,
    pub scalar_bits: usize,
}

#[derive(Clone, Copy, Debug)]
pub enum CiphertextModulusDeserializationError {
    InvalidBitWidth { expected: usize, found: usize },
    ZeroCustomModulus,
}

impl Display for CiphertextModulusDeserializationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBitWidth { expected, found } => write!(
                f,
                "Expected an unsigned integer with {expected} bits, \
            found {found} bits during deserialization of CiphertextModulus, \
            have you mixed types during deserialization?",
            ),
            Self::ZeroCustomModulus => write!(
                f,
                "Got zero modulus for CiphertextModulusInner::Custom variant"
            ),
        }
    }
}

impl std::error::Error for CiphertextModulusDeserializationError {}

impl<Scalar: UnsignedInteger> From<CiphertextModulus<Scalar>> for SerializableCiphertextModulus {
    fn from(value: CiphertextModulus<Scalar>) -> Self {
        let modulus = match value.inner {
            CiphertextModulusInner::Native => 0,
            CiphertextModulusInner::Custom(modulus) => modulus.get(),
        };

        Self {
            modulus,
            scalar_bits: Scalar::BITS,
        }
    }
}

impl<Scalar: UnsignedInteger> TryFrom<SerializableCiphertextModulus> for CiphertextModulus<Scalar> {
    type Error = CiphertextModulusDeserializationError;

    fn try_from(value: SerializableCiphertextModulus) -> Result<Self, Self::Error> {
        if value.scalar_bits != Scalar::BITS {
            return Err(CiphertextModulusDeserializationError::InvalidBitWidth {
                expected: Scalar::BITS,
                found: value.scalar_bits,
            });
        }

        let res = if value.modulus == 0 {
            Self {
                inner: CiphertextModulusInner::Native,
                _scalar: PhantomData,
            }
        } else {
            Self {
                inner: CiphertextModulusInner::Custom(
                    NonZeroU128::new(value.modulus)
                        .ok_or(CiphertextModulusDeserializationError::ZeroCustomModulus)?,
                ),
                _scalar: PhantomData,
            }
        };
        Ok(res.canonicalize())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CiphertextModulusCreationError {
    ModulusTooBig,
    CustomModuli64BitsOrLessOnly,
}

impl CiphertextModulusCreationError {
    pub const fn const_err_msg(self) -> &'static str {
        match self {
            Self::ModulusTooBig => {
                "Modulus is bigger than the maximum value of the associated Scalar type"
            }
            Self::CustomModuli64BitsOrLessOnly => {
                "Non power of 2 moduli are not supported for types wider than u64"
            }
        }
    }
}

impl From<CiphertextModulusCreationError> for &str {
    fn from(value: CiphertextModulusCreationError) -> Self {
        value.const_err_msg()
    }
}

impl std::fmt::Debug for CiphertextModulusCreationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let err_str: &str = (*self).into();
        write!(f, "{err_str}")
    }
}

impl<Scalar: UnsignedInteger> CiphertextModulus<Scalar> {
    pub const fn new_native() -> Self {
        Self {
            inner: CiphertextModulusInner::Native,
            _scalar: PhantomData,
        }
    }

    #[track_caller]
    pub const fn try_new_power_of_2(
        exponent: usize,
    ) -> Result<Self, CiphertextModulusCreationError> {
        if exponent > Scalar::BITS {
            Err(CiphertextModulusCreationError::ModulusTooBig)
        } else {
            let res = if let Some(modulus) = 1u128.checked_shl(exponent as u32) {
                let Some(non_zero_modulus) = NonZeroU128::new(modulus) else {
                    panic!("Got zero modulus for CiphertextModulusInner::Custom variant")
                };

                Self {
                    inner: CiphertextModulusInner::Custom(non_zero_modulus),
                    _scalar: PhantomData,
                }
            } else {
                assert!(exponent == 128);
                assert!(Scalar::BITS == 128);
                Self {
                    inner: CiphertextModulusInner::Native,
                    _scalar: PhantomData,
                }
            };
            Ok(res.canonicalize())
        }
    }

    #[track_caller]
    pub const fn try_new(modulus: u128) -> Result<Self, CiphertextModulusCreationError> {
        if Scalar::BITS < 128 && modulus > (1 << Scalar::BITS) {
            Err(CiphertextModulusCreationError::ModulusTooBig)
        } else {
            let res = match modulus {
                0 => Self::new_native(),
                modulus => {
                    let Some(non_zero_modulus) = NonZeroU128::new(modulus) else {
                        panic!("Got zero modulus for CiphertextModulusInner::Custom variant")
                    };
                    Self {
                        inner: CiphertextModulusInner::Custom(non_zero_modulus),
                        _scalar: PhantomData,
                    }
                }
            };
            let canonicalized_result = res.canonicalize();
            if Scalar::BITS > 64 && !canonicalized_result.is_compatible_with_native_modulus() {
                return Err(CiphertextModulusCreationError::CustomModuli64BitsOrLessOnly);
            }
            Ok(canonicalized_result)
        }
    }

    pub const fn canonicalize(self) -> Self {
        match self.inner {
            CiphertextModulusInner::Native => self,
            CiphertextModulusInner::Custom(modulus) => {
                if Scalar::BITS < 128 && modulus.get() == (1 << Scalar::BITS) {
                    Self::new_native()
                } else {
                    self
                }
            }
        }
    }

    /// # Panic
    /// Panics if modulus is not able to fit in the associated Scalar type
    #[track_caller]
    pub const fn new(modulus: u128) -> Self {
        let res = match modulus {
            0 => Self::new_native(),
            _ => match Self::try_new(modulus) {
                Ok(ciphertext_modulus) => ciphertext_modulus,
                Err(err) => panic!("{}", err.const_err_msg()),
            },
        };
        res.canonicalize()
    }

    /// # Panic
    /// Panics if the stored modulus is not a power of 2.
    #[track_caller]
    pub fn get_power_of_two_scaling_to_native_torus(&self) -> Scalar {
        match self.inner {
            CiphertextModulusInner::Native => Scalar::ONE,
            CiphertextModulusInner::Custom(modulus) => {
                assert!(
                    modulus.is_power_of_two(),
                    "Cannot get scaling for non power of two modulus {modulus}"
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
    #[track_caller]
    pub const fn get_custom_modulus(&self) -> u128 {
        match self.inner {
            CiphertextModulusInner::Native => {
                panic!("Tried getting custom modulus from native modulus")
            }
            CiphertextModulusInner::Custom(modulus) => modulus.get(),
        }
    }

    pub fn get_custom_modulus_as_optional_scalar(&self) -> Option<Scalar> {
        match self.inner {
            CiphertextModulusInner::Native => None,
            CiphertextModulusInner::Custom(modulus) => Some(modulus.get().cast_into()),
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

    pub fn try_to<ScalarTo: UnsignedInteger + CastInto<u128>>(
        &self,
    ) -> Result<CiphertextModulus<ScalarTo>, &'static str> {
        let error_msg = "failed to convert ciphertext modulus";

        let new_inner = match self.inner {
            CiphertextModulusInner::Native => match ScalarTo::BITS.cmp(&Scalar::BITS) {
                Ordering::Greater => {
                    CiphertextModulusInner::Custom(NonZeroU128::new(1u128 << Scalar::BITS).unwrap())
                }
                Ordering::Equal => CiphertextModulusInner::Native,
                Ordering::Less => {
                    return Err(error_msg);
                }
            },
            CiphertextModulusInner::Custom(v) => {
                let max = NonZeroU128::new(ScalarTo::MAX.cast_into()).unwrap();
                if v <= max {
                    CiphertextModulusInner::Custom(v)
                } else if v.is_power_of_two() && v.ilog2() as usize == ScalarTo::BITS {
                    CiphertextModulusInner::Native
                } else {
                    return Err(error_msg);
                }
            }
        };

        Ok(CiphertextModulus {
            inner: new_inner,
            _scalar: PhantomData,
        }
        .canonicalize())
    }

    pub const fn kind(&self) -> CiphertextModulusKind {
        match self.inner {
            CiphertextModulusInner::Native => CiphertextModulusKind::Native,
            CiphertextModulusInner::Custom(modulus) => {
                if modulus.is_power_of_two() {
                    CiphertextModulusKind::NonNativePowerOfTwo
                } else {
                    CiphertextModulusKind::Other
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
    use super::CiphertextModulusCreationError;
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
            let mod_32 = CiphertextModulus::<u32>::try_new_power_of_2(32).unwrap();

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
                Err(e) => assert_eq!(e, CiphertextModulusCreationError::ModulusTooBig),
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
            let mod_128 = CiphertextModulus::<u128>::try_new_power_of_2(64).unwrap();

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

    #[test]
    fn test_modulus_casting() {
        // Native (u64 -> u64) => Native
        let native_mod = CiphertextModulus::<u64>::try_new_power_of_2(64).unwrap();
        assert!(native_mod.is_native_modulus());
        let converted: CiphertextModulus<u64> = native_mod.try_to().unwrap();

        assert!(converted.is_native_modulus());

        // Native (u64 -> u128) => Custom
        let native_mod = CiphertextModulus::<u64>::try_new_power_of_2(64).unwrap();
        let converted: CiphertextModulus<u128> = native_mod.try_to().unwrap();

        assert!(!converted.is_native_modulus());
        assert_eq!(converted.get_custom_modulus(), 1u128 << 64);

        // Native(u64 -> u32) => Impossible
        let native_mod = CiphertextModulus::<u64>::try_new_power_of_2(64).unwrap();
        let converted: Result<CiphertextModulus<u32>, _> = native_mod.try_to();
        assert!(converted.is_err());

        // Custom(u64 -> u64) => Custom
        let custom_mod = CiphertextModulus::<u64>::try_new(64).unwrap();
        assert!(!custom_mod.is_native_modulus());
        let converted: CiphertextModulus<u64> = custom_mod.try_to().unwrap();

        assert!(!converted.is_native_modulus());
        assert_eq!(converted.get_custom_modulus(), 64);

        // Custom(u64[with value == 2**32] -> u32) => Native
        let custom_mod = CiphertextModulus::<u64>::try_new_power_of_2(32).unwrap();
        assert!(!custom_mod.is_native_modulus());
        let converted: CiphertextModulus<u32> = custom_mod.try_to().unwrap();
        assert!(converted.is_native_modulus());

        // Custom (u64[with value > 2**32] -> u32) => Impossible
        let custom_mod = CiphertextModulus::<u64>::try_new(1 << 48).unwrap();
        assert!(!custom_mod.is_native_modulus());
        let converted: Result<CiphertextModulus<u32>, _> = custom_mod.try_to();
        assert!(converted.is_err());

        // Custom (u64[with value < 2**32] -> u32) => Custom
        let custom_mod = CiphertextModulus::<u64>::try_new(1 << 21).unwrap();
        assert!(!custom_mod.is_native_modulus());
        let converted: CiphertextModulus<u32> = custom_mod.try_to().unwrap();
        assert!(!converted.is_native_modulus());
        assert_eq!(converted.get_custom_modulus(), 1 << 21);
    }
}
