//! Scalar field element type for BLS12-446 (320-bit integers, 5 limbs)

use crate::bindings::Scalar as ScalarFFI;
use std::fmt;

/// Get the scalar field modulus from C++ via FFI
fn scalar_modulus_limbs() -> [u64; 5] {
    let mut limbs = [0u64; 5];
    // SAFETY: `limbs.as_mut_ptr()` points to a valid array of 5 u64 values.
    // The FFI function writes exactly 5 limbs to this pointer.
    unsafe {
        crate::bindings::scalar_modulus_limbs_wrapper(limbs.as_mut_ptr());
    }
    limbs
}

/// Scalar field modulus (group order) - initialized once from C++
/// Uses OnceLock to ensure thread-safe one-time initialization
static SCALAR_MODULUS: std::sync::OnceLock<[u64; 5]> = std::sync::OnceLock::new();

fn get_scalar_modulus() -> &'static [u64; 5] {
    SCALAR_MODULUS.get_or_init(scalar_modulus_limbs)
}

/// Scalar type for BLS12-446 (320-bit integers, 5 limbs)
/// This matches the C++ Scalar type (BigInt<ZP_LIMBS>)
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Scalar {
    inner: ScalarFFI,
}

impl Scalar {
    /// Create a new scalar from limbs
    pub fn new(limbs: [u64; 5]) -> Self {
        Self {
            inner: ScalarFFI { limb: limbs },
        }
    }

    /// Create a new Scalar from a BigInt-like structure
    /// This is a convenience method for compatibility with tfhe-zk-pok's BigInt<5>
    pub fn from_bigint<const N: usize>(bigint: &[u64; N]) -> Self {
        const { assert!(N == 5, "from_bigint requires exactly ZP_LIMBS (5) limbs") };
        let mut limbs = [0u64; 5];
        limbs.copy_from_slice(bigint.as_slice());
        Self {
            inner: ScalarFFI { limb: limbs },
        }
    }

    /// Create a scalar from a single u64 value
    pub fn from_u64(value: u64) -> Self {
        Self {
            inner: ScalarFFI {
                limb: [value, 0, 0, 0, 0],
            },
        }
    }

    /// Get the limbs of the scalar
    #[inline]
    pub fn limbs(&self) -> [u64; 5] {
        self.inner.limb
    }

    /// Get the inner FFI type (for internal use)
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn inner(&self) -> &ScalarFFI {
        &self.inner
    }

    /// Get a mutable reference to the inner FFI type (for internal use)
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn inner_mut(&mut self) -> &mut ScalarFFI {
        &mut self.inner
    }

    /// Check if this scalar is less than the modulus (valid range)
    pub fn is_valid(&self) -> bool {
        let modulus = get_scalar_modulus();
        // Compare limbs from most significant to least significant
        for i in (0..5).rev() {
            if self.inner.limb[i] < modulus[i] {
                return true;
            }
            if self.inner.limb[i] > modulus[i] {
                return false;
            }
        }
        // Equal to modulus, which is out of range (should be < r)
        false
    }

    /// Reduce scalar modulo curve order if needed
    /// This is a simple reduction that works when scalar < 2*r
    /// For scalars >= 2*r, multiple subtractions may be needed
    pub fn reduce_if_needed(&self) -> Self {
        if self.is_valid() {
            return *self;
        }

        // Subtract modulus
        let modulus = get_scalar_modulus();
        let mut result = [0u64; 5];
        let mut borrow: u64 = 0;
        for i in 0..5 {
            let (diff, b1) = self.inner.limb[i].overflowing_sub(modulus[i]);
            let (diff2, b2) = diff.overflowing_sub(borrow);
            result[i] = diff2;
            borrow = (b1 as u64) + (b2 as u64);
        }

        Self::new(result)
    }
}

impl fmt::Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Scalar({:?})", self.limbs())
    }
}

impl fmt::Display for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Scalar({:?})", self.limbs())
    }
}

impl From<[u64; 5]> for Scalar {
    fn from(limbs: [u64; 5]) -> Self {
        Self::new(limbs)
    }
}

impl From<Scalar> for [u64; 5] {
    fn from(scalar: Scalar) -> Self {
        scalar.limbs()
    }
}
