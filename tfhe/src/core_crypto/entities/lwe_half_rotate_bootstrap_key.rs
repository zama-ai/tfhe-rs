//! Module containing the definition of the [`LweHalfRotateBootstrapKey`].

use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::parameters::{GlweSize, PolynomialSize};
use crate::core_crypto::commons::traits::Container;
use crate::core_crypto::entities::LweBootstrapKey;

/// The two standard-domain sections of a "half-rotate" bootstrap key.
///
/// The input LWE mask is split into two disjoint sections, each encrypted with its own
/// decomposition parameters but under the same output GLWE key, polynomial size and GLWE size.
/// This is the standard-domain output of
/// [`par_allocate_and_generate_new_half_rotate_lwe_bootstrap_key`]; convert it to the Fourier
/// domain with [`par_allocate_and_convert_standard_half_rotate_lwe_bootstrap_key_to_fourier_128`]
/// before use.
///
/// [`par_allocate_and_generate_new_half_rotate_lwe_bootstrap_key`]:
///     crate::core_crypto::algorithms::par_allocate_and_generate_new_half_rotate_lwe_bootstrap_key
/// [`par_allocate_and_convert_standard_half_rotate_lwe_bootstrap_key_to_fourier_128`]:
///     crate::core_crypto::algorithms::par_allocate_and_convert_standard_half_rotate_lwe_bootstrap_key_to_fourier_128
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LweHalfRotateBootstrapKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    start: LweBootstrapKey<C>,
    end: LweBootstrapKey<C>,
}

/// A [`LweHalfRotateBootstrapKey`] owning its memory.
pub type LweHalfRotateBootstrapKeyOwned<Scalar> = LweHalfRotateBootstrapKey<Vec<Scalar>>;

impl<C: Container> LweHalfRotateBootstrapKey<C>
where
    C::Element: UnsignedInteger,
{
    /// Bundle two standard-domain sections into a [`LweHalfRotateBootstrapKey`].
    ///
    /// # Panics
    ///
    /// Panics if the two sections do not share the same GLWE size, polynomial size or ciphertext
    /// modulus.
    pub fn from_keys(start: LweBootstrapKey<C>, end: LweBootstrapKey<C>) -> Self {
        assert_eq!(
            start.glwe_size(),
            end.glwe_size(),
            "Both half-rotate sections must share the same GLWE size"
        );
        assert_eq!(
            start.polynomial_size(),
            end.polynomial_size(),
            "Both half-rotate sections must share the same polynomial size"
        );
        assert_eq!(
            start.ciphertext_modulus(),
            end.ciphertext_modulus(),
            "Both half-rotate sections must share the same ciphertext modulus"
        );
        Self { start, end }
    }

    /// Return the section covering the first input LWE mask elements.
    pub fn start(&self) -> &LweBootstrapKey<C> {
        &self.start
    }

    /// Return the section covering the last input LWE mask elements.
    pub fn end(&self) -> &LweBootstrapKey<C> {
        &self.end
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.start.glwe_size()
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.start.polynomial_size()
    }
}
