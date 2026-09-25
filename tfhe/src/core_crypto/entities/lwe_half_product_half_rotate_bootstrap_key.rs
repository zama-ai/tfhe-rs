//! Module containing the definition of the [`LweHalfProductHalfRotateBootstrapKey`].

use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::parameters::{GlweSize, LweDimension, PolynomialSize};
use crate::core_crypto::commons::traits::Container;
use crate::core_crypto::entities::LweHalfProductBootstrapKey;

/// The two standard-domain sections of a combined "half-product + half-rotate" bootstrap key.
///
/// The input LWE mask is split into two disjoint sections as in
/// [`LweHalfRotateBootstrapKey`](`crate::core_crypto::entities::LweHalfRotateBootstrapKey`), and
/// each section is itself a [`half-product key`](`LweHalfProductBootstrapKey`) with its own mask
/// and body decomposition parameters. Both sections encrypt under the same output GLWE key.
///
/// Convert it to the Fourier domain with
/// [`par_allocate_and_convert_standard_half_product_half_rotate_lwe_bootstrap_key_to_fourier_128`]
/// before use.
///
/// [`par_allocate_and_convert_standard_half_product_half_rotate_lwe_bootstrap_key_to_fourier_128`]:
///     crate::core_crypto::algorithms::par_allocate_and_convert_standard_half_product_half_rotate_lwe_bootstrap_key_to_fourier_128
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LweHalfProductHalfRotateBootstrapKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    start: LweHalfProductBootstrapKey<C>,
    end: LweHalfProductBootstrapKey<C>,
}

/// A [`LweHalfProductHalfRotateBootstrapKey`] owning its memory.
pub type LweHalfProductHalfRotateBootstrapKeyOwned<Scalar> =
    LweHalfProductHalfRotateBootstrapKey<Vec<Scalar>>;

impl<C: Container> LweHalfProductHalfRotateBootstrapKey<C>
where
    C::Element: UnsignedInteger,
{
    /// Bundle two standard-domain sections into a [`LweHalfProductHalfRotateBootstrapKey`].
    ///
    /// # Panics
    ///
    /// Panics if the two sections do not share the same GLWE size, polynomial size or ciphertext
    /// modulus.
    pub fn from_keys(
        start: LweHalfProductBootstrapKey<C>,
        end: LweHalfProductBootstrapKey<C>,
    ) -> Self {
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
    pub fn start(&self) -> &LweHalfProductBootstrapKey<C> {
        &self.start
    }

    /// Return the section covering the last input LWE mask elements.
    pub fn end(&self) -> &LweHalfProductBootstrapKey<C> {
        &self.end
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.start.glwe_size()
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.start.polynomial_size()
    }

    /// Total input LWE dimension of the two sections.
    pub fn input_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.start.input_lwe_dimension().0 + self.end.input_lwe_dimension().0)
    }
}
