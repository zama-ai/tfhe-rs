use crate::core_crypto::prelude::{GlweDimension, PolynomialSize};
use crate::core_crypto::specification::entities::markers::GlweSecretKeyKind;
use crate::core_crypto::specification::entities::AbstractEntity;

/// A trait implemented by types embodying a GLWE secret key.
///
/// # Formal Definition
///
/// ## GLWE Secret Key
///
/// We consider a secret key:
/// $$\vec{S} =\left( S\_0, \ldots, S\_{k-1}\right) \in \mathcal{R}^{k}$$
/// The $k$ polynomials composing $\vec{S}$ contain each $N$ integers coefficients that have been
/// sampled from some distribution which is either uniformly binary, uniformly ternary, gaussian or
/// even uniform.
pub trait GlweSecretKeyEntity: AbstractEntity<Kind = GlweSecretKeyKind> {
    /// Returns the GLWE dimension of the key.
    fn glwe_dimension(&self) -> GlweDimension;

    /// Returns the polynomial size of the key.
    fn polynomial_size(&self) -> PolynomialSize;
}
