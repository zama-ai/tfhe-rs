use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};
use crate::core_crypto::specification::entities::markers::LweBootstrapKeyKind;
use crate::core_crypto::specification::entities::AbstractEntity;

/// A trait implemented by types embodying an LWE bootstrap key.
///
/// # Formal Definition
///
/// ## Bootstrapping Key
/// A bootstrapping key is a vector of
/// [`GGSW ciphertexts`](`crate::core_crypto::specification::entities::GgswCiphertextEntity`). It
/// encrypts the coefficients of the [`LWE secret
/// key`](`crate::core_crypto::specification::entities::LweSecretKeyEntity`) $\vec{s}\_{\
/// mathsf{in}}$ under the [GLWE secret
/// key](`crate::core_crypto::specification::entities::GlweSecretKeyEntity`) $\vec{S}\_{\
/// mathsf{out}}$.
///
/// $$\mathsf{BSK}\_{\vec{s}\_{\mathsf{in}}\rightarrow \vec{S}\_{\mathsf{out}}} = \left(
/// \overline{\overline{\mathsf{CT}\_0}}, \cdots ,
/// \overline{\overline{\mathsf{CT}\_{n\_{\mathsf{in}}-1}}}\right) \subseteq
/// \mathbb{Z}\_q^{(n\_{\mathsf{out}}+1)\cdot n\_{\mathsf{in}}}$$
///
/// where $\vec{s}\_{\mathsf{in}} = \left( s\_0 , \cdots , s\_{\mathsf{in}-1} \right)$ and for all
/// $0\le i <n\_{\mathsf{in}}$ we have $\overline{\overline{\mathsf{CT}\_i}} \in
/// \mathsf{GGSW}\_{\vec{S}\_{\mathsf{out}}}^{\beta, \ell}\left(s\_i\right)$.
///
/// **Remark:** Observe that the GGSW secret key, which is a GLWE secret key,  can be easily seen as
/// a LWE secret key by simply taking all the coefficients of the polynomials composing the secret
/// key and putting them into a vector in order. We will call this LWE secret key derived from the
/// GLWE secret key **_extracted LWE key_**.
///
/// Let $\vec{S}\_{\mathsf{out}} = (S\_{\mathsf{out},0}, \ldots,
/// S\_{\mathsf{out},k\_{\mathsf{out}}-1}) \in \mathcal{R}^{k\_{\mathsf{out}}}$, such that
/// $S\_{\mathsf{out},i} = \sum\_{j=0}^{N\_{\mathsf{out}}-1} s\_{\mathsf{out},i, j} \cdot X^j$.
/// Then, the extracted LWE key will be $\vec{s}\_{\mathsf{out}} = (s\_{\mathsf{out},0,0}, \ldots,
/// s\_{\mathsf{out},0,N\_{\mathsf{out}}-1}, \ldots, s\_{\mathsf{out},k\_{\mathsf{out}}-1,0},
/// \ldots, s\_{\mathsf{out},k\_{\mathsf{out}}-1,N\_{\mathsf{out}}-1}) \in
/// \mathbb{Z}^{n\_{\mathsf{out}}}$, where $n\_{\mathsf{out}} = k\_{\mathsf{out}} \cdot
/// N\_{\mathsf{out}}$.
pub trait LweBootstrapKeyEntity: AbstractEntity<Kind = LweBootstrapKeyKind> {
    /// Returns the GLWE dimension of the key.
    fn glwe_dimension(&self) -> GlweDimension;

    /// Returns the polynomial size of the key.
    fn polynomial_size(&self) -> PolynomialSize;

    /// Returns the input LWE dimension of the key.
    fn input_lwe_dimension(&self) -> LweDimension;

    /// Returns the output LWE dimension of the key.
    fn output_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.glwe_dimension().0 * self.polynomial_size().0)
    }

    /// Returns the number of decomposition levels of the key.
    fn decomposition_base_log(&self) -> DecompositionBaseLog;

    /// Returns the logarithm of the base used in the key.
    fn decomposition_level_count(&self) -> DecompositionLevelCount;
}
