use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, LweDimension,
};
use crate::core_crypto::specification::entities::markers::LweKeyswitchKeyKind;
use crate::core_crypto::specification::entities::AbstractEntity;

/// A trait implemented by types embodying an LWE keyswitch key.
///
/// # Formal Definition
///
/// ## Key Switching Key
///
/// A key switching key is a vector of Lev ciphertexts (described on the bottom of
/// [`this page`](`crate::core_crypto::specification::entities::GswCiphertextEntity`)).
/// It encrypts the coefficient of
/// the [`LWE secret key`](`crate::core_crypto::specification::entities::LweSecretKeyEntity`)
/// $\vec{s}\_{\mathsf{in}}$ under the
/// [`LWE secret key`](`crate::core_crypto::specification::entities::LweSecretKeyEntity`)
/// $\vec{s}\_{\mathsf{out}}$.
///
/// $$\mathsf{KSK}\_{\vec{s}\_{\mathsf{in}}\rightarrow \vec{s}\_{\mathsf{out}}} = \left(
/// \overline{\mathsf{ct}\_0}, \cdots , \overline{\mathsf{ct}\_{n\_{\mathsf{in}}-1}}\right)
/// \subseteq \mathbb{Z}\_q^{(n\_{\mathsf{out}}+1)\cdot n\_{\mathsf{in}}}$$
///
/// where $\vec{s}\_{\mathsf{in}} = \left( s\_0 , \cdots , s\_{\mathsf{in}-1} \right)$ and for all
/// $0\le i <n\_{\mathsf{in}}$ we have $\overline{\mathsf{ct}\_i} \in
/// \mathsf{Lev}\_{\vec{s}\_{\mathsf{out}}}^{\beta, \ell}\left(s\_i\right)$.
pub trait LweKeyswitchKeyEntity: AbstractEntity<Kind = LweKeyswitchKeyKind> {
    /// Returns the input LWE dimension of the key.
    fn input_lwe_dimension(&self) -> LweDimension;

    /// Returns the output lew dimension of the key.
    fn output_lwe_dimension(&self) -> LweDimension;

    /// Returns the number of decomposition levels of the key.
    fn decomposition_level_count(&self) -> DecompositionLevelCount;

    /// Returns the logarithm of the base used in the key.
    fn decomposition_base_log(&self) -> DecompositionBaseLog;
}
