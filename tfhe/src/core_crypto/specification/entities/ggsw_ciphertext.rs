use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
};
use crate::core_crypto::specification::entities::markers::GgswCiphertextKind;
use crate::core_crypto::specification::entities::AbstractEntity;

/// A trait implemented by types embodying a GGSW ciphertext.
///
/// # Formal Definition
///
/// # GGSW Ciphertext
///
/// A GGSW ciphertext is an encryption of a polynomial plaintext.
/// It is a vector of [`GLWE
/// ciphertexts`](`crate::core_crypto::specification::entities::GlweCiphertextEntity`). It is
/// a generalization of both GSW ciphertexts and RGSW ciphertexts.
///
/// We call $q$ the ciphertext modulus.
/// We use the notation $\mathcal{R}\_q$ for the following cyclotomic ring:
/// $\mathbb{Z}\_q\[X\]/\left\langle X^N + 1\right\rangle$ where $N\in\mathbb{N}$ is a
/// power of two.
///
/// We indicate a GGSW ciphertext of a polynomial plaintext $\mathsf{PT} \in\mathcal{R}\_q$
/// as the following vector:
///
/// $$\overline{\overline{\mathsf{CT}}} = \left( \overline{\mathsf{CT}\_0}, \cdots
/// , \overline{\mathsf{CT}\_{k}} \right) \in \mathsf{GGSW}\_{\vec{S}}^{\beta,
/// \ell}\left(\mathsf{PT}\right) \subseteq \mathcal{R}\_q^{(k+1)\times\ell\cdot(k+1)}$$
///
/// Where $\vec{S}=\left(S\_0, \cdots , S\_{k-1}\right)\in \mathcal{R}\_q^k$ and for all $0\le i<k$
/// we have $\overline{\mathsf{CT}\_i} \in \mathsf{GLev}\_{\vec{S}}^{\beta, \ell}\left( -S\_i \cdot
/// \mathsf{PT}\right)\subseteq \mathcal{R}\_q^{\ell \cdot (k+1)}$ and $\overline{\mathsf{CT}\_k}
/// \in \mathsf{GLev}\_{\vec{S}}^{\beta, \ell}\left( \mathsf{PT}\right)\subseteq
/// \mathcal{R}\_q^{\ell \cdot (k+1)}$.
///
/// This type of ciphertext contains a lot of redundancy ($k+1$ GLev ciphertexts -- definition
/// below -- each encrypting the same plaintext times an element of the secret key) .
///
/// ## Levels and decomposition base
/// A GGSW ciphertext contains GLev ciphertexts that are parametrized with an
/// integer $\ell$ called level and an integer $\beta$ (generally a power of 2) called
/// decomposition base.
///
/// ## Secret Key
/// A GGSW ciphertext is encrypted under a
/// [`GLWE secret key`](`crate::core_crypto::specification::entities::GlweSecretKeyEntity`).
///
/// ## GGSW Encryption
/// ###### inputs:
/// - $\mathsf{PT}\in\mathcal{R}\_q$: a polynomial plaintext
/// - $\vec{S}=\left(S\_0, \cdots, S\_{k-1} \right) \in\mathcal{R}\_q^k$: an
/// [`GLWE secret key`](`crate::core_crypto::specification::entities::GlweSecretKeyEntity`)
/// - $\mathcal{D\_{\sigma^2,\mu}}$: a normal distribution of variance $\sigma^2$ and a mean of
///   $\mu$
/// - $\ell$: number of levels desired
/// - $\beta$: decomposition base
///
/// ###### outputs:
/// - $\overline{\overline{\mathsf{CT}}} = \left( \overline{\mathsf{CT}\_0}, \cdots ,
///   \overline{\mathsf{CT}\_{k-1}} \right) \in \mathsf{GGSW}\_{\vec{S}}^{\beta,
///   \ell}\left(\mathsf{PT}\right) \subseteq \mathcal{R}\_q^{(k+1)\cdot\ell\cdot(k+1)}$: a GGSW
///   ciphertext
///
/// ###### algorithm:
/// 1. for $0\le i < k$:
///     - compute $\mathsf{PT}\_i = -S\_i\cdot\mathsf{PT} \in \mathbb{Z}\_q$
///     - compute $\overline{\mathsf{CT}\_i} \leftarrow \mathsf{GLev}.\mathsf{encrypt}\left(
///    \mathsf{PT}\_i, \vec{S} ,\mathcal{D\_{\sigma^2,\mu}} ,\ell \right)$
/// 2. compute  $\overline{\mathsf{CT}\_n} \leftarrow \mathsf{GLev}.\mathsf{encrypt}\left(
/// \mathsf{PT}, \vec{s} ,\mathcal{D\_{\sigma^2,\mu}} ,\ell \right)$
/// 3. output $\overline{\overline{\mathsf{CT}}} = \left( \overline{\mathsf{CT}\_0} , \cdots ,
/// \overline{\mathsf{CT}\_{n}} \right)$
///
/// ###### equivalent algorithm (using the gadget matrix):
/// 1. for $0\le i \le k$:
///     - for  $0\le j < \ell$:
///         - compute $\mathsf{CT}\_{i,j} \leftarrow \mathsf{GLWE}.\mathsf{encrypt}\left( 0, \vec{S}
///     ,\mathcal{D\_{\sigma^2,\mu}} \right)$
///         - add to the $i$-th component of $\mathsf{CT}\_{i,j}$ the value
///           $\left\lfloor\mathsf{PT}\cdot
///     \frac{q}{\beta^{j+1}} \right\rceil \in \mathcal{R}\_q$
///     - set $\overline{\mathsf{CT}\_i} = \left( \mathsf{CT}\_{i,0} , \cdots ,
///       \mathsf{CT}\_{i,\ell-1}
///    \right)$
/// 2. output $\overline{\overline{\mathsf{CT}}} = \left( \overline{\mathsf{CT}\_0} , \cdots ,
/// \overline{\mathsf{CT}\_{n}} \right)$
///
/// ## GGSW Decryption
/// Simply use the GLev decryption algorithm on the last GLev ciphertext contained in the GGSW
/// ciphertext.
///
/// # GLev Ciphertext
///
/// **Remark:** This type of ciphertexts is not yet directly exposed in the library but its
/// description helps understanding GGSW ciphertext.
///
/// A GLev ciphertext is an encryption of a polynomial plaintext.
/// It is a vector of GLev ciphertexts.
/// It is a generalization of both Lev ciphertexts and RLev ciphertexts.
///
/// We call $q$ the ciphertext modulus.
/// We use the notation $\mathcal{R}\_q$ for the following cyclotomic ring:
/// $\mathbb{Z}\_q\[X\]/\left\langle X^N + 1\right\rangle$ where $N\in\mathbb{N}$ is a power of two.
///
/// We indicate a GLev ciphertext of a polynomial plaintext $\mathsf{PT} \in\mathcal{R}\_q^{k+1}$ as
/// the following vector: $$\overline{\mathsf{CT}} = \left( \mathsf{CT}\_0 , \cdots ,
/// \mathsf{CT}\_{\ell-1} \right) \in \mathsf{GLev}\_{\vec{S}}^{\beta, \ell}\left(\mathsf{PT}\right)
/// \subseteq \mathcal{R}\_q^{(k+1)\cdot \ell}$$
///
/// Where $k=|\vec{S}|$ and for all $0\le i <\ell$, we have $\mathsf{CT}\_i \in
/// \mathsf{GLWE}\_{\vec{S}}\left( \left\lfloor\mathsf{PT}\cdot \frac{q}{\beta^{i+1}} \right\rceil
/// \right)\subseteq  \mathcal{R}\_q^{k+1}$ (we are using the encoding in the MSB with $\Delta =
/// \frac{q}{\beta^{i+1}}$).
///
/// This type of ciphertext contains redundancy ($\ell$
/// [`GLWE ciphertext`](`crate::core_crypto::specification::entities::GlweCiphertextEntity`),
/// each encrypting the same plaintext times a different scaling factor).
///
/// ## Decomposition base
/// A GLev ciphertext is parametrized with a decomposition base $\beta$, generally chosen as a power
/// of 2.
///
/// ## Levels
/// A GLev ciphertext contains a number of levels $\ell$ from level $0$ to level $\ell-1$.
///
/// ## Secret Key
/// A GLev ciphertext is encrypted under a
/// [`GLWE secret key`](`crate::core_crypto::specification::entities::GlweSecretKeyEntity`).
///
/// ## GLev Encryption
/// ###### inputs:
/// - $\mathsf{PT}\in \mathcal{R}\_q$: a polynomial plaintext
/// - $\vec{S}\in  \mathcal{R}\_q^k$: a
/// [`GLWE Secret Key`](`crate::core_crypto::specification::entities::GlweSecretKeyEntity`)
/// - $\mathcal{D\_{\sigma^2,\mu}}$: a normal distribution of variance $\sigma^2$ and a mean of
///   $\mu$
/// - $\ell$: number of levels desired
/// - $\beta$: decomposition base
///
/// ###### outputs:
/// - $\overline{\mathsf{CT}} = \left( \mathsf{CT}\_0 , \cdots , \mathsf{CT}\_{\ell-1} \right) \in
///   \mathsf{GLev}\_{\vec{S}}^{\beta, \ell}\left(\mathsf{PT}\right) \subseteq
///   \mathcal{R}\_q^{(k+1)\cdot\ell}$: a GLev ciphertext
///
/// ###### algorithm:
/// 1. for $0\le i < \ell-1$:
///     - compute $\mathsf{PT}\_i = \left\lfloor\mathsf{PT}\cdot \frac{q}{\beta^{i+1}} \right\rceil
///       \in
///    \mathcal{R}\_q$
///     - compute $\mathsf{CT}\_i \leftarrow \mathsf{GLWE}.\mathsf{encrypt}\left( \mathsf{PT}\_i,
///    \vec{S} ,\mathcal{D\_{\sigma^2,\mu}} \right)$
/// 2. output $\overline{\mathsf{CT}} = \left( \mathsf{CT}\_0 , \cdots , \mathsf{CT}\_{\ell-1}
/// \right)$
///
/// ## GLev Decryption
/// Simply use the
/// [`GLWE decryption
/// algorithm`](`crate::core_crypto::specification::engines::GlweCiphertextDecryptionEngine`)
/// on one of the GLWE ciphertexts contained in the GLev ciphertext.
pub trait GgswCiphertextEntity: AbstractEntity<Kind = GgswCiphertextKind> {
    /// Returns the GLWE dimension of the ciphertext.
    fn glwe_dimension(&self) -> GlweDimension;

    /// Returns the polynomial size of the ciphertext.
    fn polynomial_size(&self) -> PolynomialSize;

    /// Returns the number of decomposition levels of the ciphertext.
    fn decomposition_level_count(&self) -> DecompositionLevelCount;

    /// Returns the logarithm of the base used in the ciphertext.
    fn decomposition_base_log(&self) -> DecompositionBaseLog;
}
