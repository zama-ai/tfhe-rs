//! Module containing the definition of the GswCiphertext.

use tfhe_versionable::Versionize;

use crate::core_crypto::backward_compatibility::entities::gsw_ciphertext::GswCiphertextVersions;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;

// TODO actually implement primitives for the GswCiphertext.

/// A [`GSW ciphertext`](`GswCiphertext`).
///
/// # Note
///
/// The [`GswCiphertext`] entity and related algorithms are not yet implemented.
///
/// # Formal Definition
///
/// # GSW Ciphertext
///
/// A GSW ciphertext is an encryption of a plaintext.
/// It is a vector of Lev ciphertexts.
/// It is a specialization of
/// [`GGSW ciphertexts`](`crate::core_crypto::entities::GgswCiphertext`).
///
/// We call $q$ the ciphertext modulus.
///
/// We indicate a GSW ciphertext of a plaintext $\mathsf{pt} \in\mathbb{Z}\_q$ as the following
/// vector: $$\overline{\overline{\mathsf{ct}}} = \left( \overline{\mathsf{ct}\_0} , \cdots ,
/// \overline{\mathsf{ct}\_{n}} \right) \in \mathsf{GSW}\_{\vec{s}}^{\beta,
/// \ell}\left(\mathsf{pt}\right) \subseteq \mathbb{Z}\_q^{(n+1)\cdot\ell\cdot(n+1)}$$
///
/// Where $\vec{s}=\left(s\_0,\cdots, s\_{n-1}\right)$ and for all $0\le i <n$, we have
/// $\overline{\mathsf{ct}\_i} \in \mathsf{Lev}\_{\vec{s}}^{\beta, \ell}\left( -s\_i \cdot
/// \mathsf{pt}\right)\subseteq \mathbb{Z}\_q^{(n+1)\cdot\ell}$ and $\overline{\mathsf{ct}\_n} \in
/// \mathsf{Lev}\_{\vec{s}}^{\beta, \ell}\left( \mathsf{pt}\right)\subseteq
/// \mathbb{Z}\_q^{(n+1)\cdot\ell}$.
///
/// This type of ciphertext contains a lot of redundancy ($n+1$ Lev ciphertexts -- definition
/// below -- each encrypting the same plaintext times an element of the secret key).
///
/// ## Levels and decomposition base
/// A GSW ciphertext contains Lev ciphertexts that are parameterized with an integer $\ell$ called
/// level and an integer $\beta$ (generally a power of 2) called decomposition base.
///
/// ## Secret Key
/// A GSW ciphertext is encrypted under an
/// [`LWE secret key`](`crate::core_crypto::entities::LweSecretKey`).
///
/// ## GSW Encryption
/// ###### inputs:
/// - $\mathsf{pt}\in\mathbb{Z}\_q$: a plaintext
/// - $\vec{s}\in\mathbb{Z}\_q^n$: an [`LWE secret
///   key`](`crate::core_crypto::entities::LweSecretKey`)
/// - $\mathcal{D\_{\sigma^2,\mu}}$: a normal distribution of variance $\sigma^2$ and a mean of
///   $\mu$
/// - $\ell$: number of levels desired
/// - $\beta$: decomposition base
///
/// ###### outputs:
/// - $\overline{\overline{\mathsf{ct}}} = \left( \overline{\mathsf{ct}\_0} , \cdots ,
///   \overline{\mathsf{ct}\_{n}} \right) \in \mathsf{GSW}\_{\vec{s}}^{\beta, \ell} \subseteq
///   \mathbb{Z}\_q^{(n+1)\cdot\ell\cdot(n+1)}$: a GSW ciphertext
///
/// ###### algorithm:
/// 1. for $0\le i < n$:
///     - compute $\mathsf{pt}\_i = -s\_i\cdot\mathsf{pt} \in \mathbb{Z}\_q$
///     - compute $\overline{\mathsf{ct}\_i} \leftarrow \mathsf{Lev}.\mathsf{encrypt}\left(
///       \mathsf{pt}\_i, \vec{s} ,\mathcal{D\_{\sigma^2,\mu}} ,\ell \right)$
/// 2. compute  $\overline{\mathsf{ct}\_n} \leftarrow \mathsf{Lev}.\mathsf{encrypt}\left(
///    \mathsf{pt}, \vec{s} ,\mathcal{D\_{\sigma^2,\mu}} ,\ell \right)$
/// 3. output $\overline{\overline{\mathsf{ct}}} = \left( \overline{\mathsf{ct}\_0} , \cdots ,
///    \overline{\mathsf{ct}\_{n}} \right)$
///
/// ###### equivalent algorithm (using the gadget matrix):
/// 1. for $0\le i \le n$:
///     - for  $0\le j < \ell$:
///         - compute $\mathsf{ct}\_{i,j} \leftarrow \mathsf{LWE}.\mathsf{encrypt}\left( 0, \vec{s}
///           ,\mathcal{D\_{\sigma^2,\mu}} \right)$
///         - add to the $i$-th component of $\mathsf{ct}\_{i,j}$ the value
///           $\left\lfloor\mathsf{pt}\cdot \frac{q}{\beta^{j+1}} \right\rceil \in \mathbb{Z}\_q$
///     - set $\overline{\mathsf{ct}\_i} = \left( \mathsf{ct}\_{i,0} , \cdots ,
///       \mathsf{ct}\_{i,\ell-1} \right)$
/// 3. output $\overline{\overline{\mathsf{ct}}} = \left( \overline{\mathsf{ct}\_0} , \cdots ,
///    \overline{\mathsf{ct}\_{n}} \right)$
///
/// ## GSW Decryption
/// Simply use the Lev decryption algorithm on the last Lev ciphertext contained in the GSW
/// ciphertext.
///
/// # Lev Ciphertext
///
/// **Remark:** This type of ciphertexts is not yet directly exposed in the library but its
/// description helps understanding GSW ciphertext.
///
/// An Lev ciphertext is an encryption of a plaintext.
/// It is a vector of [`LWE ciphertexts`](`crate::core_crypto::entities::LweCiphertext`).
/// It is a specialization of GLev ciphertexts.
///
/// We call $q$ the ciphertext modulus.
///
/// We indicate a Lev ciphertext of a plaintext $\mathsf{pt} \in\mathbb{Z}\_q$ as the following
/// vector: $$\overline{\mathsf{ct}} = \left( \mathsf{ct}\_0 , \cdots , \mathsf{ct}\_{\ell-1}
/// \right) \in \mathsf{Lev}\_{\vec{s}}^{\beta, \ell}\left(\mathsf{pt}\right) \subseteq
/// \mathbb{Z}\_q^{(n+1)\cdot\ell}$$
///
/// Where $n=|\vec{s}|$ and for all $0\le i <\ell$, we have $\mathsf{ct}\_i \in
/// \mathsf{LWE}^n\_{\vec{s}}\left( \left\lfloor\mathsf{pt}\cdot \frac{q}{\beta^{i+1}} \right\rceil
/// \right)\subseteq \mathbb{Z}\_q^{(n+1)}$ (we are using the encoding in the MSB with $\Delta =
/// \frac{q}{\beta^{i+1}}$).
///
/// This type of ciphertext contains redundancy ($\ell$
/// [`LWE Ciphertext`](`crate::core_crypto::entities::LweCiphertext`),
/// each encrypting the same plaintext times a different scaling factor).
///
/// ## Decomposition base
/// A Lev ciphertext is parameterized with a decomposition base $\beta$, generally chosen as a power
/// of 2.
///
/// ## Levels
/// A Lev ciphertext contains a number of levels $\ell$ from level $0$ to level $\ell-1$.
///
/// ## Secret Key
/// A Lev ciphertext is encrypted under an
/// [`LWE secret key`](`crate::core_crypto::entities::LweSecretKey`).
///
/// ## Lev Encryption
/// ###### inputs:
/// - $\mathsf{pt}\in\mathbb{Z}\_q$: a plaintext
/// - $\vec{s}\in\mathbb{Z}\_q^n$: an [`LWE secret
///   key`](`crate::core_crypto::entities::LweSecretKey`)
/// - $\mathcal{D\_{\sigma^2,\mu}}$: a normal distribution of variance $\sigma^2$ and a mean of
///   $\mu$
/// - $\ell$: number of levels desired
/// - $\beta$: decomposition base
///
/// ###### outputs:
/// - $\overline{\mathsf{ct}} = \left( \mathsf{ct}\_0 , \cdots , \mathsf{ct}\_{\ell-1} \right) \in
///   \mathsf{Lev}\_{\vec{s}}^{\beta, \ell}\left(\mathsf{pt}\right) \subseteq
///   \mathbb{Z}\_q^{(n+1)\cdot\ell}$: a Lev ciphertext
///
/// ###### algorithm:
/// 1. for $0\le i < \ell-1$:
///     - compute $\mathsf{pt}\_i = \left\lfloor\mathsf{pt}\cdot \frac{q}{\beta^{i+1}} \right\rceil
///       \in \mathbb{Z}\_q$
///     - compute $\mathsf{ct}\_i \leftarrow \mathsf{LWE}.\mathsf{encrypt}\left( \mathsf{pt}\_i,
///       \vec{s} ,\mathcal{D\_{\sigma^2,\mu}} \right)$
/// 2. output $\overline{\mathsf{ct}} = \left( \mathsf{ct}\_0 , \cdots , \mathsf{ct}\_{\ell-1}
///    \right)$
///
/// ## Lev Decryption
/// Simply use the
/// [`LWE decryption algorithm`](`crate::core_crypto::algorithms::decrypt_lwe_ciphertext`)
/// on one of the LWE ciphertexts contained in the Lev ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(GswCiphertextVersions)]
pub struct GswCiphertext<C: Container> {
    data: C,
    lwe_size: LweSize,
    decomp_base_log: DecompositionBaseLog,
}
