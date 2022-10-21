use crate::core_crypto::commons::crypto::encoding::Plaintext;
use crate::core_crypto::commons::math::tensor::Container;

use crate::core_crypto::commons::crypto::glwe::GlweList;
use crate::core_crypto::commons::math::decomposition::DecompositionLevel;
use crate::core_crypto::commons::math::tensor::{
    ck_dim_div, tensor_traits, AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor, Tensor,
};
use crate::core_crypto::commons::math::torus::UnsignedTorus;

use super::GgswLevelMatrix;

use crate::core_crypto::commons::numeric::Numeric;
use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
};
#[cfg(feature = "__commons_parallel")]
use rayon::{iter::IndexedParallelIterator, prelude::*};
#[cfg(feature = "__commons_serialization")]
use serde::{Deserialize, Serialize};

/// A GGSW ciphertext.
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StandardGgswCiphertext<Cont> {
    pub(crate) tensor: Tensor<Cont>,
    poly_size: PolynomialSize,
    rlwe_size: GlweSize,
    decomp_base_log: DecompositionBaseLog,
}

tensor_traits!(StandardGgswCiphertext);

impl<Scalar> StandardGgswCiphertext<Vec<Scalar>> {
    /// Allocates a new GGSW ciphertext whose coefficients are all `value`.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::ggsw::StandardGgswCiphertext;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    ///
    /// let ggsw = StandardGgswCiphertext::allocate(
    ///     9 as u8,
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(4),
    /// );
    /// assert_eq!(ggsw.glwe_size(), GlweSize(7));
    /// assert_eq!(ggsw.decomposition_level_count(), DecompositionLevelCount(3));
    /// assert_eq!(ggsw.decomposition_base_log(), DecompositionBaseLog(4));
    /// ```
    pub fn allocate(
        value: Scalar,
        poly_size: PolynomialSize,
        rlwe_size: GlweSize,
        decomp_level: DecompositionLevelCount,
        decomp_base_log: DecompositionBaseLog,
    ) -> Self
    where
        Scalar: Copy,
    {
        StandardGgswCiphertext {
            tensor: Tensor::from_container(vec![
                value;
                decomp_level.0
                    * rlwe_size.0
                    * rlwe_size.0
                    * poly_size.0
            ]),
            poly_size,
            rlwe_size,
            decomp_base_log,
        }
    }
}

impl<Scalar> StandardGgswCiphertext<Vec<Scalar>>
where
    Scalar: UnsignedTorus,
{
    pub fn new_trivial_encryption(
        poly_size: PolynomialSize,
        glwe_size: GlweSize,
        decomp_level: DecompositionLevelCount,
        decomp_base_log: DecompositionBaseLog,
        plaintext: &Plaintext<Scalar>,
    ) -> Self {
        let mut ciphertext = Self::allocate(
            Scalar::ZERO,
            poly_size,
            glwe_size,
            decomp_level,
            decomp_base_log,
        );
        ciphertext.fill_with_trivial_encryption(plaintext);
        ciphertext
    }
}

impl<Cont> StandardGgswCiphertext<Cont> {
    /// Creates an Rgsw ciphertext from an existing container.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::ggsw::StandardGgswCiphertext;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    ///
    /// let ggsw = StandardGgswCiphertext::from_container(
    ///     vec![9 as u8; 7 * 7 * 10 * 3],
    ///     GlweSize(7),
    ///     PolynomialSize(10),
    ///     DecompositionBaseLog(4),
    /// );
    /// assert_eq!(ggsw.glwe_size(), GlweSize(7));
    /// assert_eq!(ggsw.decomposition_level_count(), DecompositionLevelCount(3));
    /// assert_eq!(ggsw.decomposition_base_log(), DecompositionBaseLog(4));
    /// ```
    pub fn from_container(
        cont: Cont,
        rlwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
    ) -> Self
    where
        Cont: AsRefSlice,
    {
        let tensor = Tensor::from_container(cont);
        ck_dim_div!(tensor.len() => rlwe_size.0, poly_size.0, rlwe_size.0 * rlwe_size.0);
        StandardGgswCiphertext {
            tensor,
            poly_size,
            rlwe_size,
            decomp_base_log,
        }
    }

    pub fn into_container(self) -> Cont {
        self.tensor.into_container()
    }

    pub fn as_view(&self) -> StandardGgswCiphertext<&'_ [Cont::Element]>
    where
        Cont: Container,
    {
        StandardGgswCiphertext {
            tensor: Tensor::from_container(self.tensor.as_container().as_ref()),
            poly_size: self.poly_size,
            rlwe_size: self.rlwe_size,
            decomp_base_log: self.decomp_base_log,
        }
    }

    pub fn as_mut_view(&mut self) -> StandardGgswCiphertext<&'_ mut [Cont::Element]>
    where
        Cont: Container,
        Cont: AsMut<[Cont::Element]>,
    {
        StandardGgswCiphertext {
            tensor: Tensor::from_container(self.tensor.as_mut_container().as_mut()),
            poly_size: self.poly_size,
            rlwe_size: self.rlwe_size,
            decomp_base_log: self.decomp_base_log,
        }
    }

    /// Returns the size of the glwe ciphertexts composing the ggsw ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::ggsw::StandardGgswCiphertext;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    ///
    /// let ggsw = StandardGgswCiphertext::allocate(
    ///     9 as u8,
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(4),
    /// );
    /// assert_eq!(ggsw.glwe_size(), GlweSize(7));
    /// ```
    pub fn glwe_size(&self) -> GlweSize {
        self.rlwe_size
    }

    /// Returns the number of decomposition levels used in the ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::ggsw::StandardGgswCiphertext;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    ///
    /// let ggsw = StandardGgswCiphertext::allocate(
    ///     9 as u8,
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(4),
    /// );
    /// assert_eq!(ggsw.decomposition_level_count(), DecompositionLevelCount(3));
    /// ```
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount
    where
        Self: AsRefTensor,
    {
        ck_dim_div!(self.as_tensor().len() =>
            self.rlwe_size.0,
            self.poly_size.0,
            self.rlwe_size.0 * self.rlwe_size.0
        );
        DecompositionLevelCount(
            self.as_tensor().len() / (self.rlwe_size.0 * self.rlwe_size.0 * self.poly_size.0),
        )
    }

    /// Returns the size of the polynomials used in the ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::ggsw::StandardGgswCiphertext;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    ///
    /// let ggsw = StandardGgswCiphertext::allocate(
    ///     9 as u8,
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(4),
    /// );
    /// assert_eq!(ggsw.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.poly_size
    }

    /// Returns a borrowed list composed of all the GLWE ciphertext composing current ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::ggsw::StandardGgswCiphertext;
    /// use tfhe::core_crypto::prelude::{
    ///     CiphertextCount, DecompositionBaseLog, DecompositionLevelCount, GlweDimension, GlweSize,
    ///     PolynomialSize,
    /// };
    ///
    /// let ggsw = StandardGgswCiphertext::allocate(
    ///     9 as u8,
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(4),
    /// );
    /// let list = ggsw.as_glwe_list();
    /// assert_eq!(list.glwe_dimension(), GlweDimension(6));
    /// assert_eq!(list.ciphertext_count(), CiphertextCount(3 * 7));
    /// ```
    pub fn as_glwe_list<Scalar>(&self) -> GlweList<&[Scalar]>
    where
        Self: AsRefTensor<Element = Scalar>,
    {
        GlweList::from_container(
            self.as_tensor().as_slice(),
            self.rlwe_size.to_glwe_dimension(),
            self.poly_size,
        )
    }

    /// Returns a mutably borrowed `GlweList` composed of all the GLWE ciphertext composing
    /// current ciphertext.
    ///
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::ggsw::StandardGgswCiphertext;
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use tfhe::core_crypto::prelude::{
    ///     CiphertextCount, DecompositionBaseLog, DecompositionLevelCount, GlweDimension, GlweSize,
    ///     PolynomialSize,
    /// };
    ///
    /// let mut ggsw = StandardGgswCiphertext::allocate(
    ///     9 as u8,
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(4),
    /// );
    /// let mut list = ggsw.as_mut_glwe_list();
    /// list.as_mut_tensor().fill_with_element(0);
    /// assert_eq!(list.glwe_dimension(), GlweDimension(6));
    /// assert_eq!(list.ciphertext_count(), CiphertextCount(3 * 7));
    /// ggsw.as_tensor().iter().for_each(|a| assert_eq!(*a, 0));
    /// ```
    pub fn as_mut_glwe_list<Scalar>(&mut self) -> GlweList<&mut [Scalar]>
    where
        Self: AsMutTensor<Element = Scalar>,
    {
        let dimension = self.rlwe_size.to_glwe_dimension();
        let size = self.poly_size;
        GlweList::from_container(self.as_mut_tensor().as_mut_slice(), dimension, size)
    }

    /// Returns the logarithm of the base used for the gadget decomposition.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::ggsw::StandardGgswCiphertext;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    ///
    /// let ggsw = StandardGgswCiphertext::allocate(
    ///     9 as u8,
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(4),
    /// );
    /// assert_eq!(ggsw.decomposition_base_log(), DecompositionBaseLog(4));
    /// ```
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Returns an iterator over borrowed level matrices.
    ///
    /// # Note
    ///
    /// This iterator iterates over the levels from the lower to the higher level in the usual
    /// order. To iterate in the reverse order, you can use `rev()` on the iterator.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::ggsw::StandardGgswCiphertext;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    ///
    /// let ggsw = StandardGgswCiphertext::allocate(
    ///     9 as u8,
    ///     PolynomialSize(9),
    ///     GlweSize(7),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(4),
    /// );
    /// for level_matrix in ggsw.level_matrix_iter() {
    ///     assert_eq!(level_matrix.row_iter().count(), 7);
    ///     assert_eq!(level_matrix.polynomial_size(), PolynomialSize(9));
    ///     for rlwe in level_matrix.row_iter() {
    ///         assert_eq!(rlwe.glwe_size(), GlweSize(7));
    ///         assert_eq!(rlwe.polynomial_size(), PolynomialSize(9));
    ///     }
    /// }
    /// assert_eq!(ggsw.level_matrix_iter().count(), 3);
    /// ```
    pub fn level_matrix_iter(
        &self,
    ) -> impl DoubleEndedIterator<Item = GgswLevelMatrix<&[<Self as AsRefTensor>::Element]>>
    where
        Self: AsRefTensor,
    {
        let chunks_size = self.poly_size.0 * self.rlwe_size.0 * self.rlwe_size.0;
        let poly_size = self.poly_size;
        let rlwe_size = self.rlwe_size;
        self.as_tensor()
            .subtensor_iter(chunks_size)
            .enumerate()
            .map(move |(index, tensor)| {
                GgswLevelMatrix::from_container(
                    tensor.into_container(),
                    poly_size,
                    rlwe_size,
                    DecompositionLevel(index + 1),
                )
            })
    }

    /// Returns an iterator over mutably borrowed level matrices.
    ///
    /// # Note
    ///
    /// This iterator iterates over the levels from the lower to the higher level in the usual
    /// order. To iterate in the reverse order, you can use `rev()` on the iterator.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::ggsw::StandardGgswCiphertext;
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    ///
    /// let mut ggsw = StandardGgswCiphertext::allocate(
    ///     9 as u8,
    ///     PolynomialSize(9),
    ///     GlweSize(7),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(4),
    /// );
    /// for mut level_matrix in ggsw.level_matrix_iter_mut() {
    ///     for mut rlwe in level_matrix.row_iter_mut() {
    ///         rlwe.as_mut_tensor().fill_with_element(9);
    ///     }
    /// }
    /// assert!(ggsw.as_tensor().iter().all(|a| *a == 9));
    /// assert_eq!(ggsw.level_matrix_iter_mut().count(), 3);
    /// ```
    pub fn level_matrix_iter_mut(
        &mut self,
    ) -> impl DoubleEndedIterator<Item = GgswLevelMatrix<&mut [<Self as AsRefTensor>::Element]>>
    where
        Self: AsMutTensor,
    {
        let chunks_size = self.poly_size.0 * self.rlwe_size.0 * self.rlwe_size.0;
        let poly_size = self.poly_size;
        let rlwe_size = self.rlwe_size;
        self.as_mut_tensor()
            .subtensor_iter_mut(chunks_size)
            .enumerate()
            .map(move |(index, tensor)| {
                GgswLevelMatrix::from_container(
                    tensor.into_container(),
                    poly_size,
                    rlwe_size,
                    DecompositionLevel(index + 1),
                )
            })
    }

    /// Returns a parallel iterator over mutably borrowed level matrices.
    ///
    /// # Notes
    /// This iterator is hidden behind the "__commons_parallel" feature gate.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::ggsw::StandardGgswCiphertext;
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
    /// };
    /// use rayon::iter::ParallelIterator;
    ///
    /// let mut ggsw = StandardGgswCiphertext::allocate(
    ///     9 as u8,
    ///     PolynomialSize(9),
    ///     GlweSize(7),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(4),
    /// );
    /// ggsw.par_level_matrix_iter_mut()
    ///     .for_each(|mut level_matrix| {
    ///         for mut rlwe in level_matrix.row_iter_mut() {
    ///             rlwe.as_mut_tensor().fill_with_element(9);
    ///         }
    ///     });
    /// assert!(ggsw.as_tensor().iter().all(|a| *a == 9));
    /// assert_eq!(ggsw.level_matrix_iter_mut().count(), 3);
    /// ```
    #[cfg(feature = "__commons_parallel")]
    pub fn par_level_matrix_iter_mut(
        &mut self,
    ) -> impl IndexedParallelIterator<Item = GgswLevelMatrix<&mut [<Self as AsRefTensor>::Element]>>
    where
        Self: AsMutTensor,
        <Self as AsMutTensor>::Element: Sync + Send,
    {
        let chunks_size = self.poly_size.0 * self.rlwe_size.0 * self.rlwe_size.0;
        let poly_size = self.poly_size;
        let rlwe_size = self.rlwe_size;
        self.as_mut_tensor()
            .par_subtensor_iter_mut(chunks_size)
            .enumerate()
            .map(move |(index, tensor)| {
                GgswLevelMatrix::from_container(
                    tensor.into_container(),
                    poly_size,
                    rlwe_size,
                    DecompositionLevel(index + 1),
                )
            })
    }

    pub fn fill_with_trivial_encryption<Scalar>(&mut self, plaintext: &Plaintext<Scalar>)
    where
        Self: AsMutTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
    {
        // We fill the ggsw with trivial glwe encryptions of zero:
        for mut glwe in self.as_mut_glwe_list().ciphertext_iter_mut() {
            let mut mask = glwe.get_mut_mask();
            mask.as_mut_tensor().fill_with_element(Scalar::ZERO);
        }
        let base_log = self.decomposition_base_log();
        for mut matrix in self.level_matrix_iter_mut() {
            let decomposition = plaintext.0.wrapping_mul(
                Scalar::ONE
                    << (<Scalar as Numeric>::BITS
                        - (base_log.0 * (matrix.decomposition_level().0))),
            );
            // We iterate over the rows of the level matrix
            for (index, row) in matrix.row_iter_mut().enumerate() {
                let rlwe_ct = row.into_glwe();
                // We retrieve the row as a polynomial list
                let mut polynomial_list = rlwe_ct.into_polynomial_list();
                // We retrieve the polynomial in the diagonal
                let mut level_polynomial = polynomial_list.get_mut_polynomial(index);
                // We get the first coefficient
                let first_coef = level_polynomial.as_mut_tensor().first_mut();
                // We update the first coefficient
                *first_coef = first_coef.wrapping_add(decomposition);
            }
        }
    }
}
