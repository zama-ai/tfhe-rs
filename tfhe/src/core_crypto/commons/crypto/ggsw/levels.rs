use crate::core_crypto::commons::crypto::glwe::GlweCiphertext;
use crate::core_crypto::commons::math::decomposition::DecompositionLevel;
use crate::core_crypto::commons::math::tensor::{
    ck_dim_div, tensor_traits, AsMutTensor, AsRefSlice, AsRefTensor, Tensor,
};
use crate::core_crypto::prelude::{GlweSize, PolynomialSize};
#[cfg(feature = "__commons_parallel")]
use rayon::prelude::*;

/// A matrix containing a single level of gadget decomposition.
pub struct GgswLevelMatrix<Cont> {
    tensor: Tensor<Cont>,
    poly_size: PolynomialSize,
    glwe_size: GlweSize,
    level: DecompositionLevel,
}

tensor_traits!(GgswLevelMatrix);

impl<Cont> GgswLevelMatrix<Cont> {
    /// Creates a GGSW level matrix from an arbitrary container.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::ggsw::GgswLevelMatrix;
    /// use tfhe::core_crypto::commons::math::decomposition::DecompositionLevel;
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialSize};
    /// let level_matrix = GgswLevelMatrix::from_container(
    ///     vec![0 as u8; 10 * 7 * 7],
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     DecompositionLevel(1),
    /// );
    /// assert_eq!(level_matrix.polynomial_size(), PolynomialSize(10));
    /// assert_eq!(level_matrix.glwe_size(), GlweSize(7));
    /// assert_eq!(level_matrix.decomposition_level(), DecompositionLevel(1));
    /// ```
    pub fn from_container(
        cont: Cont,
        poly_size: PolynomialSize,
        rlwe_size: GlweSize,
        level: DecompositionLevel,
    ) -> Self
    where
        Cont: AsRefSlice,
    {
        let tensor = Tensor::from_container(cont);
        ck_dim_div!(tensor.len() => rlwe_size.0, poly_size.0);
        GgswLevelMatrix {
            tensor,
            poly_size,
            glwe_size: rlwe_size,
            level,
        }
    }

    /// Returns the size of the GLWE ciphertexts composing the GGSW level matrix.
    ///
    /// This is also the number of columns of the matrix (assuming it is a matrix of
    /// polynomials), as well as its number of rows.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::ggsw::GgswLevelMatrix;
    /// use tfhe::core_crypto::commons::math::decomposition::DecompositionLevel;
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialSize};
    /// let level_matrix = GgswLevelMatrix::from_container(
    ///     vec![0 as u8; 10 * 7 * 7],
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     DecompositionLevel(1),
    /// );
    /// assert_eq!(level_matrix.glwe_size(), GlweSize(7));
    /// ```
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    /// Returns the index of the level corresponding to this matrix.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::ggsw::GgswLevelMatrix;
    /// use tfhe::core_crypto::commons::math::decomposition::DecompositionLevel;
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialSize};
    /// let level_matrix = GgswLevelMatrix::from_container(
    ///     vec![0 as u8; 10 * 7 * 7],
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     DecompositionLevel(1),
    /// );
    /// assert_eq!(level_matrix.decomposition_level(), DecompositionLevel(1));
    /// ```
    pub fn decomposition_level(&self) -> DecompositionLevel {
        self.level
    }

    /// Returns the size of the polynomials of the current ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::ggsw::GgswLevelMatrix;
    /// use tfhe::core_crypto::commons::math::decomposition::DecompositionLevel;
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialSize};
    /// let level_matrix = GgswLevelMatrix::from_container(
    ///     vec![0 as u8; 10 * 7 * 7],
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     DecompositionLevel(1),
    /// );
    /// assert_eq!(level_matrix.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.poly_size
    }

    /// Returns an iterator over the borrowed rows of the matrix.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::ggsw::GgswLevelMatrix;
    /// use tfhe::core_crypto::commons::math::decomposition::DecompositionLevel;
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialSize};
    /// let level_matrix = GgswLevelMatrix::from_container(
    ///     vec![0 as u8; 10 * 7 * 7],
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     DecompositionLevel(1),
    /// );
    /// for row in level_matrix.row_iter() {
    ///     assert_eq!(row.glwe_size(), GlweSize(7));
    ///     assert_eq!(row.polynomial_size(), PolynomialSize(10));
    /// }
    /// assert_eq!(level_matrix.row_iter().count(), 7);
    /// ```
    pub fn row_iter(&self) -> impl Iterator<Item = GgswLevelRow<&[<Self as AsRefTensor>::Element]>>
    where
        Self: AsRefTensor,
    {
        self.as_tensor()
            .subtensor_iter(self.poly_size.0 * self.glwe_size.0)
            .map(move |tens| {
                GgswLevelRow::from_container(tens.into_container(), self.poly_size, self.level)
            })
    }

    /// Returns an iterator over the mutably borrowed rows of the matrix.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::ggsw::GgswLevelMatrix;
    /// use tfhe::core_crypto::commons::math::decomposition::DecompositionLevel;
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialSize};
    /// let mut level_matrix = GgswLevelMatrix::from_container(
    ///     vec![0 as u8; 10 * 7 * 7],
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     DecompositionLevel(1),
    /// );
    /// for mut row in level_matrix.row_iter_mut() {
    ///     row.as_mut_tensor().fill_with_element(9);
    /// }
    /// assert!(level_matrix.as_tensor().iter().all(|a| *a == 9));
    /// assert_eq!(level_matrix.row_iter_mut().count(), 7);
    /// ```
    pub fn row_iter_mut(
        &mut self,
    ) -> impl Iterator<Item = GgswLevelRow<&mut [<Self as AsRefTensor>::Element]>>
    where
        Self: AsMutTensor,
    {
        let chunks_size = self.poly_size.0 * self.glwe_size.0;
        let poly_size = self.poly_size;
        let level = self.level;
        self.as_mut_tensor()
            .subtensor_iter_mut(chunks_size)
            .map(move |tens| GgswLevelRow::from_container(tens.into_container(), poly_size, level))
    }

    /// Returns a parallel iterator over the mutably borrowed rows of the matrix.
    ///
    /// # Note
    ///
    /// This method uses _rayon_ internally, and is hidden behind the "__commons_parallel" feature
    /// gate.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::ggsw::GgswLevelMatrix;
    /// use tfhe::core_crypto::commons::math::decomposition::DecompositionLevel;
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialSize};
    /// use rayon::iter::ParallelIterator;
    /// let mut level_matrix = GgswLevelMatrix::from_container(
    ///     vec![0 as u8; 10 * 7 * 7],
    ///     PolynomialSize(10),
    ///     GlweSize(7),
    ///     DecompositionLevel(1),
    /// );
    /// level_matrix.par_row_iter_mut().for_each(|mut row| {
    ///     row.as_mut_tensor().fill_with_element(9);
    /// });
    /// ```
    #[cfg(feature = "__commons_parallel")]
    pub fn par_row_iter_mut(
        &mut self,
    ) -> impl IndexedParallelIterator<Item = GgswLevelRow<&mut [<Self as AsRefTensor>::Element]>>
    where
        Self: AsMutTensor,
        <Self as AsMutTensor>::Element: Send + Sync,
    {
        let chunks_size = self.poly_size.0 * self.glwe_size.0;
        let poly_size = self.poly_size;
        let level = self.level;
        self.as_mut_tensor()
            .par_subtensor_iter_mut(chunks_size)
            .map(move |tens| GgswLevelRow::from_container(tens.into_container(), poly_size, level))
    }
}

/// A row of a GGSW level matrix.
pub struct GgswLevelRow<Cont> {
    tensor: Tensor<Cont>,
    poly_size: PolynomialSize,
    level: DecompositionLevel,
}

tensor_traits!(GgswLevelRow);

impl<Cont> GgswLevelRow<Cont> {
    /// Creates an Rgsw level row from an arbitrary container.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::ggsw::GgswLevelRow;
    /// use tfhe::core_crypto::commons::math::decomposition::DecompositionLevel;
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialSize};
    /// let level_row = GgswLevelRow::from_container(
    ///     vec![0 as u8; 10 * 7],
    ///     PolynomialSize(10),
    ///     DecompositionLevel(1),
    /// );
    /// assert_eq!(level_row.polynomial_size(), PolynomialSize(10));
    /// assert_eq!(level_row.glwe_size(), GlweSize(7));
    /// assert_eq!(level_row.decomposition_level(), DecompositionLevel(1));
    /// ```
    pub fn from_container(cont: Cont, poly_size: PolynomialSize, level: DecompositionLevel) -> Self
    where
        Cont: AsRefSlice,
    {
        let tensor = Tensor::from_container(cont);
        ck_dim_div!(tensor.len() => poly_size.0);
        GgswLevelRow {
            tensor,
            poly_size,
            level,
        }
    }

    /// Returns the size of the glwe ciphertext composing this level row.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::ggsw::GgswLevelRow;
    /// use tfhe::core_crypto::commons::math::decomposition::DecompositionLevel;
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialSize};
    /// let level_row = GgswLevelRow::from_container(
    ///     vec![0 as u8; 10 * 7],
    ///     PolynomialSize(10),
    ///     DecompositionLevel(1),
    /// );
    /// assert_eq!(level_row.glwe_size(), GlweSize(7));
    /// ```
    pub fn glwe_size(&self) -> GlweSize
    where
        Self: AsRefTensor,
    {
        ck_dim_div!(self.as_tensor().len() => self.poly_size.0);
        GlweSize(self.as_tensor().len() / self.poly_size.0)
    }

    /// Returns the index of the level corresponding to this row.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::ggsw::GgswLevelRow;
    /// use tfhe::core_crypto::commons::math::decomposition::DecompositionLevel;
    /// use tfhe::core_crypto::prelude::PolynomialSize;
    /// let level_row = GgswLevelRow::from_container(
    ///     vec![0 as u8; 10 * 7],
    ///     PolynomialSize(10),
    ///     DecompositionLevel(1),
    /// );
    /// assert_eq!(level_row.decomposition_level(), DecompositionLevel(1));
    /// ```
    pub fn decomposition_level(&self) -> DecompositionLevel {
        self.level
    }

    /// Returns the size of the polynomials used in the row.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::ggsw::GgswLevelRow;
    /// use tfhe::core_crypto::commons::math::decomposition::DecompositionLevel;
    /// use tfhe::core_crypto::prelude::PolynomialSize;
    /// let level_row = GgswLevelRow::from_container(
    ///     vec![0 as u8; 10 * 7],
    ///     PolynomialSize(10),
    ///     DecompositionLevel(1),
    /// );
    /// assert_eq!(level_row.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.poly_size
    }

    /// Consumes the row and returns its container wrapped into an `GlweCiphertext`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::ggsw::GgswLevelRow;
    /// use tfhe::core_crypto::commons::math::decomposition::DecompositionLevel;
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialSize};
    /// let level_row = GgswLevelRow::from_container(
    ///     vec![0 as u8; 10 * 7],
    ///     PolynomialSize(10),
    ///     DecompositionLevel(1),
    /// );
    /// let glwe = level_row.into_glwe();
    /// assert_eq!(glwe.polynomial_size(), PolynomialSize(10));
    /// assert_eq!(glwe.size(), GlweSize(7));
    /// ```
    pub fn into_glwe(self) -> GlweCiphertext<Cont> {
        GlweCiphertext {
            tensor: self.tensor,
            poly_size: self.poly_size,
        }
    }
}
