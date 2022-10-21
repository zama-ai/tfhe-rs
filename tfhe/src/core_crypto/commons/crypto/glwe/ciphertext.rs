use super::{GlweBody, GlweMask};
use crate::core_crypto::commons::crypto::encoding::{Plaintext, PlaintextList};
use crate::core_crypto::commons::crypto::lwe::LweCiphertext;
use crate::core_crypto::commons::math::polynomial::PolynomialList;
use crate::core_crypto::commons::math::tensor::{
    tensor_traits, AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor, Container, Tensor,
};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::Numeric;
use crate::core_crypto::prelude::{GlweDimension, GlweSize, MonomialDegree, PolynomialSize};
#[cfg(feature = "__commons_serialization")]
use serde::{Deserialize, Serialize};

/// An GLWE ciphertext.
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlweCiphertext<Cont> {
    pub(crate) tensor: Tensor<Cont>,
    pub(crate) poly_size: PolynomialSize,
}

tensor_traits!(GlweCiphertext);

impl<Scalar> GlweCiphertext<Vec<Scalar>> {
    /// Allocates a new GLWE ciphertext, whose body and masks coefficients are all `value`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweCiphertext;
    /// use tfhe::core_crypto::prelude::{GlweDimension, GlweSize, PolynomialSize};
    /// let glwe_ciphertext = GlweCiphertext::allocate(0 as u8, PolynomialSize(10), GlweSize(100));
    /// assert_eq!(glwe_ciphertext.polynomial_size(), PolynomialSize(10));
    /// assert_eq!(glwe_ciphertext.mask_size(), GlweDimension(99));
    /// assert_eq!(glwe_ciphertext.size(), GlweSize(100));
    /// ```
    pub fn allocate(
        value: Scalar,
        poly_size: PolynomialSize,
        size: GlweSize,
    ) -> GlweCiphertext<Vec<Scalar>>
    where
        GlweCiphertext<Vec<Scalar>>: AsMutTensor,
        Scalar: Copy,
    {
        GlweCiphertext::from_container(vec![value; poly_size.0 * size.0], poly_size)
    }
}

impl<Scalar> GlweCiphertext<Vec<Scalar>>
where
    Scalar: Numeric,
{
    pub fn new_trivial_encryption<Cont>(
        glwe_size: GlweSize,
        plaintexts: &PlaintextList<Cont>,
    ) -> Self
    where
        PlaintextList<Cont>: AsRefTensor<Element = Scalar>,
    {
        let poly_size = PolynomialSize(plaintexts.count().0);
        let mut ciphertext = Self::allocate(Scalar::ZERO, poly_size, glwe_size);
        ciphertext.fill_with_trivial_encryption(plaintexts);
        ciphertext
    }
}

impl<Cont> GlweCiphertext<Cont> {
    /// Creates a new GLWE ciphertext from an existing container.
    ///
    /// # Note
    ///
    /// This method does not perform any transformation of the container data. Those are assumed to
    /// represent a valid glwe ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweCiphertext;
    /// use tfhe::core_crypto::prelude::{GlweDimension, GlweSize, PolynomialSize};
    /// let glwe = GlweCiphertext::from_container(vec![0 as u8; 1100], PolynomialSize(10));
    /// assert_eq!(glwe.polynomial_size(), PolynomialSize(10));
    /// assert_eq!(glwe.mask_size(), GlweDimension(109));
    /// assert_eq!(glwe.size(), GlweSize(110));
    /// ```
    pub fn from_container(cont: Cont, poly_size: PolynomialSize) -> GlweCiphertext<Cont> {
        GlweCiphertext {
            tensor: Tensor::from_container(cont),
            poly_size,
        }
    }

    pub fn as_view(&self) -> GlweCiphertext<&'_ [Cont::Element]>
    where
        Cont: Container,
    {
        GlweCiphertext {
            tensor: Tensor::from_container(self.tensor.as_container().as_ref()),
            poly_size: self.poly_size,
        }
    }

    pub fn as_mut_view(&mut self) -> GlweCiphertext<&'_ mut [Cont::Element]>
    where
        Cont: Container,
        Cont: AsMut<[Cont::Element]>,
    {
        GlweCiphertext {
            tensor: Tensor::from_container(self.tensor.as_mut_container().as_mut()),
            poly_size: self.poly_size,
        }
    }

    pub fn into_container(self) -> Cont {
        self.tensor.into_container()
    }

    /// Returns the size of the ciphertext, e.g. the number of masks + 1.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweCiphertext;
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialSize};
    /// let glwe = GlweCiphertext::allocate(0 as u8, PolynomialSize(10), GlweSize(100));
    /// assert_eq!(glwe.size(), GlweSize(100));
    /// ```
    pub fn size(&self) -> GlweSize
    where
        Self: AsRefTensor,
    {
        GlweSize(self.as_tensor().len() / self.poly_size.0)
    }

    /// Returns the number of masks of the ciphertext, e.g. its size - 1.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweCiphertext;
    /// use tfhe::core_crypto::prelude::{GlweDimension, GlweSize, PolynomialSize};
    /// let glwe = GlweCiphertext::allocate(0 as u8, PolynomialSize(10), GlweSize(100));
    /// assert_eq!(glwe.mask_size(), GlweDimension(99));
    /// ```
    pub fn mask_size(&self) -> GlweDimension
    where
        Self: AsRefTensor,
    {
        GlweDimension(self.size().0 - 1)
    }

    /// Returns the number of coefficients of the polynomials of the ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweCiphertext;
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialSize};
    /// let rlwe_ciphertext = GlweCiphertext::allocate(0 as u8, PolynomialSize(10), GlweSize(100));
    /// assert_eq!(rlwe_ciphertext.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.poly_size
    }

    /// Returns a borrowed [`GlweBody`] from the current ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweCiphertext;
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialSize};
    /// let rlwe_ciphertext = GlweCiphertext::allocate(0 as u8, PolynomialSize(10), GlweSize(100));
    /// let body = rlwe_ciphertext.get_body();
    /// assert_eq!(body.as_polynomial().polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn get_body(&self) -> GlweBody<&[<Self as AsRefTensor>::Element]>
    where
        Self: AsRefTensor,
    {
        GlweBody {
            tensor: self
                .as_tensor()
                .get_sub((self.mask_size().0 * self.polynomial_size().0)..),
        }
    }

    /// Returns a borrowed [`GlweMask`] from the current ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweCiphertext;
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialSize};
    /// let rlwe_ciphertext = GlweCiphertext::allocate(0 as u8, PolynomialSize(10), GlweSize(100));
    /// let mask = rlwe_ciphertext.get_mask();
    /// assert_eq!(mask.mask_element_iter().count(), 99);
    /// ```
    pub fn get_mask(&self) -> GlweMask<&[<Self as AsRefTensor>::Element]>
    where
        Self: AsRefTensor,
    {
        GlweMask {
            tensor: self
                .as_tensor()
                .get_sub(..(self.mask_size().0 * self.polynomial_size().0)),
            poly_size: self.poly_size,
        }
    }

    /// Returns a mutably borrowed [`GlweBody`] from the current ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweCiphertext;
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialSize};
    /// let mut glwe = GlweCiphertext::allocate(0 as u8, PolynomialSize(10), GlweSize(100));
    /// let mut body = glwe.get_mut_body();
    /// body.as_mut_tensor().fill_with_element(9);
    /// let body = glwe.get_body();
    /// assert!(body.as_tensor().iter().all(|a| *a == 9));
    /// ```
    pub fn get_mut_body(&mut self) -> GlweBody<&mut [<Self as AsRefTensor>::Element]>
    where
        Self: AsMutTensor,
    {
        let body_index = self.mask_size().0 * self.polynomial_size().0;
        GlweBody {
            tensor: self.as_mut_tensor().get_sub_mut(body_index..),
        }
    }

    /// Returns a mutably borrowed [`GlweMask`] from the current ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweCiphertext;
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialSize};
    /// let mut glwe = GlweCiphertext::allocate(0 as u8, PolynomialSize(10), GlweSize(100));
    /// let mut masks = glwe.get_mut_mask();
    /// for mut mask in masks.mask_element_iter_mut() {
    ///     mask.as_mut_tensor().fill_with_element(9);
    /// }
    /// assert_eq!(masks.mask_element_iter_mut().count(), 99);
    /// assert!(!glwe.as_tensor().iter().all(|a| *a == 9));
    /// ```
    pub fn get_mut_mask(&mut self) -> GlweMask<&mut [<Self as AsRefTensor>::Element]>
    where
        Self: AsMutTensor,
    {
        let body_index = self.mask_size().0 * self.polynomial_size().0;
        let poly_size = self.poly_size;
        GlweMask {
            tensor: self.as_mut_tensor().get_sub_mut(..body_index),
            poly_size,
        }
    }

    /// Returns borrowed [`GlweBody`] and [`GlweMask`] from the current ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweCiphertext;
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialSize};
    /// let mut glwe = GlweCiphertext::allocate(0 as u8, PolynomialSize(10), GlweSize(100));
    /// let (body, masks) = glwe.get_body_and_mask();
    /// assert_eq!(body.as_polynomial().polynomial_size(), PolynomialSize(10));
    /// assert_eq!(masks.mask_element_iter().count(), 99);
    /// ```
    #[allow(clippy::type_complexity)]
    pub fn get_body_and_mask(
        &self,
    ) -> (
        GlweBody<&[<Self as AsRefTensor>::Element]>,
        GlweMask<&[<Self as AsRefTensor>::Element]>,
    )
    where
        Self: AsRefTensor,
    {
        let index = self.mask_size().0 * self.polynomial_size().0;
        (
            GlweBody {
                tensor: self.as_tensor().get_sub(index..),
            },
            GlweMask {
                tensor: self.as_tensor().get_sub(..index),
                poly_size: self.poly_size,
            },
        )
    }

    /// Returns borrowed [`GlweBody`] and [`GlweMask`] from the current ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweCiphertext;
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialSize};
    /// let mut glwe = GlweCiphertext::allocate(0 as u8, PolynomialSize(10), GlweSize(100));
    /// let (mut body, mut masks) = glwe.get_mut_body_and_mask();
    /// body.as_mut_tensor().fill_with_element(9);
    /// for mut mask in masks.mask_element_iter_mut() {
    ///     mask.as_mut_tensor().fill_with_element(9);
    /// }
    /// assert_eq!(body.as_polynomial().polynomial_size(), PolynomialSize(10));
    /// assert!(glwe.as_tensor().iter().all(|a| *a == 9));
    /// ```
    #[allow(clippy::type_complexity)]
    pub fn get_mut_body_and_mask(
        &mut self,
    ) -> (
        GlweBody<&mut [<Self as AsRefTensor>::Element]>,
        GlweMask<&mut [<Self as AsRefTensor>::Element]>,
    )
    where
        Self: AsMutTensor,
    {
        let body_index = self.mask_size().0 * self.polynomial_size().0;
        let poly_size = self.poly_size;
        let (masks, body) = self.as_mut_tensor().as_mut_slice().split_at_mut(body_index);
        (
            GlweBody {
                tensor: Tensor::from_container(body),
            },
            GlweMask {
                tensor: Tensor::from_container(masks),
                poly_size,
            },
        )
    }

    /// Consumes the current ciphertext and turn it to a list of polynomial.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweCiphertext;
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialCount, PolynomialSize};
    /// let rlwe_ciphertext = GlweCiphertext::allocate(0 as u8, PolynomialSize(10), GlweSize(100));
    /// let poly_list = rlwe_ciphertext.into_polynomial_list();
    /// assert_eq!(poly_list.polynomial_count(), PolynomialCount(100));
    /// assert_eq!(poly_list.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn into_polynomial_list(self) -> PolynomialList<Cont> {
        PolynomialList {
            tensor: self.tensor,
            poly_size: self.poly_size,
        }
    }

    /// Returns a borrowed polynomial list from the current ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweCiphertext;
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialCount, PolynomialSize};
    /// let rlwe_ciphertext = GlweCiphertext::allocate(0 as u8, PolynomialSize(10), GlweSize(100));
    /// let poly_list = rlwe_ciphertext.as_polynomial_list();
    /// assert_eq!(poly_list.polynomial_count(), PolynomialCount(100));
    /// assert_eq!(poly_list.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn as_polynomial_list(&self) -> PolynomialList<&[<Self as AsRefTensor>::Element]>
    where
        Self: AsRefTensor,
    {
        PolynomialList {
            tensor: Tensor::from_container(self.as_tensor().as_slice()),
            poly_size: self.poly_size,
        }
    }

    /// Returns a mutably borrowed polynomial list from the current ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweCiphertext;
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use tfhe::core_crypto::prelude::{GlweSize, PolynomialSize};
    /// let mut glwe = GlweCiphertext::allocate(0 as u8, PolynomialSize(10), GlweSize(100));
    /// let mut poly_list = glwe.as_mut_polynomial_list();
    /// for mut poly in poly_list.polynomial_iter_mut() {
    ///     poly.as_mut_tensor().fill_with_element(9);
    /// }
    /// assert!(glwe.as_tensor().iter().all(|a| *a == 9));
    /// ```
    pub fn as_mut_polynomial_list(
        &mut self,
    ) -> PolynomialList<&mut [<Self as AsMutTensor>::Element]>
    where
        Self: AsMutTensor,
    {
        let poly_size = self.poly_size;
        PolynomialList {
            tensor: Tensor::from_container(self.as_mut_tensor().as_mut_slice()),
            poly_size,
        }
    }

    /// Fills an LWE ciphertext with the extraction of one coefficient of the current GLWE
    /// ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    /// use tfhe::core_crypto::commons::crypto::encoding::{Plaintext, PlaintextList};
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweCiphertext;
    /// use tfhe::core_crypto::commons::crypto::lwe::LweCiphertext;
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::GlweSecretKey;
    /// use tfhe::core_crypto::commons::math::polynomial::MonomialDegree;
    /// use tfhe::core_crypto::commons::math::tensor::AsRefTensor;
    /// use tfhe::core_crypto::prelude::{
    ///     GlweDimension, LogStandardDev, LweDimension, PolynomialSize,
    /// };
    ///
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut encryption_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
    /// let poly_size = PolynomialSize(4);
    /// let glwe_dim = GlweDimension(2);
    /// let glwe_secret_key =
    ///     GlweSecretKey::generate_binary(glwe_dim, poly_size, &mut secret_generator);
    /// let mut plaintext_list =
    ///     PlaintextList::from_container(vec![100000 as u32, 200000, 300000, 400000]);
    /// let mut glwe_ct = GlweCiphertext::allocate(0u32, poly_size, glwe_dim.to_glwe_size());
    /// let mut lwe_ct =
    ///     LweCiphertext::allocate(0u32, LweDimension(poly_size.0 * glwe_dim.0).to_lwe_size());
    /// glwe_secret_key.encrypt_glwe(
    ///     &mut glwe_ct,
    ///     &plaintext_list,
    ///     LogStandardDev(-60.),
    ///     &mut encryption_generator,
    /// );
    /// let lwe_secret_key = glwe_secret_key.into_lwe_secret_key();
    ///
    /// // Check for the first
    /// for i in 0..4 {
    ///     // We sample extract
    ///     glwe_ct.fill_lwe_with_sample_extraction(&mut lwe_ct, MonomialDegree(i));
    ///     // We decrypt
    ///     let mut output = Plaintext(0u32);
    ///     lwe_secret_key.decrypt_lwe(&mut output, &lwe_ct);
    ///     // We check that the decryption is correct
    ///     let plain = plaintext_list.as_tensor().get_element(i);
    ///     let d0 = output.0.wrapping_sub(*plain);
    ///     let d1 = plain.wrapping_sub(output.0);
    ///     let dist = std::cmp::min(d0, d1);
    ///     assert!(dist < 400);
    /// }
    /// ```
    pub fn fill_lwe_with_sample_extraction<OutputCont, Element>(
        &self,
        lwe: &mut LweCiphertext<OutputCont>,
        n_th: MonomialDegree,
    ) where
        Self: AsRefTensor<Element = Element>,
        LweCiphertext<OutputCont>: AsMutTensor<Element = Element>,
        Element: UnsignedTorus,
    {
        // We retrieve the bodies and masks of the two ciphertexts.
        let (lwe_body, mut lwe_mask) = lwe.get_mut_body_and_mask();
        let (glwe_body, glwe_mask) = self.get_body_and_mask();

        // We copy the body
        lwe_body.0 = *glwe_body
            .as_polynomial()
            .get_monomial(n_th)
            .get_coefficient();

        // We copy the mask (each polynomial is in the wrong order)
        lwe_mask
            .as_mut_tensor()
            .fill_with_copy(glwe_mask.as_tensor());

        // We compute the number of elements which must be
        // turned into their opposite
        let opposite_count = self.poly_size.0 - n_th.0 - 1;

        // We loop through the polynomials (as mut tensors)
        for mut lwe_mask_poly in lwe_mask
            .as_mut_tensor()
            .subtensor_iter_mut(self.poly_size.0)
        {
            // We reverse the polynomial
            lwe_mask_poly.reverse();
            // We compute the opposite of the proper coefficients
            lwe_mask_poly
                .get_sub_mut(0..opposite_count)
                .update_with_wrapping_neg();
            // We rotate the polynomial properly
            lwe_mask_poly.rotate_left(opposite_count);
        }
    }

    pub fn fill_with_trivial_encryption<PlaintextContainer, Scalar>(
        &mut self,
        plaintexts: &PlaintextList<PlaintextContainer>,
    ) where
        PlaintextList<PlaintextContainer>: AsRefTensor<Element = Scalar>,
        Self: AsMutTensor<Element = Scalar>,
        Scalar: Numeric,
    {
        debug_assert_eq!(plaintexts.count().0, self.poly_size.0);
        let (mut body, mut mask) = self.get_mut_body_and_mask();

        mask.as_mut_polynomial_list()
            .polynomial_iter_mut()
            .for_each(|mut polynomial| {
                polynomial
                    .coefficient_iter_mut()
                    .for_each(|mask_coeff| *mask_coeff = <Scalar as Numeric>::ZERO)
            });

        body.as_mut_polynomial()
            .coefficient_iter_mut()
            .zip(plaintexts.plaintext_iter())
            .for_each(
                |(body_coeff, plaintext): (&mut Scalar, &Plaintext<Scalar>)| {
                    *body_coeff = plaintext.0;
                },
            );
    }
}
