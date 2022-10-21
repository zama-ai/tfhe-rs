use super::LweCiphertext;
use crate::core_crypto::commons::crypto::encoding::{CleartextList, PlaintextList};
use crate::core_crypto::commons::math::tensor::{
    ck_dim_div, tensor_traits, AsMutTensor, AsRefSlice, AsRefTensor, Container, Tensor,
};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::utils::{zip, zip_args};
use crate::core_crypto::prelude::{CiphertextCount, CleartextCount, LweDimension, LweSize};
#[cfg(feature = "__commons_parallel")]
use rayon::{iter::IndexedParallelIterator, prelude::*};
#[cfg(feature = "__commons_serialization")]
use serde::{Deserialize, Serialize};

/// A list of ciphertext encoded with the LWE scheme.
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweList<Cont> {
    pub(crate) tensor: Tensor<Cont>,
    pub(crate) lwe_size: LweSize,
}

tensor_traits!(LweList);

impl<Scalar> LweList<Vec<Scalar>>
where
    Scalar: Copy,
{
    /// Allocates a list of lwe ciphertext whose all masks and bodies have the value `value`.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::lwe::LweList;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{CiphertextCount, LweSize};
    /// let list = LweList::allocate(0 as u8, LweSize(10), CiphertextCount(20));
    /// assert_eq!(list.count(), CiphertextCount(20));
    /// assert_eq!(list.lwe_size(), LweSize(10));
    /// ```
    pub fn allocate(value: Scalar, lwe_size: LweSize, lwe_count: CiphertextCount) -> Self {
        LweList {
            tensor: Tensor::from_container(vec![value; lwe_size.0 * lwe_count.0]),
            lwe_size,
        }
    }
}

impl<Scalar> LweList<Vec<Scalar>>
where
    Scalar: UnsignedTorus,
{
    /// Creates a new ciphertext containing the trivial encryption of the plain text
    ///
    /// `Trivial` means that the LWE masks consist of zeros only.
    ///
    /// # Example
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::crypto::encoding::*;
    /// use tfhe::core_crypto::commons::crypto::lwe::*;
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{
    ///     CiphertextCount, CleartextCount, LogStandardDev, LweDimension, LweSize, PlaintextCount,
    /// };
    ///
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let secret_key = LweSecretKey::generate_binary(LweDimension(256), &mut secret_generator);
    ///
    /// let clear_values = CleartextList::allocate(2. as f32, CleartextCount(100));
    /// let mut plain_values = PlaintextList::allocate(0u32, PlaintextCount(100));
    /// let encoder = RealEncoder {
    ///     offset: 0. as f32,
    ///     delta: 10.,
    /// };
    ///
    /// encoder.encode_list(&mut plain_values, &clear_values);
    /// let mut encrypted_values =
    ///     LweList::new_trivial_encryption(secret_key.key_size().to_lwe_size(), &plain_values);
    ///
    /// for ciphertext in encrypted_values.ciphertext_iter() {
    ///     for mask in ciphertext.get_mask().mask_element_iter() {
    ///         assert_eq!(*mask, 0);
    ///     }
    /// }
    ///
    /// let mut decrypted_values = PlaintextList::allocate(0u32, PlaintextCount(100));
    /// secret_key.decrypt_lwe_list(&mut decrypted_values, &encrypted_values);
    /// let mut decoded_values = CleartextList::allocate(0. as f32, CleartextCount(100));
    /// encoder.decode_list(&mut decoded_values, &decrypted_values);
    /// for (clear, decoded) in clear_values
    ///     .cleartext_iter()
    ///     .zip(decoded_values.cleartext_iter())
    /// {
    ///     assert!((clear.0 - decoded.0).abs() < 0.1);
    /// }
    /// ```
    pub fn new_trivial_encryption<PlaintextContainer>(
        lwe_size: LweSize,
        plaintexts: &PlaintextList<PlaintextContainer>,
    ) -> Self
    where
        PlaintextList<PlaintextContainer>: AsRefTensor<Element = Scalar>,
    {
        let mut ciphertexts = Self::allocate(
            Scalar::ZERO,
            lwe_size,
            CiphertextCount(plaintexts.count().0),
        );
        ciphertexts.fill_with_trivial_encryption(plaintexts);
        ciphertexts
    }
}

impl<Cont> LweList<Cont> {
    /// Creates a list from a container and a lwe size.
    ///
    /// # Example:
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::lwe::LweList;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{CiphertextCount, LweSize};
    /// let list = LweList::from_container(vec![0 as u8; 200], LweSize(10));
    /// assert_eq!(list.count(), CiphertextCount(20));
    /// assert_eq!(list.lwe_size(), LweSize(10));
    /// ```
    pub fn from_container(cont: Cont, lwe_size: LweSize) -> Self
    where
        Cont: AsRefSlice,
    {
        ck_dim_div!(cont.as_slice().len() => lwe_size.0);
        let tensor = Tensor::from_container(cont);
        LweList { tensor, lwe_size }
    }

    pub fn into_container(self) -> Cont {
        self.tensor.into_container()
    }

    pub fn as_view(&self) -> LweList<&'_ [Cont::Element]>
    where
        Cont: Container,
    {
        LweList {
            tensor: Tensor::from_container(self.tensor.as_container().as_ref()),
            lwe_size: self.lwe_size,
        }
    }

    pub fn as_mut_view(&mut self) -> LweList<&'_ mut [Cont::Element]>
    where
        Cont: Container,
        Cont: AsMut<[Cont::Element]>,
    {
        LweList {
            tensor: Tensor::from_container(self.tensor.as_mut_container().as_mut()),
            lwe_size: self.lwe_size,
        }
    }

    /// Returns the number of ciphertexts in the list.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::lwe::LweList;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{CiphertextCount, LweSize};
    /// let list = LweList::from_container(vec![0 as u8; 200], LweSize(10));
    /// assert_eq!(list.count(), CiphertextCount(20));
    /// ```
    pub fn count(&self) -> CiphertextCount
    where
        Self: AsRefTensor,
    {
        ck_dim_div!(self.as_tensor().len() => self.lwe_size.0);
        CiphertextCount(self.as_tensor().len() / self.lwe_size.0)
    }

    /// Returns the size of the ciphertexts in the list.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::lwe::LweList;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::LweSize;
    /// let list = LweList::from_container(vec![0 as u8; 200], LweSize(10));
    /// assert_eq!(list.lwe_size(), LweSize(10));
    /// ```
    pub fn lwe_size(&self) -> LweSize
    where
        Self: AsRefTensor,
    {
        self.lwe_size
    }

    /// Returns the number of masks of the ciphertexts in the list.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::lwe::LweList;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{LweDimension, LweSize};
    /// let list = LweList::from_container(vec![0 as u8; 200], LweSize(10));
    /// assert_eq!(list.mask_size(), LweDimension(9));
    /// ```
    pub fn mask_size(&self) -> LweDimension
    where
        Self: AsRefTensor,
    {
        LweDimension(self.lwe_size.0 - 1)
    }

    /// Returns an iterator over ciphertexts borrowed from the list.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::lwe::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::LweSize;
    /// let list = LweList::from_container(vec![0 as u8; 200], LweSize(10));
    /// for ciphertext in list.ciphertext_iter() {
    ///     let (body, masks) = ciphertext.get_body_and_mask();
    ///     assert_eq!(body, &LweBody(0));
    ///     assert_eq!(
    ///         masks,
    ///         LweMask::from_container(&[0 as u8, 0, 0, 0, 0, 0, 0, 0, 0][..])
    ///     );
    /// }
    /// assert_eq!(list.ciphertext_iter().count(), 20);
    /// ```
    pub fn ciphertext_iter(
        &self,
    ) -> impl DoubleEndedIterator<Item = LweCiphertext<&[<Self as AsRefTensor>::Element]>>
    where
        Self: AsRefTensor,
    {
        ck_dim_div!(self.as_tensor().len() => self.lwe_size.0);
        self.as_tensor()
            .subtensor_iter(self.lwe_size.0)
            .map(|sub| LweCiphertext::from_container(sub.into_container()))
    }

    #[cfg(feature = "__commons_parallel")]
    pub fn par_ciphertext_iter(
        &mut self,
    ) -> impl IndexedParallelIterator<Item = LweCiphertext<&[<Self as AsRefTensor>::Element]>>
    where
        Self: AsRefTensor,
        <Self as AsRefTensor>::Element: Sync,
    {
        ck_dim_div!(self.as_tensor().len() => self.lwe_size.0);
        let lwe_size = self.lwe_size.0;
        self.as_tensor()
            .par_subtensor_iter(lwe_size)
            .map(|sub| LweCiphertext::from_container(sub.into_container()))
    }

    /// Returns an iterator over ciphers mutably borrowed from the list.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::lwe::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::LweSize;
    /// let mut list = LweList::from_container(vec![0 as u8; 200], LweSize(10));
    /// for mut ciphertext in list.ciphertext_iter_mut() {
    ///     let body = ciphertext.get_mut_body();
    ///     *body = LweBody(2);
    /// }
    /// for ciphertext in list.ciphertext_iter() {
    ///     let body = ciphertext.get_body();
    ///     assert_eq!(body, &LweBody(2));
    /// }
    /// assert_eq!(list.ciphertext_iter_mut().count(), 20);
    /// ```
    pub fn ciphertext_iter_mut(
        &mut self,
    ) -> impl DoubleEndedIterator<Item = LweCiphertext<&mut [<Self as AsMutTensor>::Element]>>
    where
        Self: AsMutTensor,
    {
        ck_dim_div!(self.as_tensor().len() => self.lwe_size.0);
        let lwe_size = self.lwe_size.0;
        self.as_mut_tensor()
            .subtensor_iter_mut(lwe_size)
            .map(|sub| LweCiphertext::from_container(sub.into_container()))
    }

    #[cfg(feature = "__commons_parallel")]
    pub fn par_ciphertext_iter_mut(
        &mut self,
    ) -> impl IndexedParallelIterator<Item = LweCiphertext<&mut [<Self as AsMutTensor>::Element]>>
    where
        Self: AsMutTensor,
        <Self as AsMutTensor>::Element: Sync + Send,
    {
        ck_dim_div!(self.as_tensor().len() => self.lwe_size.0);
        let lwe_size = self.lwe_size.0;
        self.as_mut_tensor()
            .par_subtensor_iter_mut(lwe_size)
            .map(|sub| LweCiphertext::from_container(sub.into_container()))
    }

    /// Returns an iterator over sub lists borrowed from the list.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::lwe::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{CiphertextCount, LweSize};
    /// let list = LweList::from_container(vec![0 as u8; 200], LweSize(10));
    /// for sublist in list.sublist_iter(CiphertextCount(5)) {
    ///     assert_eq!(sublist.count(), CiphertextCount(5));
    ///     for ciphertext in sublist.ciphertext_iter() {
    ///         let (body, masks) = ciphertext.get_body_and_mask();
    ///         assert_eq!(body, &LweBody(0));
    ///         assert_eq!(
    ///             masks,
    ///             LweMask::from_container(&[0 as u8, 0, 0, 0, 0, 0, 0, 0, 0][..])
    ///         );
    ///     }
    /// }
    /// assert_eq!(list.sublist_iter(CiphertextCount(5)).count(), 4);
    /// ```
    pub fn sublist_iter(
        &self,
        sub_len: CiphertextCount,
    ) -> impl Iterator<Item = LweList<&[<Self as AsRefTensor>::Element]>>
    where
        Self: AsRefTensor,
    {
        ck_dim_div!(self.as_tensor().len() => self.lwe_size.0, sub_len.0);
        let lwe_size = self.lwe_size;
        self.as_tensor()
            .subtensor_iter(self.lwe_size.0 * sub_len.0)
            .map(move |sub| LweList::from_container(sub.into_container(), lwe_size))
    }

    /// Returns an iterator over sub lists borrowed from the list.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::lwe::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{CiphertextCount, LweSize};
    /// let mut list = LweList::from_container(vec![0 as u8; 200], LweSize(10));
    /// for mut sublist in list.sublist_iter_mut(CiphertextCount(5)) {
    ///     assert_eq!(sublist.count(), CiphertextCount(5));
    ///     for mut ciphertext in sublist.ciphertext_iter_mut() {
    ///         let (body, mut masks) = ciphertext.get_mut_body_and_mask();
    ///         *body = LweBody(9);
    ///         for mut mask in masks.mask_element_iter_mut() {
    ///             *mask = 8;
    ///         }
    ///     }
    /// }
    /// for ciphertext in list.ciphertext_iter() {
    ///     let (body, masks) = ciphertext.get_body_and_mask();
    ///     assert_eq!(body, &LweBody(9));
    ///     assert_eq!(
    ///         masks,
    ///         LweMask::from_container(&[8 as u8, 8, 8, 8, 8, 8, 8, 8, 8][..])
    ///     );
    /// }
    /// assert_eq!(list.sublist_iter_mut(CiphertextCount(5)).count(), 4);
    /// ```
    pub fn sublist_iter_mut(
        &mut self,
        sub_len: CiphertextCount,
    ) -> impl Iterator<Item = LweList<&mut [<Self as AsMutTensor>::Element]>>
    where
        Self: AsMutTensor,
    {
        ck_dim_div!(self.as_tensor().len() => self.lwe_size.0, sub_len.0);
        let chunks_size = self.lwe_size.0 * sub_len.0;
        let size = self.lwe_size;
        self.as_mut_tensor()
            .subtensor_iter_mut(chunks_size)
            .map(move |sub| LweList::from_container(sub.into_container(), size))
    }

    /// Fills each ciphertexts of the list with the result of the multisum of a subpart of the
    /// `input_list` ciphers, with a subset of the `weights_list` values, and one value of
    /// `biases_list`.
    ///
    /// Said differently, this function fills `self` with:
    /// $$
    /// bias\[i\] + \sum\_j input\_list\[i\]\[j\] * weights\[i\]\[j\]
    /// $$
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    /// use tfhe::core_crypto::commons::crypto::encoding::*;
    /// use tfhe::core_crypto::commons::crypto::lwe::*;
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::commons::math::tensor::AsRefTensor;
    /// use tfhe::core_crypto::prelude::{LogStandardDev, LweDimension, LweSize};
    ///
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut encryption_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
    ///
    /// let secret_key = LweSecretKey::generate_binary(LweDimension(4), &mut secret_generator);
    /// let parameters = LogStandardDev::from_log_standard_dev(-60.);
    /// let encoder = RealEncoder {
    ///     offset: 0. as f32,
    ///     delta: 200.,
    /// };
    ///
    /// let clear_values = CleartextList::from_container(vec![1f32, 2., 3., 4., 5., 6.]);
    /// let mut plain_values = PlaintextList::from_container(vec![0u32; 6]);
    /// encoder.encode_list(&mut plain_values, &clear_values);
    /// let mut cipher_values = LweList::from_container(vec![0. as u32; 5 * 6], LweSize(5));
    /// secret_key.encrypt_lwe_list(
    ///     &mut cipher_values,
    ///     &plain_values,
    ///     parameters,
    ///     &mut encryption_generator,
    /// );
    ///
    /// let mut output = LweList::from_container(vec![0u32; 5 * 2], LweSize(5));
    /// let weights = CleartextList::from_container(vec![7, 8, 9, 10, 11, 12]);
    /// let biases = PlaintextList::from_container(vec![
    ///     encoder.encode(Cleartext(13.)).0,
    ///     encoder.encode(Cleartext(14.)).0,
    /// ]);
    ///
    /// output.fill_with_multisums_with_biases(&cipher_values, &weights, &biases);
    ///
    /// let mut decrypted = PlaintextList::from_container(vec![0u32; 2]);
    /// secret_key.decrypt_lwe_list(&mut decrypted, &output);
    /// let mut decoded = CleartextList::from_container(vec![0f32; 2]);
    /// encoder.decode_list(&mut decoded, &decrypted);
    /// assert!((decoded.as_tensor().first() - 63.).abs() < 0.3);
    /// assert!((decoded.as_tensor().last() - 181.).abs() < 0.3);
    /// ```
    pub fn fill_with_multisums_with_biases<Scalar, InputCont, WeightCont, BiasesCont>(
        &mut self,
        input_list: &LweList<InputCont>,
        weights_list: &CleartextList<WeightCont>,
        biases_list: &PlaintextList<BiasesCont>,
    ) where
        Self: AsMutTensor<Element = Scalar>,
        LweList<InputCont>: AsRefTensor<Element = Scalar>,
        CleartextList<WeightCont>: AsRefTensor<Element = Scalar>,
        PlaintextList<BiasesCont>: AsRefTensor<Element = Scalar>,
        for<'a> CleartextList<&'a [Scalar]>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
    {
        ck_dim_div!(input_list.count().0 => weights_list.count().0, biases_list.count().0);
        ck_dim_div!(input_list.count().0 => self.count().0);
        let count = input_list.count().0 / self.count().0;
        for zip_args!(mut output, input, weights, bias) in zip!(
            self.ciphertext_iter_mut(),
            input_list.sublist_iter(CiphertextCount(count)),
            weights_list.sublist_iter(CleartextCount(count)),
            biases_list.plaintext_iter()
        ) {
            output.fill_with_multisum_with_bias(&input, &weights, bias);
        }
    }

    pub fn fill_with_trivial_encryption<InputCont, Scalar>(
        &mut self,
        encoded: &PlaintextList<InputCont>,
    ) where
        Self: AsMutTensor<Element = Scalar>,
        PlaintextList<InputCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
    {
        debug_assert!(
            self.count().0 == encoded.count().0,
            "Lwe cipher list size and encoded list size are not compatible"
        );
        for (mut cipher, plaintext) in self.ciphertext_iter_mut().zip(encoded.plaintext_iter()) {
            cipher.fill_with_trivial_encryption(plaintext);
        }
    }
}
