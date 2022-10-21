use super::LweList;
use crate::core_crypto::commons::crypto::encoding::{Cleartext, CleartextList, Plaintext};
use crate::core_crypto::commons::crypto::glwe::GlweCiphertext;
use crate::core_crypto::commons::crypto::secret::LweSecretKey;
use crate::core_crypto::commons::math::tensor::{
    tensor_traits, AsMutTensor, AsRefTensor, Container, Tensor,
};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::{Numeric, UnsignedInteger};
use crate::core_crypto::prelude::{KeyKind, LweDimension, LweSize, MonomialDegree};
#[cfg(feature = "__commons_serialization")]
use serde::{Deserialize, Serialize};

/// A ciphertext encrypted using the LWE scheme.
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LweCiphertext<Cont> {
    pub(crate) tensor: Tensor<Cont>,
}

tensor_traits!(LweCiphertext);

impl<Scalar> LweCiphertext<Vec<Scalar>>
where
    Scalar: Copy,
{
    /// Allocates a new ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::lwe::LweCiphertext;
    /// use tfhe::core_crypto::prelude::{LweDimension, LweSize};
    /// let ct = LweCiphertext::allocate(0 as u8, LweSize(4));
    /// assert_eq!(ct.lwe_size(), LweSize(4));
    /// assert_eq!(ct.get_mask().mask_size(), LweDimension(3));
    /// ```
    pub fn allocate(value: Scalar, size: LweSize) -> Self {
        LweCiphertext {
            tensor: Tensor::from_container(vec![value; size.0]),
        }
    }
}

impl<Scalar> LweCiphertext<Vec<Scalar>>
where
    Scalar: Numeric,
{
    /// Creates a new ciphertext containing the trivial encryption of the plain text
    ///
    /// `Trivial` means tha the LWE mask consists of zeros only.
    ///
    /// # Example
    ///
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
    /// use tfhe::core_crypto::prelude::{LogStandardDev, LweDimension, LweSize};
    ///
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let secret_key = LweSecretKey::generate_binary(LweDimension(256), &mut secret_generator);
    ///
    /// let encoder = RealEncoder {
    ///     offset: 0. as f32,
    ///     delta: 10.,
    /// };
    /// let clear = Cleartext(2. as f32);
    /// let plain: Plaintext<u32> = encoder.encode(clear);
    ///
    /// let mut encrypted =
    ///     LweCiphertext::new_trivial_encryption(secret_key.key_size().to_lwe_size(), &plain);
    ///
    /// let mut decrypted = Plaintext(0u32);
    /// secret_key.decrypt_lwe(&mut decrypted, &encrypted);
    /// let decoded = encoder.decode(decrypted);
    ///
    /// assert!((decoded.0 - clear.0).abs() < 0.1);
    /// ```
    pub fn new_trivial_encryption(lwe_size: LweSize, plaintext: &Plaintext<Scalar>) -> Self {
        let mut ciphertext = Self::allocate(Scalar::ZERO, lwe_size);
        ciphertext.fill_with_trivial_encryption(plaintext);
        ciphertext
    }
}

impl<Cont> LweCiphertext<Cont> {
    /// Creates a ciphertext from a container of values.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::lwe::LweCiphertext;
    /// use tfhe::core_crypto::prelude::{LweDimension, LweSize};
    /// let vector = vec![0 as u8; 10];
    /// let ct = LweCiphertext::from_container(vector.as_slice());
    /// assert_eq!(ct.lwe_size(), LweSize(10));
    /// assert_eq!(ct.get_mask().mask_size(), LweDimension(9));
    /// ```
    pub fn from_container(cont: Cont) -> LweCiphertext<Cont> {
        let tensor = Tensor::from_container(cont);
        LweCiphertext { tensor }
    }

    pub fn into_container(self) -> Cont {
        self.tensor.into_container()
    }

    pub fn as_view(&self) -> LweCiphertext<&'_ [Cont::Element]>
    where
        Cont: Container,
    {
        LweCiphertext::from_container(self.tensor.as_container().as_ref())
    }

    pub fn as_mut_view(&mut self) -> LweCiphertext<&'_ mut [Cont::Element]>
    where
        Cont: Container,
        Cont: AsMut<[Cont::Element]>,
    {
        LweCiphertext::from_container(self.tensor.as_mut_container().as_mut())
    }

    /// Returns the size of the cipher, e.g. the size of the mask + 1 for the body.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::lwe::LweCiphertext;
    /// use tfhe::core_crypto::prelude::LweSize;
    /// let ct = LweCiphertext::allocate(0 as u8, LweSize(4));
    /// assert_eq!(ct.lwe_size(), LweSize(4));
    /// ```
    pub fn lwe_size(&self) -> LweSize
    where
        Self: AsRefTensor,
    {
        LweSize(self.as_tensor().len())
    }

    /// Returns the body of the ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::lwe::{LweBody, LweCiphertext};
    /// let ciphertext = LweCiphertext::from_container(vec![0 as u8; 10]);
    /// let body = ciphertext.get_body();
    /// assert_eq!(body, &LweBody(0 as u8));
    /// ```
    pub fn get_body<Scalar>(&self) -> &LweBody<Scalar>
    where
        Self: AsRefTensor<Element = Scalar>,
    {
        unsafe { &*{ self.as_tensor().last() as *const Scalar as *const LweBody<Scalar> } }
    }

    /// Returns the mask of the ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::lwe::LweCiphertext;
    /// use tfhe::core_crypto::prelude::LweDimension;
    /// let ciphertext = LweCiphertext::from_container(vec![0 as u8; 10]);
    /// let mask = ciphertext.get_mask();
    /// assert_eq!(mask.mask_size(), LweDimension(9));
    /// ```
    pub fn get_mask<Scalar>(&self) -> LweMask<&[Scalar]>
    where
        Self: AsRefTensor<Element = Scalar>,
    {
        let (_, mask) = self.as_tensor().split_last();
        LweMask { tensor: mask }
    }

    /// Returns the body and the mask of the ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::lwe::{LweBody, LweCiphertext};
    /// use tfhe::core_crypto::prelude::LweDimension;
    /// let ciphertext = LweCiphertext::from_container(vec![0 as u8; 10]);
    /// let (body, mask) = ciphertext.get_body_and_mask();
    /// assert_eq!(body, &LweBody(0));
    /// assert_eq!(mask.mask_size(), LweDimension(9));
    /// ```
    pub fn get_body_and_mask<Scalar>(&self) -> (&LweBody<Scalar>, LweMask<&[Scalar]>)
    where
        Self: AsRefTensor<Element = Scalar>,
    {
        let (body, mask) = self.as_tensor().split_last();
        let body = unsafe { &*{ body as *const Scalar as *const LweBody<Scalar> } };
        (body, LweMask { tensor: mask })
    }

    /// Returns the mutable body of the ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::lwe::{LweBody, LweCiphertext};
    /// let mut ciphertext = LweCiphertext::from_container(vec![0 as u8; 10]);
    /// let mut body = ciphertext.get_mut_body();
    /// *body = LweBody(8);
    /// let body = ciphertext.get_body();
    /// assert_eq!(body, &LweBody(8 as u8));
    /// ```
    pub fn get_mut_body<Scalar>(&mut self) -> &mut LweBody<Scalar>
    where
        Self: AsMutTensor<Element = Scalar>,
    {
        unsafe { &mut *{ self.as_mut_tensor().last_mut() as *mut Scalar as *mut LweBody<Scalar> } }
    }

    /// Returns the mutable mask of the ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::lwe::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// let mut ciphertext = LweCiphertext::from_container(vec![0 as u8; 10]);
    /// let mut mask = ciphertext.get_mut_mask();
    /// for mut elt in mask.mask_element_iter_mut() {
    ///     *elt = 8;
    /// }
    /// let mask = ciphertext.get_mask();
    /// for elt in mask.mask_element_iter() {
    ///     assert_eq!(*elt, 8);
    /// }
    /// assert_eq!(mask.mask_element_iter().count(), 9);
    /// ```
    pub fn get_mut_mask<Scalar>(&mut self) -> LweMask<&mut [Scalar]>
    where
        Self: AsMutTensor<Element = Scalar>,
    {
        let (_, masks) = self.as_mut_tensor().split_last_mut();
        LweMask { tensor: masks }
    }

    /// Returns the mutable body and mask of the ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::lwe::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::LweDimension;
    /// let mut ciphertext = LweCiphertext::from_container(vec![0 as u8; 10]);
    /// let (body, mask) = ciphertext.get_mut_body_and_mask();
    /// assert_eq!(body, &mut LweBody(0));
    /// assert_eq!(mask.mask_size(), LweDimension(9));
    /// ```
    pub fn get_mut_body_and_mask<Scalar>(
        &mut self,
    ) -> (&mut LweBody<Scalar>, LweMask<&mut [Scalar]>)
    where
        Self: AsMutTensor<Element = Scalar>,
    {
        let (body, masks) = self.as_mut_tensor().split_last_mut();
        let body = unsafe { &mut *{ body as *mut Scalar as *mut LweBody<Scalar> } };
        (body, LweMask { tensor: masks })
    }

    /// Fills the ciphertext with the result of the multiplication of the `input` ciphertext by the
    /// `scalar` cleartext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    /// use tfhe::core_crypto::commons::crypto::encoding::*;
    /// use tfhe::core_crypto::commons::crypto::lwe::*;
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::LweSecretKey;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{LogStandardDev, LweDimension};
    ///
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut encryption_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
    ///
    /// let secret_key = LweSecretKey::generate_binary(LweDimension(256), &mut secret_generator);
    /// let noise = LogStandardDev::from_log_standard_dev(-15.);
    /// let encoder = RealEncoder {
    ///     offset: 0. as f32,
    ///     delta: 10.,
    /// };
    ///
    /// let cleartext = Cleartext(2. as f32);
    /// let plaintext: Plaintext<u32> = encoder.encode(cleartext);
    /// let mut ciphertext = LweCiphertext::from_container(vec![0. as u32; 257]);
    /// secret_key.encrypt_lwe(
    ///     &mut ciphertext,
    ///     &plaintext,
    ///     noise,
    ///     &mut encryption_generator,
    /// );
    ///
    /// let mut processed = LweCiphertext::from_container(vec![0 as u32; 257]);
    /// processed.fill_with_scalar_mul(&ciphertext, &Cleartext(4));
    ///
    /// let mut decrypted = Plaintext(0 as u32);
    /// secret_key.decrypt_lwe(&mut decrypted, &processed);
    /// let decoded = encoder.decode(decrypted);
    /// assert!((decoded.0 - (cleartext.0 * 4.)).abs() < 0.2);
    /// ```
    pub fn fill_with_scalar_mul<Scalar, InputCont>(
        &mut self,
        input: &LweCiphertext<InputCont>,
        scalar: &Cleartext<Scalar>,
    ) where
        Self: AsMutTensor<Element = Scalar>,
        LweCiphertext<InputCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedInteger,
    {
        self.as_mut_tensor()
            .fill_with_one(input.as_tensor(), |o| o.wrapping_mul(scalar.0));
    }

    /// Fills the ciphertext with the result of the multisum of the `input_list` with the
    /// `weights` values, and adds a bias.
    ///
    /// Said differently, this function fills `self` with:
    /// $$
    /// bias + \sum\_i input\_list\[i\] * weights\[i\]
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
    /// use tfhe::core_crypto::commons::crypto::secret::LweSecretKey;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{LogStandardDev, LweDimension, LweSize};
    ///
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut encryption_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
    ///
    /// // Insecure parameters for a toy example
    /// let secret_key = LweSecretKey::generate_binary(LweDimension(4), &mut secret_generator);
    /// let noise = LogStandardDev::from_log_standard_dev(-60.);
    /// let encoder = RealEncoder {
    ///     offset: 0. as f32,
    ///     delta: 100.,
    /// };
    ///
    /// let clear_values = CleartextList::from_container(vec![1. as f32, 2., 3.]);
    /// let mut plain_values = PlaintextList::from_container(vec![0 as u32; 3]);
    /// encoder.encode_list(&mut plain_values, &clear_values);
    /// let mut ciphertext_values = LweList::from_container(vec![0. as u32; 5 * 3], LweSize(5));
    /// secret_key.encrypt_lwe_list(
    ///     &mut ciphertext_values,
    ///     &plain_values,
    ///     noise,
    ///     &mut encryption_generator,
    /// );
    ///
    /// let mut output = LweCiphertext::from_container(vec![0. as u32; 5]);
    /// let weights = CleartextList::from_container(vec![7, 8, 9]);
    /// let bias = encoder.encode(Cleartext(13.));
    ///
    /// output.fill_with_multisum_with_bias(&ciphertext_values, &weights, &bias);
    ///
    /// let mut decrypted = Plaintext(0 as u32);
    /// secret_key.decrypt_lwe(&mut decrypted, &output);
    /// let decoded = encoder.decode(decrypted);
    /// assert!((decoded.0 - 63.).abs() < 0.1);
    /// ```
    pub fn fill_with_multisum_with_bias<Scalar, InputCont, WeightCont>(
        &mut self,
        input_list: &LweList<InputCont>,
        weights: &CleartextList<WeightCont>,
        bias: &Plaintext<Scalar>,
    ) where
        Self: AsMutTensor<Element = Scalar>,
        LweList<InputCont>: AsRefTensor<Element = Scalar>,
        CleartextList<WeightCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedInteger,
    {
        // loop over the ciphertexts and the weights
        for (input_cipher, weight) in input_list.ciphertext_iter().zip(weights.cleartext_iter()) {
            let cipher_tens = input_cipher.as_tensor();
            self.as_mut_tensor().update_with_one(cipher_tens, |o, c| {
                *o = o.wrapping_add(c.wrapping_mul(weight.0))
            });
        }

        // add the bias
        let new_body = (self.get_body().0).wrapping_add(bias.0);
        *self.get_mut_body() = LweBody(new_body);
    }

    /// Adds the `other` ciphertext to the current one.
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
    /// use tfhe::core_crypto::commons::crypto::secret::LweSecretKey;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{LogStandardDev, LweDimension};
    ///
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut encryption_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
    ///
    /// let secret_key = LweSecretKey::generate_binary(LweDimension(256), &mut secret_generator);
    /// let noise = LogStandardDev::from_log_standard_dev(-15.);
    /// let encoder = RealEncoder {
    ///     offset: 0. as f32,
    ///     delta: 10.,
    /// };
    ///
    /// let clear_1 = Cleartext(2. as f32);
    /// let plain_1: Plaintext<u32> = encoder.encode(clear_1);
    /// let mut cipher_1 = LweCiphertext::from_container(vec![0. as u32; 257]);
    /// secret_key.encrypt_lwe(&mut cipher_1, &plain_1, noise, &mut encryption_generator);
    ///
    /// let clear_2 = Cleartext(3. as f32);
    /// let plain_2: Plaintext<u32> = encoder.encode(clear_2);
    /// let mut cipher_2 = LweCiphertext::from_container(vec![0. as u32; 257]);
    /// secret_key.encrypt_lwe(&mut cipher_2, &plain_2, noise, &mut encryption_generator);
    ///
    /// cipher_1.update_with_add(&cipher_2);
    ///
    /// let mut decrypted = Plaintext(0 as u32);
    /// secret_key.decrypt_lwe(&mut decrypted, &cipher_1);
    /// let decoded = encoder.decode(decrypted);
    ///
    /// assert!((decoded.0 - 5.).abs() < 0.1);
    /// ```
    pub fn update_with_add<OtherCont, Scalar>(&mut self, other: &LweCiphertext<OtherCont>)
    where
        Self: AsMutTensor<Element = Scalar>,
        LweCiphertext<OtherCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
    {
        self.as_mut_tensor()
            .update_with_wrapping_add(other.as_tensor())
    }

    /// Subtracts the `other` ciphertext from the current one.
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
    /// use tfhe::core_crypto::commons::crypto::secret::LweSecretKey;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{LogStandardDev, LweDimension};
    ///
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut encryption_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
    ///
    /// let secret_key = LweSecretKey::generate_binary(LweDimension(256), &mut secret_generator);
    /// let noise = LogStandardDev::from_log_standard_dev(-15.);
    /// let encoder = RealEncoder {
    ///     offset: 0. as f32,
    ///     delta: 10.,
    /// };
    ///
    /// let clear_1 = Cleartext(3. as f32);
    /// let plain_1: Plaintext<u32> = encoder.encode(clear_1);
    /// let mut cipher_1 = LweCiphertext::from_container(vec![0. as u32; 257]);
    /// secret_key.encrypt_lwe(&mut cipher_1, &plain_1, noise, &mut encryption_generator);
    ///
    /// let clear_2 = Cleartext(2. as f32);
    /// let plain_2: Plaintext<u32> = encoder.encode(clear_2);
    /// let mut cipher_2 = LweCiphertext::from_container(vec![0. as u32; 257]);
    /// secret_key.encrypt_lwe(&mut cipher_2, &plain_2, noise, &mut encryption_generator);
    ///
    /// cipher_1.update_with_sub(&cipher_2);
    ///
    /// let mut decrypted = Plaintext(0 as u32);
    /// secret_key.decrypt_lwe(&mut decrypted, &cipher_1);
    /// let decoded = encoder.decode(decrypted);
    ///
    /// assert!((decoded.0 - 1.).abs() < 0.1);
    /// ```
    pub fn update_with_sub<OtherCont, Scalar>(&mut self, other: &LweCiphertext<OtherCont>)
    where
        Self: AsMutTensor<Element = Scalar>,
        LweCiphertext<OtherCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
    {
        self.as_mut_tensor()
            .update_with_wrapping_sub(other.as_tensor())
    }

    /// Computes the opposite of the ciphertext.
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
    /// use tfhe::core_crypto::commons::crypto::secret::LweSecretKey;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{LogStandardDev, LweDimension};
    ///
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut encryption_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
    ///
    /// let secret_key = LweSecretKey::generate_binary(LweDimension(256), &mut secret_generator);
    /// let noise = LogStandardDev::from_log_standard_dev(-15.);
    /// let encoder = RealEncoder {
    ///     offset: -5. as f32,
    ///     delta: 10.,
    /// };
    ///
    /// let clear = Cleartext(2. as f32);
    /// let plain: Plaintext<u32> = encoder.encode(clear);
    /// let mut cipher = LweCiphertext::from_container(vec![0. as u32; 257]);
    /// secret_key.encrypt_lwe(&mut cipher, &plain, noise, &mut encryption_generator);
    ///
    /// cipher.update_with_neg();
    ///
    /// let mut decrypted = Plaintext(0 as u32);
    /// secret_key.decrypt_lwe(&mut decrypted, &cipher);
    /// let decoded = encoder.decode(decrypted);
    ///
    /// assert!((decoded.0 - (-2.)).abs() < 0.1);
    /// ```
    pub fn update_with_neg<Scalar>(&mut self)
    where
        Self: AsMutTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
    {
        self.as_mut_tensor().update_with_wrapping_neg()
    }

    /// Multiplies the current ciphertext with a scalar value inplace.
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
    /// use tfhe::core_crypto::commons::crypto::secret::LweSecretKey;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{LogStandardDev, LweDimension};
    ///
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut encryption_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
    ///
    /// let secret_key = LweSecretKey::generate_binary(LweDimension(256), &mut secret_generator);
    /// let noise = LogStandardDev::from_log_standard_dev(-15.);
    /// let encoder = RealEncoder {
    ///     offset: 0. as f32,
    ///     delta: 10.,
    /// };
    ///
    /// let clear = Cleartext(2. as f32);
    /// let plain: Plaintext<u32> = encoder.encode(clear);
    /// let mut cipher = LweCiphertext::from_container(vec![0. as u32; 257]);
    /// secret_key.encrypt_lwe(&mut cipher, &plain, noise, &mut encryption_generator);
    ///
    /// cipher.update_with_scalar_mul(Cleartext(3));
    ///
    /// let mut decrypted = Plaintext(0 as u32);
    /// secret_key.decrypt_lwe(&mut decrypted, &cipher);
    /// let decoded = encoder.decode(decrypted);
    ///
    /// assert!((decoded.0 - 6.).abs() < 0.2);
    /// ```
    pub fn update_with_scalar_mul<Scalar>(&mut self, scalar: Cleartext<Scalar>)
    where
        Self: AsMutTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
    {
        self.as_mut_tensor()
            .update_with_wrapping_scalar_mul(&scalar.0)
    }

    /// Fills an LWE ciphertext with the sample extraction of one of the coefficients of a GLWE
    /// ciphertext.
    ///
    /// # Example
    ///
    /// ```
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
    ///     LogStandardDev(-50.),
    ///     &mut encryption_generator,
    /// );
    /// let lwe_secret_key = glwe_secret_key.into_lwe_secret_key();
    ///
    /// // Check for the first
    /// for i in 0..4 {
    ///     // We sample extract
    ///     lwe_ct.fill_with_glwe_sample_extraction(&glwe_ct, MonomialDegree(i));
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
    pub fn fill_with_glwe_sample_extraction<InputCont, Element>(
        &mut self,
        glwe: &GlweCiphertext<InputCont>,
        n_th: MonomialDegree,
    ) where
        Self: AsMutTensor<Element = Element>,
        GlweCiphertext<InputCont>: AsRefTensor<Element = Element>,
        Element: UnsignedTorus,
    {
        glwe.fill_lwe_with_sample_extraction(self, n_th);
    }

    pub fn fill_with_trivial_encryption<Scalar>(&mut self, plaintext: &Plaintext<Scalar>)
    where
        Scalar: Numeric,
        Self: AsMutTensor<Element = Scalar>,
    {
        let (output_body, mut output_mask) = self.get_mut_body_and_mask();

        // generate a uniformly random mask
        output_mask.as_mut_tensor().fill_with_element(Scalar::ZERO);

        // No need to do the multisum between the secret key and the mask
        // as the mask only contains zeros

        // add the encoded message
        output_body.0 = plaintext.0;
    }
}

/// The mask of an LWE encrypted ciphertext.
#[derive(Debug, PartialEq, Eq)]
pub struct LweMask<Cont> {
    tensor: Tensor<Cont>,
}

tensor_traits!(LweMask);

impl<Cont> LweMask<Cont> {
    /// Creates a mask from a scalar container.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::lwe::*;
    /// use tfhe::core_crypto::prelude::LweDimension;
    /// let masks = LweMask::from_container(vec![0 as u8; 10]);
    /// assert_eq!(masks.mask_size(), LweDimension(10));
    /// ```
    pub fn from_container(cont: Cont) -> LweMask<Cont> {
        LweMask {
            tensor: Tensor::from_container(cont),
        }
    }

    /// Returns an iterator over the mask elements.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::lwe::*;
    /// let mut ciphertext = LweCiphertext::from_container(vec![0 as u8; 10]);
    /// let masks = ciphertext.get_mask();
    /// for mask in masks.mask_element_iter() {
    ///     assert_eq!(mask, &0);
    /// }
    /// assert_eq!(masks.mask_element_iter().count(), 9);
    /// ```
    pub fn mask_element_iter(&self) -> impl Iterator<Item = &<Self as AsRefTensor>::Element>
    where
        Self: AsRefTensor,
    {
        self.as_tensor().iter()
    }

    /// Returns an iterator over mutable mask elements.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::lwe::*;
    /// let mut ciphertext = LweCiphertext::from_container(vec![0 as u8; 10]);
    /// let mut masks = ciphertext.get_mut_mask();
    /// for mask in masks.mask_element_iter_mut() {
    ///     *mask = 9;
    /// }
    /// for mask in masks.mask_element_iter() {
    ///     assert_eq!(mask, &9);
    /// }
    /// assert_eq!(masks.mask_element_iter_mut().count(), 9);
    /// ```
    pub fn mask_element_iter_mut(
        &mut self,
    ) -> impl Iterator<Item = &mut <Self as AsMutTensor>::Element>
    where
        Self: AsMutTensor,
    {
        self.as_mut_tensor().iter_mut()
    }

    /// Returns the number of masks.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::lwe::*;
    /// use tfhe::core_crypto::prelude::LweDimension;
    /// let mut ciphertext = LweCiphertext::from_container(vec![0 as u8; 10]);
    /// assert_eq!(ciphertext.get_mask().mask_size(), LweDimension(9));
    /// ```
    pub fn mask_size(&self) -> LweDimension
    where
        Self: AsRefTensor,
    {
        LweDimension(self.as_tensor().len())
    }

    /// Computes sum of the mask elements weighted by the key elements.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::lwe::LweCiphertext;
    /// use tfhe::core_crypto::commons::crypto::secret::LweSecretKey;
    /// let ciphertext = LweCiphertext::from_container(vec![1u32, 2, 3, 4, 5]);
    /// let mask = ciphertext.get_mask();
    /// let key = LweSecretKey::binary_from_container(vec![1, 1, 0, 1]);
    /// let multisum = mask.compute_multisum(&key);
    /// assert_eq!(multisum, 7);
    /// ```
    pub fn compute_multisum<Kind, Scalar, Cont1>(&self, key: &LweSecretKey<Kind, Cont1>) -> Scalar
    where
        Self: AsRefTensor<Element = Scalar>,
        LweSecretKey<Kind, Cont1>: AsRefTensor<Element = Scalar>,
        Kind: KeyKind,
        Scalar: UnsignedTorus,
    {
        self.as_tensor().fold_with_one(
            key.as_tensor(),
            <Scalar as Numeric>::ZERO,
            |ac, s_i, o_i| ac.wrapping_add(*s_i * *o_i),
        )
    }
}

/// The body of an Lwe ciphertext.
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct LweBody<T>(pub T);
