use super::{GlweCiphertext, GlweList};
use crate::core_crypto::commons::crypto::encoding::PlaintextList;
use crate::core_crypto::commons::crypto::lwe::{LweCiphertext, LweList};
use crate::core_crypto::commons::crypto::secret::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
use crate::core_crypto::commons::math::decomposition::{
    DecompositionLevel, DecompositionTerm, SignedDecomposer,
};
use crate::core_crypto::commons::math::polynomial::{Polynomial, PolynomialList};
use crate::core_crypto::commons::math::random::ByteRandomGenerator;
#[cfg(feature = "__commons_parallel")]
use crate::core_crypto::commons::math::random::ParallelByteRandomGenerator;
use crate::core_crypto::commons::math::tensor::{
    ck_dim_div, ck_dim_eq, tensor_traits, AsMutTensor, AsRefSlice, AsRefTensor, Container, Tensor,
};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::prelude::{
    BinaryKeyKind, CiphertextCount, DecompositionBaseLog, DecompositionLevelCount,
    DispersionParameter, FunctionalPackingKeyswitchKeyCount, GlweDimension, GlweSize, LweDimension,
    LweSize, MonomialDegree, PlaintextCount, PolynomialCount, PolynomialSize,
};
#[cfg(feature = "__commons_parallel")]
use rayon::{iter::IndexedParallelIterator, prelude::*};
#[cfg(feature = "__commons_serialization")]
use serde::{Deserialize, Serialize};

/// A packing keyswitching key.
///
/// A packing keyswitching key allows to  pack several LWE ciphertexts into a single GLWE
/// ciphertext.
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LwePackingKeyswitchKey<Cont> {
    tensor: Tensor<Cont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    output_glwe_size: GlweSize,
    output_polynomial_size: PolynomialSize,
}

tensor_traits!(LwePackingKeyswitchKey);

impl<Scalar> LwePackingKeyswitchKey<Vec<Scalar>>
where
    Scalar: Copy,
{
    /// Allocates a packing keyswitching key whose masks and bodies are all `value`.
    ///
    /// # Note
    ///
    /// This function does *not* generate a keyswitch key, but merely allocates a container of the
    /// right size. See [`LwePackingKeyswitchKey::fill_with_keyswitch_key`] to fill the container
    /// with a proper keyswitching key.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::glwe::LwePackingKeyswitchKey;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, GlweSize, LweDimension,
    ///     LweSize, PolynomialSize,
    /// };
    /// let pksk = LwePackingKeyswitchKey::allocate(
    ///     0 as u8,
    ///     DecompositionLevelCount(10),
    ///     DecompositionBaseLog(16),
    ///     LweDimension(10),
    ///     GlweDimension(2),
    ///     PolynomialSize(256),
    /// );
    /// assert_eq!(
    ///     pksk.decomposition_level_count(),
    ///     DecompositionLevelCount(10)
    /// );
    /// assert_eq!(pksk.decomposition_base_log(), DecompositionBaseLog(16));
    /// assert_eq!(pksk.output_glwe_key_dimension(), GlweDimension(2));
    /// assert_eq!(pksk.input_lwe_key_dimension(), LweDimension(10));
    /// ```
    pub fn allocate(
        value: Scalar,
        decomp_size: DecompositionLevelCount,
        decomp_base_log: DecompositionBaseLog,
        input_dimension: LweDimension,
        output_dimension: GlweDimension,
        output_polynomial_size: PolynomialSize,
    ) -> Self {
        LwePackingKeyswitchKey {
            tensor: Tensor::from_container(vec![
                value;
                decomp_size.0
                    * output_dimension.to_glwe_size().0
                    * output_polynomial_size.0
                    * input_dimension.0
            ]),
            decomp_base_log,
            decomp_level_count: decomp_size,
            output_glwe_size: output_dimension.to_glwe_size(),
            output_polynomial_size,
        }
    }
}

impl<Cont> LwePackingKeyswitchKey<Cont> {
    /// Creates a packing keyswitching key from a container.
    ///
    /// # Notes
    ///
    /// This method does not create a packing keyswitch key, but merely wraps the container in
    /// the proper type. It assumes that either the container already contains a proper keyswitching
    /// key, or that [`LwePackingKeyswitchKey::fill_with_keyswitch_key`] will be called right
    /// after.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::glwe::LwePackingKeyswitchKey;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, GlweSize, LweDimension,
    ///     LweSize, PolynomialSize,
    /// };
    /// let input_size = LweDimension(200);
    /// let output_size = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let decomp_base_log = DecompositionBaseLog(7);
    /// let decomp_level_count = DecompositionLevelCount(4);
    ///
    /// let pksk = LwePackingKeyswitchKey::from_container(
    ///     vec![
    ///         0 as u8;
    ///         input_size.0 * (output_size.0 + 1) * polynomial_size.0 * decomp_level_count.0
    ///     ],
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     output_size,
    ///     polynomial_size,
    /// );
    ///
    /// assert_eq!(pksk.decomposition_level_count(), DecompositionLevelCount(4));
    /// assert_eq!(pksk.decomposition_base_log(), DecompositionBaseLog(7));
    /// assert_eq!(pksk.output_glwe_key_dimension(), GlweDimension(2));
    /// assert_eq!(pksk.input_lwe_key_dimension(), LweDimension(200));
    /// ```
    pub fn from_container(
        cont: Cont,
        decomp_base_log: DecompositionBaseLog,
        decomp_size: DecompositionLevelCount,
        output_glwe_dimension: GlweDimension,
        output_polynomial_size: PolynomialSize,
    ) -> LwePackingKeyswitchKey<Cont>
    where
        Cont: AsRefSlice,
    {
        let tensor = Tensor::from_container(cont);
        ck_dim_div!(tensor.len() => output_glwe_dimension.to_glwe_size().0 * output_polynomial_size.0, decomp_size.0);
        LwePackingKeyswitchKey {
            tensor,
            decomp_base_log,
            decomp_level_count: decomp_size,
            output_glwe_size: output_glwe_dimension.to_glwe_size(),
            output_polynomial_size,
        }
    }

    /// Returns the dimension of the output GLWE key.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::glwe::LwePackingKeyswitchKey;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// let pksk = LwePackingKeyswitchKey::allocate(
    ///     0 as u8,
    ///     DecompositionLevelCount(10),
    ///     DecompositionBaseLog(16),
    ///     LweDimension(10),
    ///     GlweDimension(2),
    ///     PolynomialSize(256),
    /// );
    /// assert_eq!(pksk.output_glwe_key_dimension(), GlweDimension(2));
    /// ```
    pub fn output_glwe_key_dimension(&self) -> GlweDimension {
        self.output_glwe_size.to_glwe_dimension()
    }

    /// Returns the size of the polynomials composing the GLWE ciphertext
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::glwe::LwePackingKeyswitchKey;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, LweSize,
    ///     PolynomialSize,
    /// };
    /// let pksk = LwePackingKeyswitchKey::allocate(
    ///     0 as u8,
    ///     DecompositionLevelCount(10),
    ///     DecompositionBaseLog(16),
    ///     LweDimension(10),
    ///     GlweDimension(2),
    ///     PolynomialSize(256),
    /// );
    /// assert_eq!(pksk.output_polynomial_size(), PolynomialSize(256));
    /// ```
    pub fn output_polynomial_size(&self) -> PolynomialSize {
        self.output_polynomial_size
    }

    /// Returns the dimension of the input LWE key.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::glwe::LwePackingKeyswitchKey;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// let pksk = LwePackingKeyswitchKey::allocate(
    ///     0 as u8,
    ///     DecompositionLevelCount(10),
    ///     DecompositionBaseLog(16),
    ///     LweDimension(10),
    ///     GlweDimension(2),
    ///     PolynomialSize(256),
    /// );
    /// assert_eq!(pksk.input_lwe_key_dimension(), LweDimension(10));
    /// ```
    pub fn input_lwe_key_dimension(&self) -> LweDimension
    where
        Self: AsRefTensor,
    {
        LweDimension(
            self.as_tensor().len()
                / (self.output_glwe_size.0
                    * self.output_polynomial_size.0
                    * self.decomp_level_count.0),
        )
    }

    /// Returns the number of levels used for the decomposition of the input key bits.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::glwe::LwePackingKeyswitchKey;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// let pksk = LwePackingKeyswitchKey::allocate(
    ///     0 as u8,
    ///     DecompositionLevelCount(10),
    ///     DecompositionBaseLog(16),
    ///     LweDimension(10),
    ///     GlweDimension(2),
    ///     PolynomialSize(256),
    /// );
    /// assert_eq!(
    ///     pksk.decomposition_level_count(),
    ///     DecompositionLevelCount(10)
    /// );
    /// ```
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount
    where
        Self: AsRefTensor,
    {
        self.decomp_level_count
    }

    /// Returns the logarithm of the base used for the decomposition of the input key bits.
    ///
    /// Indeed, the basis used is always of the form $2^b$. This function returns $b$.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::glwe::LwePackingKeyswitchKey;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// let pksk = LwePackingKeyswitchKey::allocate(
    ///     0 as u8,
    ///     DecompositionLevelCount(10),
    ///     DecompositionBaseLog(16),
    ///     LweDimension(10),
    ///     GlweDimension(2),
    ///     PolynomialSize(256),
    /// );
    /// assert_eq!(pksk.decomposition_base_log(), DecompositionBaseLog(16));
    /// ```
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog
    where
        Self: AsRefTensor,
    {
        self.decomp_base_log
    }

    /// Fills the current keyswitch key container with an actual keyswitching key constructed from
    /// an input and an output key.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    /// use tfhe::core_crypto::commons::crypto::glwe::LwePackingKeyswitchKey;
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::commons::math::tensor::AsRefTensor;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LogStandardDev, LweDimension,
    ///     LweSize, PolynomialSize,
    /// };
    ///
    /// let input_size = LweDimension(10);
    /// let output_size = GlweDimension(3);
    /// let polynomial_size = PolynomialSize(256);
    /// let decomp_base_log = DecompositionBaseLog(3);
    /// let decomp_level_count = DecompositionLevelCount(5);
    /// let cipher_size = LweSize(55);
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut encryption_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
    /// let noise = LogStandardDev::from_log_standard_dev(-15.);
    ///
    /// let input_key = LweSecretKey::generate_binary(input_size, &mut secret_generator);
    /// let output_key =
    ///     GlweSecretKey::generate_binary(output_size, polynomial_size, &mut secret_generator);
    ///
    /// let mut pksk = LwePackingKeyswitchKey::allocate(
    ///     0 as u32,
    ///     decomp_level_count,
    ///     decomp_base_log,
    ///     input_size,
    ///     output_size,
    ///     polynomial_size,
    /// );
    /// pksk.fill_with_packing_keyswitch_key(&input_key, &output_key, noise, &mut encryption_generator);
    ///
    /// assert!(!pksk.as_tensor().iter().all(|a| *a == 0));
    /// ```
    pub fn fill_with_packing_keyswitch_key<InKeyCont, OutKeyCont, Scalar, Gen>(
        &mut self,
        input_lwe_key: &LweSecretKey<BinaryKeyKind, InKeyCont>,
        output_glwe_key: &GlweSecretKey<BinaryKeyKind, OutKeyCont>,
        noise_parameters: impl DispersionParameter,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) where
        Self: AsMutTensor<Element = Scalar>,
        LweSecretKey<BinaryKeyKind, InKeyCont>: AsRefTensor<Element = Scalar>,
        GlweSecretKey<BinaryKeyKind, OutKeyCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
        Gen: ByteRandomGenerator,
    {
        // We instantiate a buffer
        let mut messages = PlaintextList::from_container(vec![
            <Self as AsMutTensor>::Element::ZERO;
            self.decomp_level_count.0
                * self.output_polynomial_size.0
        ]);

        // We retrieve decomposition arguments
        let decomp_level_count = self.decomp_level_count;
        let decomp_base_log = self.decomp_base_log;
        let polynomial_size = self.output_polynomial_size;

        // loop over the before key blocks
        for (input_key_bit, keyswitch_key_block) in input_lwe_key
            .as_tensor()
            .iter()
            .zip(self.bit_decomp_iter_mut())
        {
            // We reset the buffer
            messages
                .as_mut_tensor()
                .fill_with_element(<Self as AsMutTensor>::Element::ZERO);

            // We fill the buffer with the powers of the key bits
            for (level, mut message) in (1..=decomp_level_count.0)
                .map(DecompositionLevel)
                .zip(messages.sublist_iter_mut(PlaintextCount(polynomial_size.0)))
            {
                *message.as_mut_tensor().first_mut() =
                    DecompositionTerm::new(level, decomp_base_log, *input_key_bit)
                        .to_recomposition_summand();
            }

            // We encrypt the buffer
            output_glwe_key.encrypt_glwe_list(
                &mut keyswitch_key_block.into_glwe_list(),
                &messages,
                noise_parameters,
                generator,
            );
        }
    }

    /// Iterates over borrowed `LweKeyBitDecomposition` elements.
    ///
    /// One `LweKeyBitDecomposition` being a set of LWE ciphertexts, encrypting under the output
    /// key, the $l$ levels of the signed decomposition of a single bit of the input key.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use tfhe::core_crypto::backends::default::private::crypto::{*, glwe::LwePackingKeyswitchKey};
    /// use tfhe::core_crypto::backends::default::private::math::decomposition::{DecompositionLevelCount, DecompositionBaseLog};
    /// let pksk = LwePackingKeyswitchKey::allocate(
    ///     0 as u8,
    ///     DecompositionLevelCount(10),
    ///     DecompositionBaseLog(16),
    ///     LweDimension(15),
    ///     LweDimension(20)
    /// );
    /// for decomp in pksk.bit_decomp_iter() {
    ///     assert_eq!(decomp.lwe_size(), pksk.lwe_size());
    ///     assert_eq!(decomp.count().0, 10);
    /// }
    /// assert_eq!(pksk.bit_decomp_iter().count(), 15);
    /// ```
    pub(crate) fn bit_decomp_iter(
        &self,
    ) -> impl Iterator<Item = LweKeyBitDecomposition<&[<Self as AsRefTensor>::Element]>>
    where
        Self: AsRefTensor,
    {
        ck_dim_div!(self.as_tensor().len() => self.output_glwe_size.0 * self.output_polynomial_size.0, self.decomp_level_count.0);
        let size =
            self.decomp_level_count.0 * self.output_glwe_size.0 * self.output_polynomial_size.0;
        let glwe_size = self.output_glwe_size;
        let poly_size = self.output_polynomial_size;
        self.as_tensor().subtensor_iter(size).map(move |sub| {
            LweKeyBitDecomposition::from_container(sub.into_container(), glwe_size, poly_size)
        })
    }

    /// Iterates over mutably borrowed `LweKeyBitDecomposition` elements.
    ///
    /// One `LweKeyBitDecomposition` being a set of LWE ciphertexts, encrypting under the output
    /// key, the $l$ levels of the signed decomposition of a single bit of the input key.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use tfhe::core_crypto::backends::default::private::crypto::{*, glwe::LwePackingKeyswitchKey};
    /// use tfhe::core_crypto::backends::default::private::math::tensor::{AsRefTensor, AsMutTensor};
    /// use tfhe::core_crypto::backends::default::private::math::decomposition::{DecompositionLevelCount, DecompositionBaseLog};
    /// let mut pksk = LwePackingKeyswitchKey::allocate(
    ///     0 as u8,
    ///     DecompositionLevelCount(10),
    ///     DecompositionBaseLog(16),
    ///     LweDimension(15),
    ///     LweDimension(20)
    /// );
    /// for mut decomp in pksk.bit_decomp_iter_mut() {
    ///     for mut ciphertext in decomp.ciphertext_iter_mut() {
    ///         ciphertext.as_mut_tensor().fill_with_element(0);
    ///     }
    /// }
    /// assert!(pksk.as_tensor().iter().all(|a| *a == 0));
    /// assert_eq!(pksk.bit_decomp_iter_mut().count(), 15);
    /// ```
    pub(crate) fn bit_decomp_iter_mut(
        &mut self,
    ) -> impl Iterator<Item = LweKeyBitDecomposition<&mut [<Self as AsMutTensor>::Element]>>
    where
        Self: AsMutTensor,
    {
        ck_dim_div!(self.as_tensor().len() => self.output_glwe_size.0 * self.output_polynomial_size.0, self.decomp_level_count.0);
        let chunks_size =
            self.decomp_level_count.0 * self.output_glwe_size.0 * self.output_polynomial_size.0;
        let glwe_size = self.output_glwe_size;
        let poly_size = self.output_polynomial_size;
        self.as_mut_tensor()
            .subtensor_iter_mut(chunks_size)
            .map(move |sub| {
                LweKeyBitDecomposition::from_container(sub.into_container(), glwe_size, poly_size)
            })
    }

    /// Keyswitches a single LWE ciphertext into a GLWE
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    /// use tfhe::core_crypto::commons::crypto::encoding::*;
    /// use tfhe::core_crypto::commons::crypto::glwe::*;
    /// use tfhe::core_crypto::commons::crypto::lwe::*;
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::commons::math::tensor::AsRefTensor;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, GlweSize, LogStandardDev,
    ///     LweDimension, LweSize, PolynomialSize,
    /// };
    ///
    /// let input_size = LweDimension(1024);
    /// let output_size = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let decomp_base_log = DecompositionBaseLog(3);
    /// let decomp_level_count = DecompositionLevelCount(8);
    /// let noise = LogStandardDev::from_log_standard_dev(-15.);
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut encryption_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
    /// let input_key = LweSecretKey::generate_binary(input_size, &mut secret_generator);
    /// let output_key =
    ///     GlweSecretKey::generate_binary(output_size, polynomial_size, &mut secret_generator);
    ///
    /// let mut pksk = LwePackingKeyswitchKey::allocate(
    ///     0 as u64,
    ///     decomp_level_count,
    ///     decomp_base_log,
    ///     input_size,
    ///     output_size,
    ///     polynomial_size,
    /// );
    /// pksk.fill_with_packing_keyswitch_key(&input_key, &output_key, noise, &mut encryption_generator);
    ///
    /// let plaintext: Plaintext<u64> = Plaintext(1432154329994324);
    /// let mut ciphertext = LweCiphertext::allocate(0. as u64, LweSize(1025));
    /// let mut switched_ciphertext =
    ///     GlweCiphertext::allocate(0. as u64, PolynomialSize(256), GlweSize(3));
    /// input_key.encrypt_lwe(
    ///     &mut ciphertext,
    ///     &plaintext,
    ///     noise,
    ///     &mut encryption_generator,
    /// );
    ///
    /// pksk.keyswitch_ciphertext(&mut switched_ciphertext, &ciphertext);
    ///
    /// let mut decrypted = PlaintextList::from_container(vec![0 as u64; 256]);
    /// output_key.decrypt_glwe(&mut decrypted, &switched_ciphertext);
    /// ```
    pub fn keyswitch_ciphertext<InCont, OutCont, Scalar>(
        &self,
        after: &mut GlweCiphertext<OutCont>,
        before: &LweCiphertext<InCont>,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        GlweCiphertext<OutCont>: AsMutTensor<Element = Scalar>,
        LweCiphertext<InCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
    {
        ck_dim_eq!(self.input_lwe_key_dimension().0 => before.lwe_size().to_lwe_dimension().0);
        ck_dim_eq!(self.output_glwe_key_dimension().0 => after.size().to_glwe_dimension().0);

        // We reset the output
        after.as_mut_tensor().fill_with(|| Scalar::ZERO);

        // We copy the body
        *after.get_mut_body().tensor.as_mut_tensor().first_mut() = before.get_body().0;

        // We instantiate a decomposer
        let decomposer = SignedDecomposer::new(self.decomp_base_log, self.decomp_level_count);

        // Loop over the number of levels:
        // We compute the multiplication of a ciphertext from the keyswitching key with a
        // piece of the decomposition and subtract it to the buffer
        for (block, input_lwe_mask) in self
            .bit_decomp_iter()
            .zip(before.get_mask().mask_element_iter())
        {
            // We decompose
            let mask_rounded = decomposer.closest_representable(*input_lwe_mask);
            let decomp = decomposer.decompose(mask_rounded);

            // Loop over the number of levels:
            // We compute the multiplication of a ciphertext from the keyswitching key with a
            // piece of the decomposition and subtract it to the buffer
            for (level_key_cipher, decomposed) in block
                .as_tensor()
                .subtensor_iter(self.output_glwe_size.0 * self.output_polynomial_size.0)
                .rev()
                .zip(decomp)
            {
                after
                    .as_mut_tensor()
                    .update_with_wrapping_sub_element_mul(&level_key_cipher, decomposed.value());
            }
        }
    }

    /// Packs several LweCiphertext into a single GlweCiphertext
    /// with a keyswitch technique
    pub fn packing_keyswitch<InCont, OutCont, Scalar>(
        &self,
        output: &mut GlweCiphertext<OutCont>,
        input: &LweList<InCont>,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        LweList<InCont>: AsRefTensor<Element = Scalar>,
        GlweCiphertext<OutCont>: AsMutTensor<Element = Scalar>,
        OutCont: Clone,
        Scalar: UnsignedTorus,
    {
        debug_assert!(input.count().0 <= output.polynomial_size().0);
        output.as_mut_tensor().fill_with_element(Scalar::ZERO);
        let mut buffer = output.clone();
        // for each ciphertext, call mono_key_switch
        for (degree, input_cipher) in input.ciphertext_iter().enumerate() {
            self.keyswitch_ciphertext(&mut buffer, &input_cipher);
            buffer
                .as_mut_polynomial_list()
                .polynomial_iter_mut()
                .for_each(|mut poly| {
                    poly.update_with_wrapping_monic_monomial_mul(MonomialDegree(degree))
                });
            output
                .as_mut_tensor()
                .update_with_wrapping_add(buffer.as_tensor());
        }
    }
}

/// A private functional packing keyswitching key.
///
/// A private functional packing keyswitching key allows to pack several LWE ciphertexts
/// into a single GLWE ciphertext while performing a private function on each
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LwePrivateFunctionalPackingKeyswitchKey<Cont> {
    tensor: Tensor<Cont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    output_glwe_size: GlweSize,
    output_polynomial_size: PolynomialSize,
}

tensor_traits!(LwePrivateFunctionalPackingKeyswitchKey);

impl<Scalar> LwePrivateFunctionalPackingKeyswitchKey<Vec<Scalar>>
where
    Scalar: Copy,
{
    /// Allocates a private functional packing keyswitching key whose masks and bodies are all
    /// `value`.
    ///
    /// # Note
    ///
    /// This function does *not* generate a private functional packing keyswitching key , but
    /// merely allocates a container of the right size.
    /// See [`LwePrivateFunctionalPackingKeyswitchKey::fill_with_private_functional_keyswitch_key`]
    /// to fill the container with a proper functional keyswitching key.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::glwe::LwePrivateFunctionalPackingKeyswitchKey;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, GlweSize, LweDimension,
    ///     LweSize, PolynomialSize,
    /// };
    /// let pfpksk = LwePrivateFunctionalPackingKeyswitchKey::allocate(
    ///     0 as u8,
    ///     DecompositionLevelCount(10),
    ///     DecompositionBaseLog(16),
    ///     LweDimension(10),
    ///     GlweDimension(2),
    ///     PolynomialSize(256),
    /// );
    /// assert_eq!(
    ///     pfpksk.decomposition_level_count(),
    ///     DecompositionLevelCount(10)
    /// );
    /// assert_eq!(pfpksk.decomposition_base_log(), DecompositionBaseLog(16));
    /// assert_eq!(pfpksk.output_glwe_key_dimension(), GlweDimension(2));
    /// assert_eq!(pfpksk.input_lwe_key_dimension(), LweDimension(10));
    /// ```
    pub fn allocate(
        value: Scalar,
        decomp_size: DecompositionLevelCount,
        decomp_base_log: DecompositionBaseLog,
        input_dimension: LweDimension,
        output_dimension: GlweDimension,
        output_polynomial_size: PolynomialSize,
    ) -> Self {
        LwePrivateFunctionalPackingKeyswitchKey {
            tensor: Tensor::from_container(vec![
                value;
                decomp_size.0
                    * output_dimension.to_glwe_size().0
                    * output_polynomial_size.0
                    * input_dimension.to_lwe_size().0
            ]),
            decomp_base_log,
            decomp_level_count: decomp_size,
            output_glwe_size: output_dimension.to_glwe_size(),
            output_polynomial_size,
        }
    }
}

impl<Cont> LwePrivateFunctionalPackingKeyswitchKey<Cont> {
    /// Creates a private functional packing keyswitching key from a container.
    ///
    /// # Notes
    ///
    /// This method does not create a private functional packing keyswitch key, but merely wraps
    /// the container in the proper type. It assumes that either the container already contains a
    /// proper functional keyswitching key, or that
    /// [`LwePrivateFunctionalPackingKeyswitchKey::fill_with_private_functional_keyswitch_key`] will
    /// be called right after.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::glwe::LwePrivateFunctionalPackingKeyswitchKey;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, GlweSize, LweDimension,
    ///     LweSize, PolynomialSize,
    /// };
    /// let input_lwe_dim = LweDimension(200);
    /// let output_glwe_dim = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let decomp_base_log = DecompositionBaseLog(7);
    /// let decomp_level_count = DecompositionLevelCount(4);
    ///
    /// let pfpksk = LwePrivateFunctionalPackingKeyswitchKey::from_container(
    ///     vec![
    ///         0 as u8;
    ///         input_lwe_dim.to_lwe_size().0
    ///             * output_glwe_dim.to_glwe_size().0
    ///             * polynomial_size.0
    ///             * decomp_level_count.0
    ///     ],
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     output_glwe_dim,
    ///     polynomial_size,
    /// );
    ///
    /// assert_eq!(pfpksk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(pfpksk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(pfpksk.output_glwe_key_dimension(), output_glwe_dim);
    /// assert_eq!(pfpksk.input_lwe_key_dimension(), input_lwe_dim);
    /// ```
    pub fn from_container(
        cont: Cont,
        decomp_base_log: DecompositionBaseLog,
        decomp_size: DecompositionLevelCount,
        output_glwe_dimension: GlweDimension,
        output_polynomial_size: PolynomialSize,
    ) -> LwePrivateFunctionalPackingKeyswitchKey<Cont>
    where
        Cont: AsRefSlice,
    {
        let tensor = Tensor::from_container(cont);
        ck_dim_div!(tensor.len() => output_glwe_dimension.to_glwe_size().0 * output_polynomial_size.0, decomp_size.0);
        LwePrivateFunctionalPackingKeyswitchKey {
            tensor,
            decomp_base_log,
            decomp_level_count: decomp_size,
            output_glwe_size: output_glwe_dimension.to_glwe_size(),
            output_polynomial_size,
        }
    }

    /// Returns the dimension of the output GLWE key.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::glwe::LwePrivateFunctionalPackingKeyswitchKey;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// let pfpksk = LwePrivateFunctionalPackingKeyswitchKey::allocate(
    ///     0 as u8,
    ///     DecompositionLevelCount(10),
    ///     DecompositionBaseLog(16),
    ///     LweDimension(10),
    ///     GlweDimension(2),
    ///     PolynomialSize(256),
    /// );
    /// assert_eq!(pfpksk.output_glwe_key_dimension(), GlweDimension(2));
    /// ```
    pub fn output_glwe_key_dimension(&self) -> GlweDimension {
        self.output_glwe_size.to_glwe_dimension()
    }

    /// Returns the size of the polynomials composing the GLWE ciphertext
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::glwe::LwePrivateFunctionalPackingKeyswitchKey;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, LweSize,
    ///     PolynomialSize,
    /// };
    /// let pfpksk = LwePrivateFunctionalPackingKeyswitchKey::allocate(
    ///     0 as u8,
    ///     DecompositionLevelCount(10),
    ///     DecompositionBaseLog(16),
    ///     LweDimension(10),
    ///     GlweDimension(2),
    ///     PolynomialSize(256),
    /// );
    /// assert_eq!(pfpksk.output_polynomial_size(), PolynomialSize(256));
    /// ```
    pub fn output_polynomial_size(&self) -> PolynomialSize {
        self.output_polynomial_size
    }

    /// Returns the dimension of the input LWE key.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::glwe::LwePrivateFunctionalPackingKeyswitchKey;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// let pfpksk = LwePrivateFunctionalPackingKeyswitchKey::allocate(
    ///     0 as u8,
    ///     DecompositionLevelCount(10),
    ///     DecompositionBaseLog(16),
    ///     LweDimension(10),
    ///     GlweDimension(2),
    ///     PolynomialSize(256),
    /// );
    /// assert_eq!(pfpksk.input_lwe_key_dimension(), LweDimension(10));
    /// ```
    pub fn input_lwe_key_dimension(&self) -> LweDimension
    where
        Self: AsRefTensor,
    {
        LweDimension(
            self.as_tensor().len()
                / (self.output_glwe_size.0
                    * self.output_polynomial_size.0
                    * self.decomp_level_count.0)
                - 1,
        )
    }

    /// Returns the number of levels used for the decomposition of the input key bits.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::glwe::LwePrivateFunctionalPackingKeyswitchKey;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// let pfpksk = LwePrivateFunctionalPackingKeyswitchKey::allocate(
    ///     0 as u8,
    ///     DecompositionLevelCount(10),
    ///     DecompositionBaseLog(16),
    ///     LweDimension(10),
    ///     GlweDimension(2),
    ///     PolynomialSize(256),
    /// );
    /// assert_eq!(
    ///     pfpksk.decomposition_level_count(),
    ///     DecompositionLevelCount(10)
    /// );
    /// ```
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount
    where
        Self: AsRefTensor,
    {
        self.decomp_level_count
    }

    /// Returns the logarithm of the base used for the decomposition of the input key bits.
    ///
    /// Indeed, the basis used is always of the form $2^b$. This function returns $b$.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::glwe::LwePrivateFunctionalPackingKeyswitchKey;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// let pfpksk = LwePrivateFunctionalPackingKeyswitchKey::allocate(
    ///     0 as u8,
    ///     DecompositionLevelCount(10),
    ///     DecompositionBaseLog(16),
    ///     LweDimension(10),
    ///     GlweDimension(2),
    ///     PolynomialSize(256),
    /// );
    /// assert_eq!(pfpksk.decomposition_base_log(), DecompositionBaseLog(16));
    /// ```
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog
    where
        Self: AsRefTensor,
    {
        self.decomp_base_log
    }

    /// Fills the current private functional keyswitch key container with an actual private
    /// functional keyswitching key constructed from an input and an output key.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::glwe::LwePrivateFunctionalPackingKeyswitchKey;
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::commons::math::polynomial::Polynomial;
    /// use tfhe::core_crypto::commons::math::tensor::AsRefTensor;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LogStandardDev, LweDimension,
    ///     LweSize, PolynomialSize,
    /// };
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    ///
    /// let input_size = LweDimension(10);
    /// let output_size = GlweDimension(3);
    /// let polynomial_size = PolynomialSize(256);
    /// let decomp_base_log = DecompositionBaseLog(3);
    /// let decomp_level_count = DecompositionLevelCount(5);
    /// let cipher_size = LweSize(55);
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut encryption_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
    /// let noise = LogStandardDev::from_log_standard_dev(-15.);
    ///
    /// let input_key = LweSecretKey::generate_binary(input_size, &mut secret_generator);
    /// let output_key =
    ///     GlweSecretKey::generate_binary(output_size, polynomial_size, &mut secret_generator);
    ///
    /// let mut pfpksk = LwePrivateFunctionalPackingKeyswitchKey::allocate(
    ///     0 as u32,
    ///     decomp_level_count,
    ///     decomp_base_log,
    ///     input_size,
    ///     output_size,
    ///     polynomial_size,
    /// );
    /// pfpksk.fill_with_private_functional_packing_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     noise,
    ///     &mut encryption_generator,
    ///     &|x| x,
    ///     &Polynomial::allocate(1 as u32, output_key.polynomial_size()),
    /// );
    ///
    /// assert!(!pfpksk.as_tensor().iter().all(|a| *a == 0));
    /// ```
    pub fn fill_with_private_functional_packing_keyswitch_key<
        InKeyCont,
        OutKeyCont,
        PolyCont,
        Scalar,
        Gen,
        ScalarFunc,
    >(
        &mut self,
        input_lwe_key: &LweSecretKey<BinaryKeyKind, InKeyCont>,
        output_glwe_key: &GlweSecretKey<BinaryKeyKind, OutKeyCont>,
        noise_parameters: impl DispersionParameter,
        generator: &mut EncryptionRandomGenerator<Gen>,
        f: &ScalarFunc,
        polynomial: &Polynomial<PolyCont>,
    ) where
        Self: AsMutTensor<Element = Scalar>,
        LweSecretKey<BinaryKeyKind, InKeyCont>: AsRefTensor<Element = Scalar>,
        GlweSecretKey<BinaryKeyKind, OutKeyCont>: AsRefTensor<Element = Scalar>,
        Polynomial<PolyCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
        Gen: ByteRandomGenerator,
        ScalarFunc: Fn(Scalar) -> Scalar + ?Sized,
    {
        // We instantiate a buffer
        let mut messages = PlaintextList::from_container(vec![
            <Self as AsMutTensor>::Element::ZERO;
            self.decomp_level_count.0
                * self.output_polynomial_size.0
        ]);
        // We retrieve decomposition arguments
        let decomp_level_count = self.decomp_level_count;
        let decomp_base_log = self.decomp_base_log;
        let polynomial_size = self.output_polynomial_size;

        let last_key_iter_bit = [Scalar::MAX];
        // add minus one for the function which will be applied to the decomposed body
        // ( Scalar::MAX = -Scalar::ONE )
        let input_key_bit_iter = input_lwe_key
            .as_tensor()
            .as_slice()
            .iter()
            .chain(last_key_iter_bit.iter());

        let gen_iter = generator
            .fork_pfpksk_to_pfpksk_chunks::<Scalar>(
                decomp_level_count,
                output_glwe_key.key_size().to_glwe_size(),
                output_glwe_key.polynomial_size(),
                input_lwe_key.key_size().to_lwe_size(),
            )
            .unwrap();

        // loop over the before key blocks
        for ((&input_key_bit, keyswitch_key_block), mut loop_generator) in input_key_bit_iter
            .zip(self.bit_decomp_iter_mut())
            .zip(gen_iter)
        {
            // We reset the buffer
            messages
                .as_mut_tensor()
                .fill_with_element(<Self as AsMutTensor>::Element::ZERO);

            // We fill the buffer with the powers of the key bits
            for (level, mut message) in (1..=decomp_level_count.0)
                .map(DecompositionLevel)
                .zip(messages.sublist_iter_mut(PlaintextCount(polynomial_size.0)))
            {
                message.as_mut_tensor().update_with_add_element_mul(
                    polynomial.as_tensor(),
                    DecompositionTerm::new(
                        level,
                        decomp_base_log,
                        f(Scalar::ONE).wrapping_mul(input_key_bit),
                    )
                    .to_recomposition_summand(),
                );
            }

            // We encrypt the buffer
            output_glwe_key.encrypt_glwe_list(
                &mut keyswitch_key_block.into_glwe_list(),
                &messages,
                noise_parameters,
                &mut loop_generator,
            );
        }
    }

    /// Fills the current private functional keyswitch key container with an actual private
    /// functional keyswitching key constructed from an input and an output key using multiple
    /// threads .
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::glwe::LwePrivateFunctionalPackingKeyswitchKey;
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::commons::math::polynomial::Polynomial;
    /// use tfhe::core_crypto::commons::math::tensor::AsRefTensor;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LogStandardDev, LweDimension,
    ///     LweSize, PolynomialSize,
    /// };
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    ///
    /// let input_size = LweDimension(10);
    /// let output_size = GlweDimension(3);
    /// let polynomial_size = PolynomialSize(256);
    /// let decomp_base_log = DecompositionBaseLog(3);
    /// let decomp_level_count = DecompositionLevelCount(5);
    /// let cipher_size = LweSize(55);
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut encryption_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
    /// let noise = LogStandardDev::from_log_standard_dev(-15.);
    ///
    /// let input_key = LweSecretKey::generate_binary(input_size, &mut secret_generator);
    /// let output_key =
    ///     GlweSecretKey::generate_binary(output_size, polynomial_size, &mut secret_generator);
    ///
    /// let mut pfpksk = LwePrivateFunctionalPackingKeyswitchKey::allocate(
    ///     0 as u32,
    ///     decomp_level_count,
    ///     decomp_base_log,
    ///     input_size,
    ///     output_size,
    ///     polynomial_size,
    /// );
    /// pfpksk.par_fill_with_private_functional_packing_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     noise,
    ///     &mut encryption_generator,
    ///     &|x| x,
    ///     &Polynomial::allocate(1 as u32, output_key.polynomial_size()),
    /// );
    ///
    /// assert!(!pfpksk.as_tensor().iter().all(|a| *a == 0));
    /// ```
    #[cfg(feature = "__commons_parallel")]
    pub fn par_fill_with_private_functional_packing_keyswitch_key<
        InKeyCont,
        OutKeyCont,
        PolyCont,
        Scalar,
        Gen,
        Noise,
        ScalarFunc,
    >(
        &mut self,
        input_lwe_key: &LweSecretKey<BinaryKeyKind, InKeyCont>,
        output_glwe_key: &GlweSecretKey<BinaryKeyKind, OutKeyCont>,
        noise_parameters: Noise,
        generator: &mut EncryptionRandomGenerator<Gen>,
        f: &ScalarFunc,
        polynomial: &Polynomial<PolyCont>,
    ) where
        Self: AsMutTensor<Element = Scalar>,
        <Self as AsMutTensor>::Element: Sync + Send,
        LweSecretKey<BinaryKeyKind, InKeyCont>: AsRefTensor<Element = Scalar>,
        GlweSecretKey<BinaryKeyKind, OutKeyCont>: AsRefTensor<Element = Scalar>,
        OutKeyCont: AsRefSlice<Element = Scalar> + Sync + Send,
        Polynomial<PolyCont>: AsRefTensor<Element = Scalar>,
        PolyCont: AsRefSlice<Element = Scalar> + Sync + Send,
        Scalar: UnsignedTorus + Sync + Send,
        Gen: ParallelByteRandomGenerator,
        Noise: DispersionParameter + Sync + Send,
        ScalarFunc: Fn(Scalar) -> Scalar + Sync + Send + ?Sized,
        Cont: Sync + Send,
    {
        // We retrieve decomposition arguments
        let decomp_level_count = self.decomp_level_count;
        let decomp_base_log = self.decomp_base_log;
        let polynomial_size = self.output_polynomial_size;

        let last_key_iter_bit = [Scalar::MAX];
        // add minus one for the function which will be applied to the decomposed body
        // ( Scalar::MAX = -Scalar::ONE )
        let input_key_bit_iter = input_lwe_key
            .as_tensor()
            .as_slice()
            .par_iter()
            .chain(last_key_iter_bit.par_iter());

        let gen_iter = generator
            .par_fork_pfpksk_to_pfpksk_chunks::<Scalar>(
                decomp_level_count,
                output_glwe_key.key_size().to_glwe_size(),
                output_glwe_key.polynomial_size(),
                input_lwe_key.key_size().to_lwe_size(),
            )
            .unwrap();

        // loop over the before key blocks
        input_key_bit_iter
            .zip(self.par_bit_decomp_iter_mut())
            .zip(gen_iter)
            .for_each(
                move |((&input_key_bit, keyswitch_key_block), mut loop_generator)| {
                    // We instantiate a buffer
                    let mut messages = PlaintextList::from_container(vec![
                        <Self as AsMutTensor>::Element::ZERO;
                        decomp_level_count.0
                            * polynomial_size.0
                    ]);

                    // We fill the buffer with the powers of the key bits
                    for (level, mut message) in (1..=decomp_level_count.0)
                        .map(DecompositionLevel)
                        .zip(messages.sublist_iter_mut(PlaintextCount(polynomial_size.0)))
                    {
                        message.as_mut_tensor().update_with_add_element_mul(
                            polynomial.as_tensor(),
                            DecompositionTerm::new(
                                level,
                                decomp_base_log,
                                f(Scalar::ONE).wrapping_mul(input_key_bit),
                            )
                            .to_recomposition_summand(),
                        );
                    }

                    // We encrypt the buffer
                    output_glwe_key.encrypt_glwe_list(
                        &mut keyswitch_key_block.into_glwe_list(),
                        &messages,
                        noise_parameters,
                        &mut loop_generator,
                    );
                },
            )
    }

    /// Iterates over borrowed `LweKeyBitDecomposition` elements.
    ///
    /// One `LweKeyBitDecomposition` being a set of LWE ciphertexts, encrypting under the output
    /// key, the $l$ levels of the signed decomposition of a single bit of the input key.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use tfhe::core_crypto::commons::crypto::{*, glwe::LwePrivateFunctionalPackingKeyswitchKey};
    /// use tfhe::core_crypto::prelude::{DecompositionLevelCount, DecompositionBaseLog,
    /// GlweDimension, LweDimension, PolynomialSize};
    /// let pfpksk = LwePrivateFunctionalPackingKeyswitchKey::allocate(
    ///     0 as u8,
    ///     DecompositionLevelCount(10),
    ///     DecompositionBaseLog(16),
    ///     LweDimension(15),
    ///     GlweDimension(20),
    ///     PolynomialSize(256)
    /// );
    /// for decomp in pfpksk.bit_decomp_iter() {
    ///     assert_eq!(decomp.glwe_size(), pfpksk.output_glwe_size());
    ///     assert_eq!(decomp.count().0, 10);
    /// }
    /// assert_eq!(pfpksk.bit_decomp_iter().count(), 15 + 1);
    /// ```
    pub(crate) fn bit_decomp_iter(
        &self,
    ) -> impl Iterator<Item = LweKeyBitDecomposition<&[<Self as AsRefTensor>::Element]>>
    where
        Self: AsRefTensor,
    {
        ck_dim_div!(self.as_tensor().len() => self.output_glwe_size.0 * self.output_polynomial_size.0, self.decomp_level_count.0);
        let size =
            self.decomp_level_count.0 * self.output_glwe_size.0 * self.output_polynomial_size.0;
        let glwe_size = self.output_glwe_size;
        let poly_size = self.output_polynomial_size;
        self.as_tensor().subtensor_iter(size).map(move |sub| {
            LweKeyBitDecomposition::from_container(sub.into_container(), glwe_size, poly_size)
        })
    }

    /// Iterates over mutably borrowed `LweKeyBitDecomposition` elements.
    ///
    /// One `LweKeyBitDecomposition` being a set of LWE ciphertexts, encrypting under the output
    /// key, the $l$ levels of the signed decomposition of a single bit of the input key.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use tfhe::core_crypto::commons::crypto::{*, glwe::LwePrivateFunctionalPackingKeyswitchKey};
    /// use tfhe::core_crypto::commons::math::tensor::{AsRefTensor, AsMutTensor};
    /// use tfhe::core_crypto::prelude::{DecompositionLevelCount, DecompositionBaseLog,
    /// GlweDimension, LweDimension, PolynomialSize};
    /// let mut pfpksk = LwePrivateFunctionalPackingKeyswitchKey::allocate(
    ///     0 as u8,
    ///     DecompositionLevelCount(10),
    ///     DecompositionBaseLog(16),
    ///     LweDimension(15),
    ///     GlweDimension(20),
    ///     PolynomialSize(256)
    /// );
    /// for mut decomp in pfpksk.bit_decomp_iter_mut() {
    ///     for mut ciphertext in decomp.ciphertext_iter_mut() {
    ///         ciphertext.as_mut_tensor().fill_with_element(0);
    ///     }
    /// }
    /// assert!(pfpksk.as_tensor().iter().all(|a| *a == 0));
    /// assert_eq!(pfpksk.bit_decomp_iter_mut().count(), 15 + 1);
    /// ```
    pub(crate) fn bit_decomp_iter_mut(
        &mut self,
    ) -> impl Iterator<Item = LweKeyBitDecomposition<&mut [<Self as AsMutTensor>::Element]>>
    where
        Self: AsMutTensor,
    {
        ck_dim_div!(self.as_tensor().len() => self.output_glwe_size.0 * self.output_polynomial_size.0, self.decomp_level_count.0);
        let chunks_size =
            self.decomp_level_count.0 * self.output_glwe_size.0 * self.output_polynomial_size.0;
        let glwe_size = self.output_glwe_size;
        let poly_size = self.output_polynomial_size;
        self.as_mut_tensor()
            .subtensor_iter_mut(chunks_size)
            .map(move |sub| {
                LweKeyBitDecomposition::from_container(sub.into_container(), glwe_size, poly_size)
            })
    }

    #[cfg(feature = "__commons_parallel")]
    pub(crate) fn par_bit_decomp_iter_mut(
        &mut self,
    ) -> impl IndexedParallelIterator<Item = LweKeyBitDecomposition<&mut [<Self as AsMutTensor>::Element]>>
    where
        Self: AsMutTensor,
        <Self as AsMutTensor>::Element: Sync + Send,
    {
        ck_dim_div!(self.as_tensor().len() => self.output_glwe_size.0 * self.output_polynomial_size.0, self.decomp_level_count.0);
        let chunks_size =
            self.decomp_level_count.0 * self.output_glwe_size.0 * self.output_polynomial_size.0;
        let glwe_size = self.output_glwe_size;
        let poly_size = self.output_polynomial_size;
        self.as_mut_tensor()
            .par_subtensor_iter_mut(chunks_size)
            .map(move |sub| {
                LweKeyBitDecomposition::from_container(sub.into_container(), glwe_size, poly_size)
            })
    }

    /// Keyswitches a single LWE ciphertext into a GLWE using a
    /// private functional packing keyswitch key
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    /// use tfhe::core_crypto::commons::crypto::encoding::*;
    /// use tfhe::core_crypto::commons::crypto::glwe::*;
    /// use tfhe::core_crypto::commons::crypto::lwe::*;
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::commons::math::polynomial::Polynomial;
    /// use tfhe::core_crypto::commons::math::tensor::AsRefTensor;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, GlweSize, LogStandardDev,
    ///     LweDimension, LweSize, PolynomialSize,
    /// };
    ///
    /// let input_lwe_dim = LweDimension(1024);
    /// let output_glwe_dim = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let decomp_base_log = DecompositionBaseLog(3);
    /// let decomp_level_count = DecompositionLevelCount(8);
    /// let noise = LogStandardDev::from_log_standard_dev(-60.);
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut encryption_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
    /// let input_key = LweSecretKey::generate_binary(input_lwe_dim, &mut secret_generator);
    /// let output_key =
    ///     GlweSecretKey::generate_binary(output_glwe_dim, polynomial_size, &mut secret_generator);
    ///
    /// let mut pfpksk = LwePrivateFunctionalPackingKeyswitchKey::allocate(
    ///     0 as u64,
    ///     decomp_level_count,
    ///     decomp_base_log,
    ///     input_lwe_dim,
    ///     output_glwe_dim,
    ///     polynomial_size,
    /// );
    /// pfpksk.fill_with_private_functional_packing_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     noise,
    ///     &mut encryption_generator,
    ///     &|x| x,
    ///     &Polynomial::allocate(1 as u64, polynomial_size),
    /// );
    ///
    /// let plaintext: Plaintext<u64> = Plaintext(5 << 60);
    /// let mut ciphertext = LweCiphertext::allocate(0. as u64, input_lwe_dim.to_lwe_size());
    /// let mut switched_ciphertext =
    ///     GlweCiphertext::allocate(0. as u64, polynomial_size, output_glwe_dim.to_glwe_size());
    /// input_key.encrypt_lwe(
    ///     &mut ciphertext,
    ///     &plaintext,
    ///     noise,
    ///     &mut encryption_generator,
    /// );
    ///
    /// pfpksk.private_functional_keyswitch_ciphertext(&mut switched_ciphertext, &ciphertext);
    ///
    /// let mut decrypted = PlaintextList::from_container(vec![0 as u64; polynomial_size.0]);
    /// output_key.decrypt_glwe(&mut decrypted, &switched_ciphertext);
    /// ```
    pub fn private_functional_keyswitch_ciphertext<InCont, OutCont, Scalar>(
        &self,
        after: &mut GlweCiphertext<OutCont>,
        before: &LweCiphertext<InCont>,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        GlweCiphertext<OutCont>: AsMutTensor<Element = Scalar>,
        LweCiphertext<InCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
    {
        ck_dim_eq!(self.input_lwe_key_dimension().0  => before.lwe_size().to_lwe_dimension().0 );
        ck_dim_eq!(self.output_glwe_key_dimension().0 => after.size().to_glwe_dimension().0);

        // We reset the output
        after.as_mut_tensor().fill_with(|| Scalar::ZERO);

        // We instantiate a decomposer
        let decomposer = SignedDecomposer::new(self.decomp_base_log, self.decomp_level_count);

        for (block, input_lwe) in self.bit_decomp_iter().zip(before.as_tensor().iter()) {
            // We decompose
            let rounded = decomposer.closest_representable(*input_lwe);
            let decomp = decomposer.decompose(rounded);

            // Loop over the number of levels:
            // We compute the multiplication of a ciphertext from the private functional
            // keyswitching key with a piece of the decomposition and subtract it to the buffer
            for (level_key_cipher, decomposed) in block
                .as_tensor()
                .subtensor_iter(self.output_glwe_size.0 * self.output_polynomial_size.0)
                .rev()
                .zip(decomp)
            {
                after
                    .as_mut_tensor()
                    .update_with_wrapping_sub_element_mul(&level_key_cipher, decomposed.value());
            }
        }
    }

    /// Packs several LweCiphertext into a single GlweCiphertext
    /// with a private functional keyswitch technique
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    /// use tfhe::core_crypto::commons::crypto::encoding::*;
    /// use tfhe::core_crypto::commons::crypto::glwe::*;
    /// use tfhe::core_crypto::commons::crypto::lwe::*;
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::commons::math::polynomial::Polynomial;
    /// use tfhe::core_crypto::commons::math::tensor::AsRefTensor;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, GlweSize, LogStandardDev,
    ///     LweDimension, LweSize, PlaintextCount, PolynomialSize,
    /// };
    ///
    /// let input_lwe_dim = LweDimension(1024);
    /// let output_glwe_dim = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let decomp_base_log = DecompositionBaseLog(3);
    /// let decomp_level_count = DecompositionLevelCount(8);
    /// let noise = LogStandardDev::from_log_standard_dev(-60.);
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut encryption_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
    /// let input_key = LweSecretKey::generate_binary(input_lwe_dim, &mut secret_generator);
    /// let output_key =
    ///     GlweSecretKey::generate_binary(output_glwe_dim, polynomial_size, &mut secret_generator);
    ///
    /// let mut pfpksk = LwePrivateFunctionalPackingKeyswitchKey::allocate(
    ///     0 as u64,
    ///     decomp_level_count,
    ///     decomp_base_log,
    ///     input_lwe_dim,
    ///     output_glwe_dim,
    ///     polynomial_size,
    /// );
    /// let mut vec = vec![0u64; polynomial_size.0];
    /// vec[0] = 1;
    ///
    /// pfpksk.fill_with_private_functional_packing_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     noise,
    ///     &mut encryption_generator,
    ///     &|x| x,
    ///     &Polynomial::from_container(vec),
    /// );
    ///
    /// let plaintext_list = PlaintextList::allocate(1 << 60 as u64, PlaintextCount(10));
    /// let ciphertext_list =
    ///     LweList::new_trivial_encryption(input_key.key_size().to_lwe_size(), &plaintext_list);
    /// let mut switched_ciphertext =
    ///     GlweCiphertext::allocate(0 as u64, polynomial_size, output_glwe_dim.to_glwe_size());
    ///
    /// pfpksk.private_functional_packing_keyswitch(&mut switched_ciphertext, &ciphertext_list);
    ///
    /// let mut decrypted = PlaintextList::from_container(vec![0 as u64; polynomial_size.0]);
    /// output_key.decrypt_glwe(&mut decrypted, &switched_ciphertext);
    /// ```
    pub fn private_functional_packing_keyswitch<InCont, OutCont, Scalar>(
        &self,
        output: &mut GlweCiphertext<OutCont>,
        input: &LweList<InCont>,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        LweList<InCont>: AsRefTensor<Element = Scalar>,
        GlweCiphertext<OutCont>: AsMutTensor<Element = Scalar>,
        OutCont: Clone,
        Scalar: UnsignedTorus,
    {
        debug_assert!(input.count().0 <= output.polynomial_size().0);
        output.as_mut_tensor().fill_with_element(Scalar::ZERO);
        let mut buffer = output.clone();
        // for each ciphertext, call mono_key_switch
        for (degree, input_cipher) in input.ciphertext_iter().enumerate() {
            self.private_functional_keyswitch_ciphertext(&mut buffer, &input_cipher);
            buffer
                .as_mut_polynomial_list()
                .polynomial_iter_mut()
                .for_each(|mut poly| {
                    poly.update_with_wrapping_monic_monomial_mul(MonomialDegree(degree))
                });
            output
                .as_mut_tensor()
                .update_with_wrapping_add(buffer.as_tensor());
        }
    }
}

/// The encryption of a single bit of the output key.
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq)]
pub(crate) struct LweKeyBitDecomposition<Cont> {
    pub(crate) tensor: Tensor<Cont>,
    pub(crate) glwe_size: GlweSize,
    pub(crate) poly_size: PolynomialSize,
}

tensor_traits!(LweKeyBitDecomposition);

impl<Cont> LweKeyBitDecomposition<Cont> {
    /// Creates a key bit decomposition from a container.
    ///
    /// # Notes
    ///
    /// This method does not decompose a key bit in a basis, but merely wraps a container in the
    /// right structure. See [`LwePackingKeyswitchKey::bit_decomp_iter`] for an iterator that
    /// returns key bit decompositions.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use tfhe::core_crypto::backends::default::private::crypto::{*, glwe::LweKeyBitDecomposition};
    /// let kbd = LweKeyBitDecomposition::from_container(vec![0 as u8; 1500], GlweSize(10),
    /// PolynomialSize(10);
    /// assert_eq!(kbd.count(), CiphertextCount(15));
    /// assert_eq!(kbd.glwe_size(), GlweSize(10));
    /// assert_eq!(kbd.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn from_container(cont: Cont, glwe_size: GlweSize, poly_size: PolynomialSize) -> Self
    where
        Tensor<Cont>: AsRefSlice,
    {
        LweKeyBitDecomposition {
            tensor: Tensor::from_container(cont),
            glwe_size,
            poly_size,
        }
    }

    /// Returns the size of the GLWE ciphertexts encoding each level of the key bit decomposition.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use tfhe::core_crypto::backends::default::private::crypto::{*, glwe::LweKeyBitDecomposition};
    /// let kbd = LweKeyBitDecomposition::from_container(vec![0 as u8; 150], LweSize(10));
    /// assert_eq!(kbd.lwe_size(), LweSize(10));
    /// ```
    #[allow(dead_code)]
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    /// Returns the size of the lwe ciphertexts encoding each level of the key bit decomposition.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use tfhe::core_crypto::backends::default::private::crypto::{*, glwe::LweKeyBitDecomposition};
    /// let kbd = LweKeyBitDecomposition::from_container(vec![0 as u8; 150], LweSize(10));
    /// assert_eq!(kbd.lwe_size(), LweSize(10));
    /// ```
    #[allow(dead_code)]
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.poly_size
    }

    /// Returns the number of ciphertexts in the decomposition.
    ///
    /// Note that this is actually equals to the number of levels in the decomposition.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use tfhe::core_crypto::backends::default::private::crypto::{*, glwe::LweKeyBitDecomposition};
    /// let kbd = LweKeyBitDecomposition::from_container(vec![0 as u8; 150], LweSize(10));
    /// assert_eq!(kbd.count(), CiphertextCount(15));
    /// ```
    #[allow(dead_code)]
    pub fn count(&self) -> CiphertextCount
    where
        Self: AsRefTensor,
    {
        ck_dim_div!(self.as_tensor().len() => self.glwe_size.0 * self.poly_size.0);
        CiphertextCount(self.as_tensor().len() / (self.glwe_size.0 * self.poly_size.0))
    }

    /// Returns an iterator over borrowed `GlweCiphertext`.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use tfhe::core_crypto::backends::default::private::crypto::{*, glwe::LweKeyBitDecomposition};
    /// let kbd = LweKeyBitDecomposition::from_container(vec![0 as u8; 150], LweSize(10));
    /// for ciphertext in kbd.ciphertext_iter(){
    ///     assert_eq!(ciphertext.lwe_size(), LweSize(10));
    /// }
    /// assert_eq!(kbd.ciphertext_iter().count(), 15);
    /// ```
    #[allow(dead_code)]
    pub fn ciphertext_iter(
        &self,
    ) -> impl Iterator<Item = GlweCiphertext<&[<Self as AsRefTensor>::Element]>>
    where
        Self: AsRefTensor,
    {
        self.as_tensor()
            .subtensor_iter(self.glwe_size.0 * self.poly_size.0)
            .map(move |sub| GlweCiphertext::from_container(sub.into_container(), self.poly_size))
    }

    /// Returns an iterator over mutably borrowed `GlweCiphertext`.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use tfhe::core_crypto::backends::default::private::crypto::{*, glwe::LweKeyBitDecomposition};
    /// use tfhe::core_crypto::backends::default::private::math::tensor::{AsRefTensor, AsMutTensor};
    /// let mut kbd = LweKeyBitDecomposition::from_container(vec![0 as u8; 150], LweSize(10));
    /// for mut ciphertext in kbd.ciphertext_iter_mut(){
    ///     ciphertext.as_mut_tensor().fill_with_element(9);
    /// }
    /// assert!(kbd.as_tensor().iter().all(|a| *a == 9));
    /// assert_eq!(kbd.ciphertext_iter().count(), 15);
    /// ```
    #[allow(dead_code)]
    pub fn ciphertext_iter_mut(
        &mut self,
    ) -> impl Iterator<Item = GlweCiphertext<&mut [<Self as AsMutTensor>::Element]>>
    where
        Self: AsMutTensor,
    {
        let chunks_size = self.glwe_size.0 * self.poly_size.0;
        let poly_size = self.poly_size;
        self.as_mut_tensor()
            .subtensor_iter_mut(chunks_size)
            .map(move |sub| GlweCiphertext::from_container(sub.into_container(), poly_size))
    }

    /// Consumes the current key bit decomposition and returns a GLWE.
    ///
    /// Note that this operation is super cheap, as it merely rewraps the current container in
    /// a GLWE structure.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use tfhe::core_crypto::backends::default::private::crypto::{*, glwe::LweKeyBitDecomposition};
    /// let kbd = LweKeyBitDecomposition::from_container(vec![0 as u8; 150], LweSize(10));
    /// let glwe = kbd.into_glwe_list();
    /// assert_eq!(list.count(), CiphertextCount(15));
    /// assert_eq!(list.lwe_size(), LweSize(10));
    /// ```
    pub fn into_glwe_list(self) -> GlweList<Cont> {
        GlweList {
            tensor: self.tensor,
            rlwe_size: self.glwe_size,
            poly_size: self.poly_size,
        }
    }
}

/// A private functional packing keyswitching key list.
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LwePrivateFunctionalPackingKeyswitchKeyList<Cont> {
    tensor: Tensor<Cont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    input_lwe_size: LweSize,
    output_glwe_size: GlweSize,
    output_polynomial_size: PolynomialSize,
}

tensor_traits!(LwePrivateFunctionalPackingKeyswitchKeyList);

impl<Scalar> LwePrivateFunctionalPackingKeyswitchKeyList<Vec<Scalar>>
where
    Scalar: Copy,
{
    /// Allocates storage for an owned [`LwePrivateFunctionalPackingKeyswitchKeyList`].
    ///
    /// # Note
    ///
    /// This function does *not* generate a private functional packing keyswitch key list, but
    /// merely allocates a container of the right size.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::glwe::LwePrivateFunctionalPackingKeyswitchKeyList;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, FunctionalPackingKeyswitchKeyCount,
    ///     GlweDimension, GlweSize, LweDimension, LweSize, PolynomialSize,
    /// };
    /// let input_lwe_dim = LweDimension(200);
    /// let output_glwe_dim = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let decomp_base_log = DecompositionBaseLog(7);
    /// let decomp_level_count = DecompositionLevelCount(4);
    /// let fpksk_count = FunctionalPackingKeyswitchKeyCount(3);
    ///
    /// let pfpksk_list = LwePrivateFunctionalPackingKeyswitchKeyList::allocate(
    ///     0u8,
    ///     decomp_level_count,
    ///     decomp_base_log,
    ///     input_lwe_dim,
    ///     output_glwe_dim,
    ///     polynomial_size,
    ///     fpksk_count,
    /// );
    ///
    /// assert_eq!(pfpksk_list.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(pfpksk_list.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(pfpksk_list.output_glwe_key_dimension(), output_glwe_dim);
    /// assert_eq!(pfpksk_list.input_lwe_key_dimension(), input_lwe_dim);
    /// assert_eq!(pfpksk_list.fpksk_count(), fpksk_count);
    /// ```
    pub fn allocate(
        value: Scalar,
        decomp_size: DecompositionLevelCount,
        decomp_base_log: DecompositionBaseLog,
        input_dimension: LweDimension,
        output_dimension: GlweDimension,
        output_polynomial_size: PolynomialSize,
        fpksk_count: FunctionalPackingKeyswitchKeyCount,
    ) -> Self {
        LwePrivateFunctionalPackingKeyswitchKeyList {
            tensor: Tensor::from_container(vec![
                value;
                decomp_size.0
                    * output_dimension.to_glwe_size().0
                    * output_polynomial_size.0
                    * input_dimension.to_lwe_size().0
                    * fpksk_count.0
            ]),
            decomp_base_log,
            decomp_level_count: decomp_size,
            input_lwe_size: input_dimension.to_lwe_size(),
            output_glwe_size: output_dimension.to_glwe_size(),
            output_polynomial_size,
        }
    }
}

impl<Cont> LwePrivateFunctionalPackingKeyswitchKeyList<Cont> {
    /// Creates a list from a container of values.
    ///
    /// # Notes
    ///
    /// This method does not create a private functional packing keyswitch key list, but merely
    /// wraps the container in the proper type. It assumes that either the container already
    /// contains a proper functional keyswitching key list, or that it will be filled right after.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::glwe::LwePrivateFunctionalPackingKeyswitchKeyList;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, FunctionalPackingKeyswitchKeyCount,
    ///     GlweDimension, GlweSize, LweDimension, LweSize, PolynomialSize,
    /// };
    /// let input_lwe_dim = LweDimension(200);
    /// let output_glwe_dim = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let decomp_base_log = DecompositionBaseLog(7);
    /// let decomp_level_count = DecompositionLevelCount(4);
    /// let fpksk_count = FunctionalPackingKeyswitchKeyCount(3);
    ///
    /// let pfpksk_list = LwePrivateFunctionalPackingKeyswitchKeyList::from_container(
    ///     vec![
    ///         0 as u8;
    ///         input_lwe_dim.to_lwe_size().0
    ///             * output_glwe_dim.to_glwe_size().0
    ///             * polynomial_size.0
    ///             * decomp_level_count.0
    ///             * fpksk_count.0
    ///     ],
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     input_lwe_dim,
    ///     output_glwe_dim,
    ///     polynomial_size,
    ///     fpksk_count,
    /// );
    ///
    /// assert_eq!(pfpksk_list.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(pfpksk_list.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(pfpksk_list.output_glwe_key_dimension(), output_glwe_dim);
    /// assert_eq!(pfpksk_list.input_lwe_key_dimension(), input_lwe_dim);
    /// assert_eq!(pfpksk_list.fpksk_count(), fpksk_count);
    /// ```
    pub fn from_container(
        cont: Cont,
        decomp_base_log: DecompositionBaseLog,
        decomp_size: DecompositionLevelCount,
        input_dimension: LweDimension,
        output_glwe_dimension: GlweDimension,
        output_polynomial_size: PolynomialSize,
        fpksk_count: FunctionalPackingKeyswitchKeyCount,
    ) -> LwePrivateFunctionalPackingKeyswitchKeyList<Cont>
    where
        Cont: AsRefSlice,
    {
        let tensor = Tensor::from_container(cont);
        ck_dim_div!(tensor.len() =>
            output_glwe_dimension.to_glwe_size().0 * output_polynomial_size.0,
            decomp_size.0,
            input_dimension.to_lwe_size().0,
            fpksk_count.0);
        LwePrivateFunctionalPackingKeyswitchKeyList {
            tensor,
            decomp_base_log,
            decomp_level_count: decomp_size,
            input_lwe_size: input_dimension.to_lwe_size(),
            output_glwe_size: output_glwe_dimension.to_glwe_size(),
            output_polynomial_size,
        }
    }

    pub fn into_container(self) -> Cont {
        self.tensor.into_container()
    }

    pub fn as_view(&self) -> LwePrivateFunctionalPackingKeyswitchKeyList<&'_ [Cont::Element]>
    where
        Cont: Container,
    {
        LwePrivateFunctionalPackingKeyswitchKeyList {
            tensor: Tensor::from_container(self.tensor.as_container().as_ref()),
            decomp_base_log: self.decomp_base_log,
            decomp_level_count: self.decomp_level_count,
            input_lwe_size: self.input_lwe_size,
            output_glwe_size: self.output_glwe_size,
            output_polynomial_size: self.output_polynomial_size,
        }
    }

    pub fn as_mut_view(
        &mut self,
    ) -> LwePrivateFunctionalPackingKeyswitchKeyList<&'_ mut [Cont::Element]>
    where
        Cont: Container + AsMut<[Cont::Element]>,
    {
        LwePrivateFunctionalPackingKeyswitchKeyList {
            tensor: Tensor::from_container(self.tensor.as_mut_container().as_mut()),
            decomp_base_log: self.decomp_base_log,
            decomp_level_count: self.decomp_level_count,
            input_lwe_size: self.input_lwe_size,
            output_glwe_size: self.output_glwe_size,
            output_polynomial_size: self.output_polynomial_size,
        }
    }

    /// Returns the dimension of the output GLWE key.
    pub fn output_glwe_key_dimension(&self) -> GlweDimension {
        self.output_glwe_size.to_glwe_dimension()
    }

    /// Returns the size of the polynomials composing the GLWE ciphertext
    pub fn output_polynomial_size(&self) -> PolynomialSize {
        self.output_polynomial_size
    }

    /// Returns the dimension of the input LWE key.
    pub fn input_lwe_key_dimension(&self) -> LweDimension {
        self.input_lwe_size.to_lwe_dimension()
    }

    /// Returns the number of levels used for the decomposition of the input key bits.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    /// Returns the logarithm of the base used for the decomposition of the input key bits.
    ///
    /// Indeed, the basis used is always of the form $2^b$. This function returns $b$.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Returns the number of private functional packing keyswitch key in the list.
    pub fn fpksk_count(&self) -> FunctionalPackingKeyswitchKeyCount
    where
        Self: AsRefTensor,
    {
        let single_ksk_size = self.output_glwe_size.0
            * self.output_polynomial_size.0
            * self.decomp_level_count.0
            * self.input_lwe_size.0;
        ck_dim_div!(self.as_tensor().len() => single_ksk_size);
        FunctionalPackingKeyswitchKeyCount(self.as_tensor().len() / single_ksk_size)
    }

    /// Returns an iterator over keys borrowed from the list.
    pub fn fpksk_iter(
        &self,
    ) -> impl DoubleEndedIterator<
        Item = LwePrivateFunctionalPackingKeyswitchKey<&[<Self as AsRefTensor>::Element]>,
    >
    where
        Self: AsRefTensor,
    {
        let single_ksk_size = self.output_glwe_size.0
            * self.output_polynomial_size.0
            * self.decomp_level_count.0
            * self.input_lwe_size.0;
        ck_dim_div!(self.as_tensor().len() => single_ksk_size);
        self.as_tensor()
            .subtensor_iter(single_ksk_size)
            .map(move |sub| {
                LwePrivateFunctionalPackingKeyswitchKey::from_container(
                    sub.into_container(),
                    self.decomposition_base_log(),
                    self.decomposition_level_count(),
                    self.output_glwe_key_dimension(),
                    self.output_polynomial_size(),
                )
            })
    }

    /// Returns an iterator over keys borrowed from the list.
    pub fn fpksk_iter_mut(
        &mut self,
    ) -> impl DoubleEndedIterator<
        Item = LwePrivateFunctionalPackingKeyswitchKey<&mut [<Self as AsMutTensor>::Element]>,
    >
    where
        Self: AsMutTensor,
    {
        let single_ksk_size = self.output_glwe_size.0
            * self.output_polynomial_size.0
            * self.decomp_level_count.0
            * self.input_lwe_size.0;
        ck_dim_div!(self.as_mut_tensor().len() => single_ksk_size);

        let decomposition_base_log = self.decomposition_base_log();
        let decomposition_level_count = self.decomposition_level_count();
        let output_glwe_key_dimension = self.output_glwe_key_dimension();
        let output_polynomial_size = self.output_polynomial_size();

        self.as_mut_tensor()
            .subtensor_iter_mut(single_ksk_size)
            .map(move |sub| {
                LwePrivateFunctionalPackingKeyswitchKey::from_container(
                    sub.into_container(),
                    decomposition_base_log,
                    decomposition_level_count,
                    output_glwe_key_dimension,
                    output_polynomial_size,
                )
            })
    }

    /// Returns an iterator over keys borrowed from the list.
    #[cfg(feature = "__commons_parallel")]
    pub fn par_fpksk_iter_mut(
        &mut self,
    ) -> impl IndexedParallelIterator<
        Item = LwePrivateFunctionalPackingKeyswitchKey<&mut [<Self as AsMutTensor>::Element]>,
    >
    where
        Self: AsMutTensor,
        <Self as AsMutTensor>::Element: Sync + Send,
    {
        let single_ksk_size = self.output_glwe_size.0
            * self.output_polynomial_size.0
            * self.decomp_level_count.0
            * self.input_lwe_size.0;
        ck_dim_div!(self.as_mut_tensor().len() => single_ksk_size);

        let decomposition_base_log = self.decomposition_base_log();
        let decomposition_level_count = self.decomposition_level_count();
        let output_glwe_key_dimension = self.output_glwe_key_dimension();
        let output_polynomial_size = self.output_polynomial_size();

        self.as_mut_tensor()
            .par_subtensor_iter_mut(single_ksk_size)
            .map(move |sub| {
                LwePrivateFunctionalPackingKeyswitchKey::from_container(
                    sub.into_container(),
                    decomposition_base_log,
                    decomposition_level_count,
                    output_glwe_key_dimension,
                    output_polynomial_size,
                )
            })
    }

    pub fn fill_with_fpksk_for_circuit_bootstrap<Scalar, C1, C2, Gen>(
        &mut self,
        input_lwe_key: &LweSecretKey<BinaryKeyKind, C1>,
        output_glwe_key: &GlweSecretKey<BinaryKeyKind, C2>,
        noise_parameters: impl DispersionParameter,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) where
        Scalar: UnsignedTorus,
        Self: AsMutTensor<Element = Scalar>,
        LweSecretKey<BinaryKeyKind, C1>: AsRefTensor<Element = Scalar>,
        GlweSecretKey<BinaryKeyKind, C2>: AsRefTensor<Element = Scalar>,
        Gen: ByteRandomGenerator,
    {
        debug_assert!(
            self.fpksk_count().0 == output_glwe_key.key_size().to_glwe_size().0,
            "Current list has {} fpksk, need to have {} \
            (encrypted_glwe_key.key_size().to_glwe_size())",
            self.fpksk_count().0,
            output_glwe_key.key_size().to_glwe_size().0
        );

        let decomp_level_count = self.decomp_level_count;

        let gen_iter = generator
            .fork_cbs_pfpksk_to_pfpksk::<Scalar>(
                decomp_level_count,
                output_glwe_key.key_size().to_glwe_size(),
                output_glwe_key.polynomial_size(),
                input_lwe_key.key_size().to_lwe_size(),
                self.fpksk_count(),
            )
            .unwrap();

        let mut last_polynomial_as_list = PolynomialList::allocate(
            Scalar::ZERO,
            PolynomialCount(1),
            output_glwe_key.polynomial_size(),
        );
        // We apply the x -> -x function so instead of putting one in the first coeff of the
        // polynomial, we put Scalar::MAX == - Sclar::One so that we can use a single function in
        // the loop avoiding branching
        *last_polynomial_as_list
            .get_mut_polynomial(0)
            .get_mut_monomial(MonomialDegree(0))
            .get_mut_coefficient() = Scalar::MAX;

        for ((mut fpksk, polynomial_to_encrypt), mut loop_generator) in self
            .fpksk_iter_mut()
            .zip(
                output_glwe_key
                    .as_polynomial_list()
                    .polynomial_iter()
                    .chain(last_polynomial_as_list.polynomial_iter()),
            )
            .zip(gen_iter)
        {
            fpksk.fill_with_private_functional_packing_keyswitch_key(
                input_lwe_key,
                output_glwe_key,
                noise_parameters,
                &mut loop_generator,
                &|x| Scalar::ZERO.wrapping_sub(x),
                &polynomial_to_encrypt,
            );
        }
    }

    #[cfg(feature = "__commons_parallel")]
    pub fn par_fill_with_fpksk_for_circuit_bootstrap<Scalar, C1, C2, Gen, Noise>(
        &mut self,
        input_lwe_key: &LweSecretKey<BinaryKeyKind, C1>,
        output_glwe_key: &GlweSecretKey<BinaryKeyKind, C2>,
        noise_parameters: Noise,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) where
        Scalar: UnsignedTorus + Sync + Send,
        Self: AsMutTensor<Element = Scalar>,
        <Self as AsMutTensor>::Element: Sync + Send,
        LweSecretKey<BinaryKeyKind, C1>: AsRefTensor<Element = Scalar>,
        GlweSecretKey<BinaryKeyKind, C2>: AsRefTensor<Element = Scalar>,
        C1: AsRefSlice<Element = Scalar> + Sync + Send,
        C2: AsRefSlice<Element = Scalar> + Sync + Send,
        Gen: ParallelByteRandomGenerator,
        Noise: DispersionParameter + Sync + Send,
    {
        debug_assert!(
            self.fpksk_count().0 == output_glwe_key.key_size().to_glwe_size().0,
            "Current list has {} fpksk, need to have {} \
            (encrypted_glwe_key.key_size().to_glwe_size())",
            self.fpksk_count().0,
            output_glwe_key.key_size().to_glwe_size().0
        );

        let decomp_level_count = self.decomp_level_count;

        let gen_iter = generator
            .par_fork_cbs_pfpksk_to_pfpksk::<Scalar>(
                decomp_level_count,
                output_glwe_key.key_size().to_glwe_size(),
                output_glwe_key.polynomial_size(),
                input_lwe_key.key_size().to_lwe_size(),
                self.fpksk_count(),
            )
            .unwrap();

        let mut last_polynomial_as_list = PolynomialList::allocate(
            Scalar::ZERO,
            PolynomialCount(1),
            output_glwe_key.polynomial_size(),
        );
        // We apply the x -> -x function so instead of putting one in the first coeff of the
        // polynomial, we put Scalar::MAX == - Sclar::One so that we can use a single function
        // in the loop avoiding branching
        *last_polynomial_as_list
            .get_mut_polynomial(0)
            .get_mut_monomial(MonomialDegree(0))
            .get_mut_coefficient() = Scalar::MAX;

        self.par_fpksk_iter_mut()
            .zip(
                output_glwe_key
                    .as_polynomial_list()
                    .par_polynomial_iter()
                    .chain(last_polynomial_as_list.par_polynomial_iter()),
            )
            .zip(gen_iter)
            .for_each(|((mut fpksk, polynomial_to_encrypt), mut loop_generator)| {
                fpksk.par_fill_with_private_functional_packing_keyswitch_key(
                    input_lwe_key,
                    output_glwe_key,
                    noise_parameters,
                    &mut loop_generator,
                    &|x| Scalar::ZERO.wrapping_sub(x),
                    &polynomial_to_encrypt,
                );
            })
    }
}

#[cfg(feature = "__commons_parallel")]
#[cfg(test)]
mod test {
    use crate::core_crypto::commons::crypto::glwe::LwePrivateFunctionalPackingKeyswitchKeyList;
    use crate::core_crypto::commons::crypto::secret::generators::{
        DeterministicSeeder, EncryptionRandomGenerator, SecretRandomGenerator,
    };
    use crate::core_crypto::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
    use crate::core_crypto::prelude::{
        DecompositionBaseLog, DecompositionLevelCount, FunctionalPackingKeyswitchKeyCount,
        GlweDimension, LogStandardDev, LweDimension, PolynomialSize,
    };
    use concrete_csprng::generators::SoftwareRandomGenerator;
    use concrete_csprng::seeders::Seed;

    #[test]
    fn check_equivalence_serial_parallel_pfpksk_gen() {
        let input_lwe_dimension = LweDimension(10);
        let output_glwe_dimension = GlweDimension(3);
        let polynomial_size = PolynomialSize(256);
        let decomp_base_log = DecompositionBaseLog(3);
        let decomp_level_count = DecompositionLevelCount(5);
        let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
        let noise = LogStandardDev::from_log_standard_dev(-15.);

        let mask_seed = Seed(crate::core_crypto::commons::test_tools::any_usize() as u128);
        let deterministic_seeder_seed =
            Seed(crate::core_crypto::commons::test_tools::any_usize() as u128);
        let number_of_runs = 10_usize;

        for _ in 0..number_of_runs {
            let input_key =
                LweSecretKey::generate_binary(input_lwe_dimension, &mut secret_generator);
            let output_key = GlweSecretKey::generate_binary(
                output_glwe_dimension,
                polynomial_size,
                &mut secret_generator,
            );

            let mut encryption_generator =
                EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(
                    mask_seed,
                    &mut DeterministicSeeder::<SoftwareRandomGenerator>::new(
                        deterministic_seeder_seed,
                    ),
                );

            let mut pfpksk_serial = LwePrivateFunctionalPackingKeyswitchKeyList::allocate(
                0u32,
                decomp_level_count,
                decomp_base_log,
                input_lwe_dimension,
                output_glwe_dimension,
                polynomial_size,
                FunctionalPackingKeyswitchKeyCount(output_glwe_dimension.to_glwe_size().0),
            );
            pfpksk_serial.fill_with_fpksk_for_circuit_bootstrap(
                &input_key,
                &output_key,
                noise,
                &mut encryption_generator,
            );

            let mut encryption_generator =
                EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(
                    mask_seed,
                    &mut DeterministicSeeder::<SoftwareRandomGenerator>::new(
                        deterministic_seeder_seed,
                    ),
                );
            let mut pfpksk_par = LwePrivateFunctionalPackingKeyswitchKeyList::allocate(
                0u32,
                decomp_level_count,
                decomp_base_log,
                input_lwe_dimension,
                output_glwe_dimension,
                polynomial_size,
                FunctionalPackingKeyswitchKeyCount(output_glwe_dimension.to_glwe_size().0),
            );
            pfpksk_par.par_fill_with_fpksk_for_circuit_bootstrap(
                &input_key,
                &output_key,
                noise,
                &mut encryption_generator,
            );

            assert_eq!(pfpksk_par, pfpksk_serial);
        }
    }
}
