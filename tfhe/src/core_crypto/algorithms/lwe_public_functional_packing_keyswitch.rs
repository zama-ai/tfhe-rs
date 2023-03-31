//! Module containing primitives pertaining to LWE ciphertext private functional keyswitch and
//! packing keyswitch.
//!
//! Formal description can be found in: \
//! &nbsp;&nbsp;&nbsp;&nbsp; Chillotti, I., Gama, N., Georgieva, M. et al. \
//! &nbsp;&nbsp;&nbsp;&nbsp; TFHE: Fast Fully Homomorphic Encryption Over the Torus. \
//! &nbsp;&nbsp;&nbsp;&nbsp; J. Cryptol 33, 34–91 (2020). \
//! &nbsp;&nbsp;&nbsp;&nbsp; <https://doi.org/10.1007/s00145-019-09319-x>

use crate::core_crypto::algorithms::polynomial_algorithms::*;
//use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
//use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Apply a public functional packing keyswitch on an input
/// [`LWE ciphertext list`](`LweCiphertextList`) and write
/// the result in an output [`GLWE ciphertext`](`GlweCiphertext`).
/// # Example
/// ```
/// //define the inputs for the public functional key switching
/// use tfhe::core_crypto::algorithms::polynomial_algorithms::*;
/// use tfhe::core_crypto::prelude::*;
///
/// let lwe_dimension = LweDimension(742);
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// let lwe_secret_key: LweSecretKeyOwned<u64> =
///     LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_generator);
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let glwe_secret_key: GlweSecretKeyOwned<u64> = GlweSecretKey::generate_new_binary(
///     glwe_size.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
/// let decomp_base_log = DecompositionBaseLog(8);
/// let decomp_level_count = DecompositionLevelCount(3);
/// let ciphertext_modulus = CiphertextModulus::new_native();
/// let mut lwe_pubfpksk = LwePublicFunctionalPackingKeyswitchKey::new(
///     0u64,
///     decomp_base_log,
///     decomp_level_count,
///     lwe_dimension,
///     glwe_size,
///     polynomial_size,
///     ciphertext_modulus,
/// );
/// let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
/// generate_lwe_public_functional_packing_keyswitch_key(
///     &lwe_secret_key,
///     &glwe_secret_key,
///     &mut lwe_pubfpksk,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// let lwe_ciphertext_count = LweCiphertextCount(20);
/// let mut lwe_list = LweCiphertextList::new(
///     0u64,
///     lwe_dimension.to_lwe_size(),
///     lwe_ciphertext_count,
///     ciphertext_modulus,
/// );
/// let lwe_plaintext_list = PlaintextList::new(1u64 << 59, PlaintextCount(20));
/// encrypt_lwe_ciphertext_list(
///     &lwe_secret_key,
///     &mut lwe_list,
///     &lwe_plaintext_list,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// let mut output_glwe_ciphertext =
///     GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
/// public_functional_keyswitch_lwe_ciphertexts_into_glwe_ciphertext(
///     &mut lwe_pubfpksk,
///     &mut output_glwe_ciphertext,
///     &lwe_list,
///     |mut x| {
///         let mut sum = 0u64;
///         x.iter().for_each(|y| sum = sum.wrapping_add(*y));
///         let mut temp = vec![sum];
///         temp.resize(polynomial_size.0, 0u64);
///         Polynomial::from_container(temp)
///     },
/// );
///
/// let mut output_plaintext_list = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(1), DecompositionLevelCount(4));
///
/// decrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &output_glwe_ciphertext,
///     &mut output_plaintext_list,
/// );
/// output_plaintext_list
///     .iter_mut()
///     .for_each(|x| *x.0 = decomposer.closest_representable(*x.0));
///
/// // Get the raw vecor
/// let mut cleartext = output_plaintext_list.into_container();
/// // Remove the encoding
/// cleartext.iter_mut().for_each(|x| *x = *x >> 59);
/// // Get the list immutably
/// let cleartext = cleartext;
///
/// // Check we get the correct result
/// for (index, clear) in cleartext.iter().enumerate() {
///     if index == 0 {
///         assert_eq!(20, *clear);
///     } else {
///         assert_eq!(0, *clear);
///     }
/// }
/// ```
pub fn public_functional_keyswitch_lwe_ciphertexts_into_glwe_ciphertext<
    KeyCont,
    InputCont,
    OutputCont,
    Func,
    Scalar,
>(
    lwe_pubfpksk: &LwePublicFunctionalPackingKeyswitchKey<KeyCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
    input_lwe_ciphertext_list: &LweCiphertextList<InputCont>,
    f: Func,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Func: Fn(Vec<Scalar>) -> Polynomial<Vec<Scalar>>,
{
    assert_eq!(
        output_glwe_ciphertext.polynomial_size(),
        lwe_pubfpksk.output_polynomial_size()
    );
    assert_eq!(
        output_glwe_ciphertext.glwe_size(),
        lwe_pubfpksk.output_glwe_size()
    );
    assert_eq!(
        input_lwe_ciphertext_list.lwe_size().to_lwe_dimension(),
        lwe_pubfpksk.input_lwe_key_dimension()
    );
    //evaluate the function on this list of first elements
    let mut list_output_function =
        Vec::with_capacity(input_lwe_ciphertext_list.lwe_ciphertext_count().0);
    for i in 0..input_lwe_ciphertext_list.lwe_size().to_lwe_dimension().0 {
        //get list of ith elements of the input lwes
        let vec_of_ai: Vec<Scalar> = input_lwe_ciphertext_list
            .iter()
            .map(|lwe| lwe.get_mask().as_ref()[i])
            .collect();
        list_output_function.push(f(vec_of_ai));
    }
    // We reset the output
    output_glwe_ciphertext.as_mut().fill(Scalar::ZERO);
    let vec_of_b: Vec<Scalar> = input_lwe_ciphertext_list
        .iter()
        .map(|lwe| *lwe.get_body().data)
        .collect();

    assert!(f(vec_of_b.clone()).polynomial_size() == output_glwe_ciphertext.polynomial_size(),
    "the polynomial size of the output_glwe_ciphertext value needs to be equal to the polynomial size of the output of the function f");

    //initiate the body of the output glwe ciphertext
    output_glwe_ciphertext
        .get_mut_body()
        .as_mut()
        .copy_from_slice(f(vec_of_b).as_ref());

    //decompose the result of the function
    // We instantiate a decomposer
    let decomposer = SignedDecomposer::new(
        lwe_pubfpksk.decomposition_base_log(),
        lwe_pubfpksk.decomposition_level_count(),
    );
    for (keyswitch_key_block, output_function) in
        lwe_pubfpksk.iter().zip(list_output_function.iter_mut())
    {
        let mut decomposition_iter = decomposer.decompose_slice(output_function.as_ref());
        // loop over the number of levels in reverse (from highest to lowest)
        for level_key_ciphertext in keyswitch_key_block.iter().rev() {
            let decomposed = decomposition_iter.next_term().unwrap();
            polynomial_list_wrapping_sub_scalar_mul_assign(
                &mut output_glwe_ciphertext.as_mut_polynomial_list(),
                &level_key_ciphertext.as_polynomial_list(),
                &Polynomial::from_container(decomposed.as_slice()),
            );
        }
    }
}
