use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::*;

/// Compute the tensor product of the left-hand side [`GLWE ciphertext`](`GlweCiphertext`) with the
/// right-hand side [`GLWE ciphertext`](`GlweCiphertext`)
/// writing the result in the output [`GlweCiphertext<Vec<Scalar>>`](`GlweCiphertext<Vec<Scalar>>`).
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::algorithms::polynomial_algorithms::*;
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let glwe_modular_std_dev = StandardDev(0.000000000000000000000000029403601535432533);
/// let decomp_base_log = DecompositionBaseLog(3);
/// let decomp_level_count = DecompositionLevelCount(8);
/// let ciphertext_modulus = CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap();
///
/// let delta1 = ciphertext_modulus.get_custom_modulus() as u64 / (1 << 5);
/// let delta2 = ciphertext_modulus.get_custom_modulus() as u64 / (1 << 4);
/// let delta = std::cmp::min(delta1, delta2);
/// let output_delta = std::cmp::max(delta1, delta2);
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// let decomposer = SignedDecomposerNonNative::new(
///     DecompositionBaseLog(4),
///     DecompositionLevelCount(1),
///     ciphertext_modulus,
/// );
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_size.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the first plaintext, we encrypt a single integer rather than a general polynomial
/// let msg_1 = 3u64;
/// let encoded_msg_1 = msg_1 * delta1;
///
/// let mut plaintext_list_1 = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
/// plaintext_list_1.as_mut()[0] = encoded_msg_1;
///
/// // Create the first GlweCiphertext
/// let mut glwe_1 = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
///
/// encrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &mut glwe_1,
///     &plaintext_list_1,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// // Create the second plaintext
/// let msg_2 = 2u64;
/// let encoded_msg_2 = msg_2 * delta2;
///
/// let mut plaintext_list_2 = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
/// plaintext_list_2.as_mut()[0] = encoded_msg_2;
///
/// // Create the second GlweCiphertext
/// let mut glwe_2 = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
///
/// encrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &mut glwe_2,
///     &plaintext_list_2,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// // Perform the tensor product
/// let tensor_output = glwe_tensor_product(&glwe_1, &glwe_2, delta);
///
/// // Compute the tensor product key
/// let tensor_glwe_dim = GlweDimension((glwe_size.0 - 1) * (glwe_size.0 + 2) / 2);
/// let mut tensor_key_poly_list =
///     PolynomialList::new(0u64, polynomial_size, PolynomialCount(tensor_glwe_dim.0));
/// let mut key_iter = tensor_key_poly_list.iter_mut();
///
/// for i in 0..glwe_size.0 - 1 {
///     for j in 0..i + 1 {
///         let mut key_pol = key_iter.next().unwrap();
///         polynomial_wrapping_sub_mul_assign_custom_mod(
///             &mut key_pol,
///             &glwe_secret_key.as_polynomial_list().get(i),
///             &glwe_secret_key.as_polynomial_list().get(j),
///             ciphertext_modulus.get_custom_modulus().cast_into(),
///         );
///     }
///     let mut key_pol = key_iter.next().unwrap();
///     polynomial_wrapping_add_assign_custom_mod(&mut key_pol, &glwe_secret_key
/// .as_polynomial_list().get(i), ciphertext_modulus.get_custom_modulus().cast_into());
/// }
///
/// let tensor_key = GlweSecretKey::from_container(tensor_key_poly_list.as_ref(), polynomial_size);
///
/// // Decrypt the tensor product ciphertext
/// let mut output_plaintext = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
///
/// decrypt_glwe_ciphertext(&tensor_key, &tensor_output, &mut output_plaintext);
/// output_plaintext
///     .iter_mut()
///     .for_each(|elt| *elt.0 = decomposer.closest_representable(*elt.0));
///
/// // Get the raw vector
/// let mut cleartext = output_plaintext.into_container();
/// // Remove the encoding
/// cleartext
///     .iter_mut()
///     .for_each(|elt| *elt = *elt / output_delta);
/// // Get the list immutably
/// let cleartext = cleartext;
///
/// // Compute what the product should be
/// let pt1 = Polynomial::from_container(
///     plaintext_list_1
///         .into_container()
///         .iter()
///         .map(|&x| <u64 as CastInto<u128>>::cast_into(x))
///         .collect::<Vec<_>>(),
/// );
/// let pt2 = Polynomial::from_container(
///     plaintext_list_2
///         .into_container()
///         .iter()
///         .map(|&x| <u64 as CastInto<u128>>::cast_into(x))
///         .collect::<Vec<_>>(),
/// );
///
/// let mut product = Polynomial::new(0u128, polynomial_size);
/// polynomial_wrapping_mul(&mut product, &pt1, &pt2);
///
/// let mut scaled_product = Polynomial::new(0u64, polynomial_size);
/// scaled_product
///     .as_mut()
///     .iter_mut()
///     .zip(product.as_ref().iter())
///     .for_each(|(dest, &source)| {
///         *dest = u64::cast_from(source / <u64 as CastInto<u128>>::cast_into(delta))
///             / output_delta
///     });
///
/// // Check we recovered the correct message
/// cleartext
///     .iter()
///     .zip(scaled_product.iter())
///     .for_each(|(&elt, coeff)| assert_eq!(elt, *coeff));
///
/// let glwe_relin_key = allocate_and_generate_glwe_relinearisation_key(
///     &glwe_secret_key,
///     decomp_base_log,
///     decomp_level_count,
///     glwe_modular_std_dev,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// let mut output_glwe_ciphertext =
///     GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
///
/// glwe_relinearisation(&tensor_output, &glwe_relin_key, &mut output_glwe_ciphertext);
///
/// // Decrypt the output glwe ciphertext
/// let mut output_plaintext = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
///
/// decrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &output_glwe_ciphertext,
///     &mut output_plaintext,
/// );
/// output_plaintext
///     .iter_mut()
///     .for_each(|elt| *elt.0 = decomposer.closest_representable(*elt.0));
///
/// // Get the raw vector
/// let mut cleartext = output_plaintext.into_container();
/// // Remove the encoding
/// cleartext
///     .iter_mut()
///     .for_each(|elt| *elt = *elt / output_delta);
/// // Get the list immutably
/// let cleartext = cleartext;
///
/// // Check we recovered the correct message
/// cleartext
///     .iter()
///     .zip(scaled_product.iter())
///     .for_each(|(&elt, coeff)| assert_eq!(elt, *coeff));
/// ```
/// based on algorithm 1 of `<https://eprint.iacr.org/2021/729.pdf>` in the eprint paper the result
/// of the division is rounded,
/// here the division in u128 performs a floor hence the induced error might be twice as large
pub fn glwe_tensor_product<InputCont, Scalar>(
    input_glwe_ciphertext_lhs: &GlweCiphertext<InputCont>,
    input_glwe_ciphertext_rhs: &GlweCiphertext<InputCont>,
    scale: Scalar,
) -> GlweCiphertext<Vec<Scalar>>
where
    Scalar: UnsignedTorus + CastInto<u128> + CastFrom<u128>,
    InputCont: Container<Element = Scalar>,
{

    assert_eq!(
        input_glwe_ciphertext_lhs.ciphertext_modulus(),
        input_glwe_ciphertext_rhs.ciphertext_modulus()
    );

    let ciphertext_modulus = input_glwe_ciphertext_lhs.ciphertext_modulus();

    if ciphertext_modulus.is_compatible_with_native_modulus() {
        glwe_tensor_product_native_mod_compatible(
            input_glwe_ciphertext_lhs,
            input_glwe_ciphertext_rhs,
            scale,
        )
    } else {
        glwe_tensor_product_non_native_mod(
            input_glwe_ciphertext_lhs,
            input_glwe_ciphertext_rhs,
            scale,
        )
    }
}

pub fn glwe_tensor_product_native_mod_compatible<InputCont, Scalar>(
    input_glwe_ciphertext_lhs: &GlweCiphertext<InputCont>,
    input_glwe_ciphertext_rhs: &GlweCiphertext<InputCont>,
    scale: Scalar,
) -> GlweCiphertext<Vec<Scalar>>
    where
        Scalar: UnsignedTorus + CastInto<u128> + CastFrom<u128>,
        InputCont: Container<Element = Scalar>,
{
    assert!(
        input_glwe_ciphertext_lhs.polynomial_size().0
            == input_glwe_ciphertext_rhs.polynomial_size().0,
        "The input glwe ciphertexts do not have the same polynomial size. The polynomial size of \
        the lhs is {}, while for the rhs it is {}.",
        input_glwe_ciphertext_lhs.polynomial_size().0,
        input_glwe_ciphertext_rhs.polynomial_size().0
    );

    assert!(
        input_glwe_ciphertext_lhs.glwe_size().0 == input_glwe_ciphertext_rhs.glwe_size().0,
        "The input glwe ciphertexts do not have the same glwe size. The glwe size of the lhs is \
        {}, while for the rhs it is {}.",
        input_glwe_ciphertext_lhs.glwe_size().0,
        input_glwe_ciphertext_rhs.glwe_size().0
    );


    let k = input_glwe_ciphertext_lhs.glwe_size().to_glwe_dimension().0;

    // This is k + k*(k-1)/2 + k: k square terms, k*(k-1)/2 cross terms, k linear terms
    let new_k = GlweDimension(k * (k + 3) / 2);

    let mut output_glwe_ciphertext = GlweCiphertextOwned::new(
        Scalar::ZERO,
        new_k.to_glwe_size(),
        input_glwe_ciphertext_lhs.polynomial_size(),
        input_glwe_ciphertext_lhs.ciphertext_modulus(),
    );

    let mut output_mask = output_glwe_ciphertext.get_mut_mask();
    let mut output_mask_poly_list = output_mask.as_mut_polynomial_list();
    let mut iter_output_mask = output_mask_poly_list.iter_mut();
    let input_lhs = PolynomialList::from_container(
        input_glwe_ciphertext_lhs
            .get_mask()
            .as_ref()
            .iter()
            .map(|&x| <Scalar as CastInto<u128>>::cast_into(x))
            .collect::<Vec<_>>(),
        input_glwe_ciphertext_lhs.polynomial_size(),
    );
    let input_rhs = PolynomialList::from_container(
        input_glwe_ciphertext_rhs
            .get_mask()
            .as_ref()
            .iter()
            .map(|&x| <Scalar as CastInto<u128>>::cast_into(x))
            .collect::<Vec<_>>(),
        input_glwe_ciphertext_rhs.polynomial_size(),
    );

    for (i, a_lhs_i) in input_lhs.iter().enumerate() {
        for (j, a_rhs_j) in input_rhs.iter().enumerate() {
            if i == j {
                //tensor elements corresponding to key -s_i^2
                let mut temp_poly_sq = Polynomial::new(0u128, a_lhs_i.polynomial_size());
                polynomial_wrapping_add_mul_assign(&mut temp_poly_sq, &a_lhs_i, &a_rhs_j);

                let mut output_poly_sq = iter_output_mask.next().unwrap();
                output_poly_sq
                    .as_mut()
                    .iter_mut()
                    .zip(temp_poly_sq.as_ref().iter())
                    .for_each(|(dest, &source)| {
                        *dest =
                            Scalar::cast_from(source / <Scalar as CastInto<u128>>::cast_into(scale))
                    });

                //tensor elements corresponding to key s_i
                let mut temp_poly_s1 = Polynomial::new(0u128, a_lhs_i.polynomial_size());
                polynomial_wrapping_add_mul_assign(
                    &mut temp_poly_s1,
                    &a_lhs_i,
                    &Polynomial::from_container(
                        input_glwe_ciphertext_rhs
                            .get_body()
                            .as_ref()
                            .iter()
                            .map(|&x| <Scalar as CastInto<u128>>::cast_into(x))
                            .collect::<Vec<_>>(),
                    ),
                );

                let mut temp_poly_s2 = Polynomial::new(0u128, a_lhs_i.polynomial_size());
                polynomial_wrapping_add_mul_assign(
                    &mut temp_poly_s2,
                    &Polynomial::from_container(
                        input_glwe_ciphertext_lhs
                            .get_body()
                            .as_ref()
                            .iter()
                            .map(|&x| <Scalar as CastInto<u128>>::cast_into(x))
                            .collect::<Vec<_>>(),
                    ),
                    &a_rhs_j,
                );

                polynomial_wrapping_add_assign(&mut temp_poly_s1, &temp_poly_s2);
                let mut output_poly_s = iter_output_mask.next().unwrap();
                output_poly_s
                    .as_mut()
                    .iter_mut()
                    .zip(temp_poly_s1.as_ref().iter())
                    .for_each(|(dest, &source)| {
                        *dest =
                            Scalar::cast_from(source / <Scalar as CastInto<u128>>::cast_into(scale))
                    });
            } else {
                //when i and j are different we only compute the terms where j < i
                if j < i {
                    //tensor element corresponding to key -s_i*s_j
                    let mut temp_poly = Polynomial::new(0u128, a_lhs_i.polynomial_size());
                    polynomial_wrapping_add_mul_assign(&mut temp_poly, &a_lhs_i, &a_rhs_j);
                    polynomial_wrapping_add_mul_assign(
                        &mut temp_poly,
                        &input_lhs.get(j),
                        &input_rhs.get(i),
                    );

                    let mut output_poly = iter_output_mask.next().unwrap();
                    output_poly
                        .as_mut()
                        .iter_mut()
                        .zip(temp_poly.as_ref().iter())
                        .for_each(|(dest, &source)| {
                            *dest = Scalar::cast_from(
                                source / <Scalar as CastInto<u128>>::cast_into(scale),
                            )
                        });
                }
            }
        }
    }

    //tensor element corresponding to the body
    let mut temp_poly_body = Polynomial::new(0u128, input_glwe_ciphertext_lhs.polynomial_size());
    polynomial_wrapping_add_mul_assign(
        &mut temp_poly_body,
        &Polynomial::from_container(
            input_glwe_ciphertext_lhs
                .get_body()
                .as_ref()
                .iter()
                .map(|&x| <Scalar as CastInto<u128>>::cast_into(x))
                .collect::<Vec<_>>(),
        ),
        &Polynomial::from_container(
            input_glwe_ciphertext_rhs
                .get_body()
                .as_ref()
                .iter()
                .map(|&x| <Scalar as CastInto<u128>>::cast_into(x))
                .collect::<Vec<_>>(),
        ),
    );
    let mut output_body = output_glwe_ciphertext.get_mut_body();
    let mut output_poly_body = output_body.as_mut_polynomial();
    output_poly_body
        .as_mut()
        .iter_mut()
        .zip(temp_poly_body.as_ref().iter())
        .for_each(|(dest, &source)| {
            *dest = Scalar::cast_from(source / <Scalar as CastInto<u128>>::cast_into(scale))
        });
    output_glwe_ciphertext
}

pub fn glwe_tensor_product_non_native_mod<InputCont, Scalar>(
    input_glwe_ciphertext_lhs: &GlweCiphertext<InputCont>,
    input_glwe_ciphertext_rhs: &GlweCiphertext<InputCont>,
    scale: Scalar,
) -> GlweCiphertext<Vec<Scalar>>
    where
        Scalar: UnsignedTorus + CastInto<u128> + CastFrom<u128>,
        InputCont: Container<Element = Scalar>,
{
    assert!(
        input_glwe_ciphertext_lhs.polynomial_size().0
            == input_glwe_ciphertext_rhs.polynomial_size().0,
        "The input glwe ciphertexts do not have the same polynomial size. The polynomial size of \
        the lhs is {}, while for the rhs it is {}.",
        input_glwe_ciphertext_lhs.polynomial_size().0,
        input_glwe_ciphertext_rhs.polynomial_size().0
    );

    assert!(
        input_glwe_ciphertext_lhs.glwe_size().0 == input_glwe_ciphertext_rhs.glwe_size().0,
        "The input glwe ciphertexts do not have the same glwe size. The glwe size of the lhs is \
        {}, while for the rhs it is {}.",
        input_glwe_ciphertext_lhs.glwe_size().0,
        input_glwe_ciphertext_rhs.glwe_size().0
    );

    let ciphertext_modulus = input_glwe_ciphertext_lhs.ciphertext_modulus();
    let square_ct_mod = ciphertext_modulus.get_custom_modulus().pow(2);

    let k = input_glwe_ciphertext_lhs.glwe_size().to_glwe_dimension().0;

    // This is k + k*(k-1)/2 + k: k square terms, k*(k-1)/2 cross terms, k linear terms
    let new_k = GlweDimension(k * (k + 3) / 2);

    let mut output_glwe_ciphertext = GlweCiphertextOwned::new(
        Scalar::ZERO,
        new_k.to_glwe_size(),
        input_glwe_ciphertext_lhs.polynomial_size(),
        input_glwe_ciphertext_lhs.ciphertext_modulus(),
    );

    let mut output_mask = output_glwe_ciphertext.get_mut_mask();
    let mut output_mask_poly_list = output_mask.as_mut_polynomial_list();
    let mut iter_output_mask = output_mask_poly_list.iter_mut();
    let input_lhs = PolynomialList::from_container(
        input_glwe_ciphertext_lhs
            .get_mask()
            .as_ref()
            .iter()
            .map(|&x| <Scalar as CastInto<u128>>::cast_into(x))
            .collect::<Vec<_>>(),
        input_glwe_ciphertext_lhs.polynomial_size(),
    );
    let input_rhs = PolynomialList::from_container(
        input_glwe_ciphertext_rhs
            .get_mask()
            .as_ref()
            .iter()
            .map(|&x| <Scalar as CastInto<u128>>::cast_into(x))
            .collect::<Vec<_>>(),
        input_glwe_ciphertext_rhs.polynomial_size(),
    );

    for (i, a_lhs_i) in input_lhs.iter().enumerate() {
        for (j, a_rhs_j) in input_rhs.iter().enumerate() {
            if i == j {
                //tensor elements corresponding to key -s_i^2
                let mut temp_poly_sq = Polynomial::new(0u128, a_lhs_i.polynomial_size());
                polynomial_wrapping_add_mul_assign_custom_mod(&mut temp_poly_sq, &a_lhs_i,
                                                              &a_rhs_j, square_ct_mod);
                let mut output_poly_sq = iter_output_mask.next().unwrap();
                output_poly_sq
                    .as_mut()
                    .iter_mut()
                    .zip(temp_poly_sq.as_ref().iter())
                    .for_each(|(dest, &source)| {
                        let shifted = source.wrapping_add_custom_mod(
                            <Scalar as CastInto<u128>>::cast_into(scale) / 2,
                            square_ct_mod,
                        );
                        let temp = (shifted / <Scalar as CastInto<u128>>::cast_into(scale))
                            .wrapping_rem(ciphertext_modulus.get_custom_modulus());
                        *dest = temp.cast_into()
                    });


                //tensor elements corresponding to key s_i
                let mut temp_poly_s1 = Polynomial::new(0u128, a_lhs_i.polynomial_size());
                polynomial_wrapping_add_mul_assign_custom_mod(
                    &mut temp_poly_s1,
                    &a_lhs_i,
                    &Polynomial::from_container(
                        input_glwe_ciphertext_rhs
                            .get_body()
                            .as_ref()
                            .iter()
                            .map(|&x| <Scalar as CastInto<u128>>::cast_into(x))
                            .collect::<Vec<_>>(),
                    ),
                    square_ct_mod,
                );

                let mut temp_poly_s2 = Polynomial::new(0u128, a_lhs_i.polynomial_size());
                polynomial_wrapping_add_mul_assign_custom_mod(
                    &mut temp_poly_s2,
                    &Polynomial::from_container(
                        input_glwe_ciphertext_lhs
                            .get_body()
                            .as_ref()
                            .iter()
                            .map(|&x| <Scalar as CastInto<u128>>::cast_into(x))
                            .collect::<Vec<_>>(),
                    ),
                    &a_rhs_j,
                    square_ct_mod,
                );

                polynomial_wrapping_add_assign_custom_mod(&mut temp_poly_s1, &temp_poly_s2, square_ct_mod);
                let mut output_poly_s = iter_output_mask.next().unwrap();
                output_poly_s
                    .as_mut()
                    .iter_mut()
                    .zip(temp_poly_s1.as_ref().iter())
                    .for_each(|(dest, &source)| {
                        let shifted = source.wrapping_add_custom_mod(
                            <Scalar as CastInto<u128>>::cast_into(scale) / 2,
                            square_ct_mod,
                        );
                        let temp = (shifted / <Scalar as CastInto<u128>>::cast_into(scale))
                            .wrapping_rem(ciphertext_modulus.get_custom_modulus());
                        *dest = temp.cast_into()
                    });
            } else {
                //when i and j are different we only compute the terms where j < i
                if j < i {
                    //tensor element corresponding to key -s_i*s_j
                    let mut temp_poly = Polynomial::new(0u128, a_lhs_i.polynomial_size());
                    polynomial_wrapping_add_mul_assign_custom_mod(
                        &mut temp_poly,
                        &a_lhs_i,
                        &a_rhs_j,
                        square_ct_mod,
                    );
                    polynomial_wrapping_add_mul_assign_custom_mod(
                        &mut temp_poly,
                        &input_lhs.get(j),
                        &input_rhs.get(i),
                        square_ct_mod,
                    );

                    let mut output_poly = iter_output_mask.next().unwrap();
                    output_poly
                        .as_mut()
                        .iter_mut()
                        .zip(temp_poly.as_ref().iter())
                        .for_each(|(dest, &source)| {
                            let shifted = source.wrapping_add_custom_mod(
                                <Scalar as CastInto<u128>>::cast_into(scale) / 2,
                                square_ct_mod,
                            );
                            let temp = (shifted / <Scalar as CastInto<u128>>::cast_into(scale))
                                .wrapping_rem(ciphertext_modulus.get_custom_modulus());
                            *dest = temp.cast_into()
                        });
                }
            }
        }
    }

    //tensor element corresponding to the body
    let mut temp_poly_body = Polynomial::new(0u128, input_glwe_ciphertext_lhs.polynomial_size());
    polynomial_wrapping_add_mul_assign_custom_mod(
        &mut temp_poly_body,
        &Polynomial::from_container(
            input_glwe_ciphertext_lhs
                .get_body()
                .as_ref()
                .iter()
                .map(|&x| <Scalar as CastInto<u128>>::cast_into(x))
                .collect::<Vec<_>>(),
        ),
        &Polynomial::from_container(
            input_glwe_ciphertext_rhs
                .get_body()
                .as_ref()
                .iter()
                .map(|&x| <Scalar as CastInto<u128>>::cast_into(x))
                .collect::<Vec<_>>(),
        ),
        square_ct_mod,
    );
    let mut output_body = output_glwe_ciphertext.get_mut_body();
    let mut output_poly_body = output_body.as_mut_polynomial();
    output_poly_body
        .as_mut()
        .iter_mut()
        .zip(temp_poly_body.as_ref().iter())
        .for_each(|(dest, &source)| {
            let shifted = source.wrapping_add_custom_mod(
                <Scalar as CastInto<u128>>::cast_into(scale) / 2,
                square_ct_mod,
            );
            let temp = (shifted / <Scalar as CastInto<u128>>::cast_into(scale))
                .wrapping_rem(ciphertext_modulus.get_custom_modulus());
            *dest = temp.cast_into()

        });
    output_glwe_ciphertext
}

/// Relinearise the [`GLWE ciphertext`](`GlweCiphertext`) that is output by the
/// glwe_tensor_product operation using a [`GLWE relinearisation key`](`GlweRelinearisationKey`).
pub fn glwe_relinearisation<InputCont, KeyCont, OutputCont, Scalar>(
    input_glwe_ciphertext: &GlweCiphertext<InputCont>,
    relinearisation_key: &GlweRelinearisationKey<KeyCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert_eq!(
        input_glwe_ciphertext.ciphertext_modulus(),
        relinearisation_key.ciphertext_modulus(),
    );
    assert_eq!(
        input_glwe_ciphertext.ciphertext_modulus(),
        output_glwe_ciphertext.ciphertext_modulus(),
    );

    let ciphertext_modulus = input_glwe_ciphertext.ciphertext_modulus();

    if ciphertext_modulus.is_compatible_with_native_modulus() {
        glwe_relinearisation_native_mod_compatible(
            input_glwe_ciphertext,
            relinearisation_key,
            output_glwe_ciphertext,
        )
    } else {
        glwe_relinearisation_non_native_mod(
            input_glwe_ciphertext,
            relinearisation_key,
            output_glwe_ciphertext,
        )
    }
}

pub fn glwe_relinearisation_native_mod_compatible<InputCont, KeyCont, OutputCont, Scalar>(
    input_glwe_ciphertext: &GlweCiphertext<InputCont>,
    relinearisation_key: &GlweRelinearisationKey<KeyCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert_eq!(
        relinearisation_key.glwe_dimension().0 * (relinearisation_key.glwe_dimension().0 + 3) / 2,
        input_glwe_ciphertext.glwe_size().to_glwe_dimension().0
    );
    assert_eq!(
        relinearisation_key.glwe_size(),
        output_glwe_ciphertext.glwe_size()
    );
    assert_eq!(
        relinearisation_key.polynomial_size(),
        input_glwe_ciphertext.polynomial_size()
    );
    assert_eq!(
        relinearisation_key.polynomial_size(),
        output_glwe_ciphertext.polynomial_size()
    );

    // Clear the output ciphertext, as it will get updated gradually
    output_glwe_ciphertext.as_mut().fill(Scalar::ZERO);

    // Copy the input body to the output ciphertext
    polynomial_wrapping_add_assign(
        &mut output_glwe_ciphertext.get_mut_body().as_mut_polynomial(),
        &input_glwe_ciphertext.get_body().as_polynomial(),
    );

    // We instantiate a decomposer
    let decomposer = SignedDecomposer::new(
        relinearisation_key.decomposition_base_log(),
        relinearisation_key.decomposition_level_count(),
    );

    let mut relin_key_iter = relinearisation_key.iter();
    let input_glwe_mask = input_glwe_ciphertext.get_mask();
    let input_glwe_mask_poly_list = input_glwe_mask.as_polynomial_list();
    let mut input_poly_iter = input_glwe_mask_poly_list.iter();

    for i in 0..relinearisation_key.glwe_size().0 - 1 {
        for _ in 0..i + 1 {
            let ksk = relin_key_iter.next().unwrap();
            let pol = input_poly_iter.next().unwrap();
            let mut decomposition_iter = decomposer.decompose_slice(pol.as_ref());
            // loop over the number of levels in reverse (from highest to lowest)
            for level_key_ciphertext in ksk.iter().rev() {
                let decomposed = decomposition_iter.next_term().unwrap();
                polynomial_list_wrapping_sub_scalar_mul_assign(
                    &mut output_glwe_ciphertext.as_mut_polynomial_list(),
                    &level_key_ciphertext.as_polynomial_list(),
                    &Polynomial::from_container(decomposed.as_slice()),
                );
            }
        }
        let pol = input_poly_iter.next().unwrap();
        polynomial_wrapping_add_assign(
            &mut output_glwe_ciphertext.as_mut_polynomial_list().get_mut(i),
            &pol,
        )
    }
}

pub fn glwe_relinearisation_non_native_mod<InputCont, KeyCont, OutputCont, Scalar>(
    input_glwe_ciphertext: &GlweCiphertext<InputCont>,
    relinearisation_key: &GlweRelinearisationKey<KeyCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert_eq!(
        relinearisation_key.glwe_dimension().0 * (relinearisation_key.glwe_dimension().0 + 3) / 2,
        input_glwe_ciphertext.glwe_size().to_glwe_dimension().0
    );
    assert_eq!(
        relinearisation_key.glwe_size(),
        output_glwe_ciphertext.glwe_size()
    );
    assert_eq!(
        relinearisation_key.polynomial_size(),
        input_glwe_ciphertext.polynomial_size()
    );
    assert_eq!(
        relinearisation_key.polynomial_size(),
        output_glwe_ciphertext.polynomial_size()
    );

    let ciphertext_modulus = input_glwe_ciphertext.ciphertext_modulus();

    // Clear the output ciphertext, as it will get updated gradually
    output_glwe_ciphertext.as_mut().fill(Scalar::ZERO);

    // Copy the input body to the output ciphertext (no need to use non native addition here)
    polynomial_wrapping_add_assign(
        &mut output_glwe_ciphertext.get_mut_body().as_mut_polynomial(),
        &input_glwe_ciphertext.get_body().as_polynomial(),
    );

    // We instantiate a decomposer
    let decomposer = SignedDecomposerNonNative::new(
        relinearisation_key.decomposition_base_log(),
        relinearisation_key.decomposition_level_count(),
        ciphertext_modulus,
    );

    let mut relin_key_iter = relinearisation_key.iter();
    let input_glwe_mask = input_glwe_ciphertext.get_mask();
    let input_glwe_mask_poly_list = input_glwe_mask.as_polynomial_list();
    let mut input_poly_iter = input_glwe_mask_poly_list.iter();

    for i in 0..relinearisation_key.glwe_size().0 - 1 {
        for _ in 0..i + 1 {
            let ksk = relin_key_iter.next().unwrap();
            let pol = input_poly_iter.next().unwrap();
            let mut decomposition_iter = decomposer.decompose_slice(pol.as_ref());
            // loop over the number of levels in reverse (from highest to lowest)
            for level_key_ciphertext in ksk.iter().rev() {
                let decomposed = decomposition_iter.next_term().unwrap();
                polynomial_list_wrapping_sub_scalar_mul_assign_custom_mod(
                    &mut output_glwe_ciphertext.as_mut_polynomial_list(),
                    &level_key_ciphertext.as_polynomial_list(),
                    &Polynomial::from_container(decomposed.as_slice()),
                    ciphertext_modulus.get_custom_modulus().cast_into(),
                );
            }
        }
        let pol = input_poly_iter.next().unwrap();
        polynomial_wrapping_add_assign_custom_mod(
            &mut output_glwe_ciphertext.as_mut_polynomial_list().get_mut(i),
            &pol,
            ciphertext_modulus.get_custom_modulus().cast_into(),
        )
    }
}

pub fn tensor_mult_with_relin<InputCont, KeyCont, OutputCont, Scalar>(
    input_glwe_ciphertext_lhs: &GlweCiphertext<InputCont>,
    input_glwe_ciphertext_rhs: &GlweCiphertext<InputCont>,
    scale: Scalar,
    relinearisation_key: &GlweRelinearisationKey<KeyCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
) where
    Scalar: UnsignedTorus + CastInto<u128> + CastFrom<u128>,
    InputCont: Container<Element = Scalar>,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    let tensor_output = glwe_tensor_product(
        &input_glwe_ciphertext_lhs,
        &input_glwe_ciphertext_rhs,
        scale,
    );
    glwe_relinearisation(&tensor_output, &relinearisation_key, output_glwe_ciphertext);
}

pub fn packed_mult<InputCont, KeyCont, OutputCont, Scalar>(
    input_lwe_ciphertext_list_1: &LweCiphertextList<InputCont>,
    input_lwe_ciphertext_list_2: &LweCiphertextList<InputCont>,
    lwe_pubfpksk: &LwePublicFunctionalPackingKeyswitchKey<KeyCont>,
    relinearisation_key: &GlweRelinearisationKey<KeyCont>,
    scale: Scalar,
    output_lwe_ciphertext_list: &mut LweCiphertextList<OutputCont>,
) where
    Scalar: UnsignedTorus + CastInto<u128> + CastFrom<u128>,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    let mut packed_glwe_1 =
        GlweCiphertext::new(Scalar::ZERO, 
            lwe_pubfpksk.output_glwe_size(), 
            lwe_pubfpksk.output_polynomial_size(), 
            lwe_pubfpksk.ciphertext_modulus());
    public_functional_keyswitch_lwe_ciphertexts_into_glwe_ciphertext(
        &lwe_pubfpksk,
        &mut packed_glwe_1,
        &input_lwe_ciphertext_list_1,
        | x: Vec<Scalar>| {
            let mut packed1: Vec<Scalar> = vec![Scalar::ZERO;lwe_pubfpksk.output_polynomial_size().0];
            x.iter().enumerate().for_each(|(iter,y)| packed1[iter] = *y);
            Polynomial::from_container(packed1)
            }
        );
    let mut packed_glwe_2 =
        GlweCiphertext::new(Scalar::ZERO,
            lwe_pubfpksk.output_glwe_size(), 
            lwe_pubfpksk.output_polynomial_size(), 
            lwe_pubfpksk.ciphertext_modulus());
    public_functional_keyswitch_lwe_ciphertexts_into_glwe_ciphertext(
        &lwe_pubfpksk,
        &mut packed_glwe_2,
        &input_lwe_ciphertext_list_2,
        | x| {
            let mut packed2: Vec<Scalar> = vec![Scalar::ZERO;lwe_pubfpksk.output_polynomial_size().0];
            x.iter().enumerate().for_each(|(iter,y)| packed2[input_lwe_ciphertext_list_1.lwe_ciphertext_count().0*iter] = *y);
            Polynomial::from_container(packed2)
            },
        );
    let mut relin_glwe_ciphertext =
        GlweCiphertext::new(Scalar::ZERO, lwe_pubfpksk.output_glwe_size(), 
            lwe_pubfpksk.output_polynomial_size(), 
            lwe_pubfpksk.ciphertext_modulus());
    tensor_mult_with_relin(
        &packed_glwe_1,
        &packed_glwe_2,
        scale,
        &relinearisation_key,
        &mut relin_glwe_ciphertext,
        );
        
    output_lwe_ciphertext_list.iter_mut().enumerate().
        for_each(|(iter, mut el)| extract_lwe_sample_from_glwe_ciphertext(&relin_glwe_ciphertext, 
            &mut el, 
            MonomialDegree(iter*(input_lwe_ciphertext_list_1.lwe_ciphertext_count().0+1))));

}

pub fn packed_sum_product<InputCont, KeyCont, OutputCont, Scalar>(
    input_lwe_ciphertext_list_1: &LweCiphertextList<InputCont>,
    input_lwe_ciphertext_list_2: &LweCiphertextList<InputCont>,
    lwe_pubfpksk: &LwePublicFunctionalPackingKeyswitchKey<KeyCont>,
    relinearisation_key: &GlweRelinearisationKey<KeyCont>,
    scale: Scalar,
    output_lwe_ciphertext: &mut LweCiphertext<OutputCont>,
) where
    Scalar: UnsignedTorus + CastInto<u128> + CastFrom<u128>,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    let mut packed_glwe_1 =
        GlweCiphertext::new(Scalar::ZERO, 
            lwe_pubfpksk.output_glwe_size(), 
            lwe_pubfpksk.output_polynomial_size(), 
            lwe_pubfpksk.ciphertext_modulus());
    public_functional_keyswitch_lwe_ciphertexts_into_glwe_ciphertext(
        &lwe_pubfpksk,
        &mut packed_glwe_1,
        &input_lwe_ciphertext_list_1,
        | x: Vec<Scalar>| {
            let mut packed1: Vec<Scalar> = vec![Scalar::ZERO;lwe_pubfpksk.output_polynomial_size().0];
            x.iter().enumerate().for_each(|(iter,y)| packed1[iter] = *y);
            Polynomial::from_container(packed1)
            }
        );
    let mut packed_glwe_2 =
        GlweCiphertext::new(Scalar::ZERO,
            lwe_pubfpksk.output_glwe_size(), 
            lwe_pubfpksk.output_polynomial_size(), 
            lwe_pubfpksk.ciphertext_modulus());
    public_functional_keyswitch_lwe_ciphertexts_into_glwe_ciphertext(
        &lwe_pubfpksk,
        &mut packed_glwe_2,
        &input_lwe_ciphertext_list_2,
        | x| {
            let mut packed2: Vec<Scalar> = vec![Scalar::ZERO;lwe_pubfpksk.output_polynomial_size().0];
            x.iter().enumerate().for_each(|(iter,y)| 
                packed2[input_lwe_ciphertext_list_1.lwe_ciphertext_count().0-1-iter] = *y);
            Polynomial::from_container(packed2)
            },
        );
    let mut relin_glwe_ciphertext =
        GlweCiphertext::new(Scalar::ZERO, lwe_pubfpksk.output_glwe_size(), 
            lwe_pubfpksk.output_polynomial_size(), 
            lwe_pubfpksk.ciphertext_modulus());
    tensor_mult_with_relin(
        &packed_glwe_1,
        &packed_glwe_2,
        scale,
        &relinearisation_key,
        &mut relin_glwe_ciphertext,
        );
        
    extract_lwe_sample_from_glwe_ciphertext(&relin_glwe_ciphertext, 
        output_lwe_ciphertext, 
        MonomialDegree(input_lwe_ciphertext_list_1.lwe_ciphertext_count().0-1));
}

/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweTracePackingKeyswitchKey creation
/// let lwe_dimension = LweDimension(50);
/// let lwe_count = LweCiphertextCount(5);
/// let polynomial_size = PolynomialSize(64);
/// let glwe_dimension = GlweDimension(1);
/// let lwe_modular_std_dev = StandardDev(0.00000000000000000000000000000000000000001);
/// let ciphertext_modulus = CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap();
///
/// let mut seeder = new_seeder();
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
///
/// let mut glwe_secret_key = GlweSecretKey::new_empty_key(0u64, glwe_dimension, polynomial_size);
///
/// generate_tpksk_output_glwe_secret_key(&lwe_secret_key, &mut glwe_secret_key,
/// ciphertext_modulus);
///
/// let tp_decomp_base_log = DecompositionBaseLog(12);
/// let tp_decomp_level_count = DecompositionLevelCount(4);
/// let var_small = Variance::from_variance(2f64.powf(-120.0));
/// let relin_decomp_base_log = DecompositionBaseLog(12);
/// let relin_decomp_level_count = DecompositionLevelCount(4);
/// let glwe_modular_std_dev = StandardDev(0.00000000000000000000000000000000000029403601535432533);
/// let scale = (1u64 << 58) - (1u64 << 26);
///
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
///
/// let mut lwe_tpksk = LweTracePackingKeyswitchKey::new(
///     0u64,
///     tp_decomp_base_log,
///     tp_decomp_level_count,
///     lwe_dimension.to_lwe_size(),
///     glwe_dimension.to_glwe_size(),
///     polynomial_size,
///     ciphertext_modulus,
/// );
///
/// generate_lwe_trace_packing_keyswitch_key(
///     &glwe_secret_key,
///     &mut lwe_tpksk,
///     var_small,
///     &mut encryption_generator,
/// );
///
/// let glwe_relin_key = allocate_and_generate_glwe_relinearisation_key(
///     &glwe_secret_key,
///     relin_decomp_base_log,
///     relin_decomp_level_count,
///     glwe_modular_std_dev,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// let mut lwe_ctxt_list_1 = LweCiphertextList::new(
///     0u64,
///     lwe_dimension.to_lwe_size(),
///     lwe_count,
///     ciphertext_modulus,
/// );
///
/// let msg_1 = 1u64;
/// let plaintext_list_1 = PlaintextList::new(msg_1 * scale, PlaintextCount(lwe_count.0));
///
/// encrypt_lwe_ciphertext_list(
///     &lwe_secret_key,
///     &mut lwe_ctxt_list_1,
///     &plaintext_list_1,
///     lwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// let mut lwe_ctxt_list_2 = LweCiphertextList::new(
///     0u64,
///     lwe_dimension.to_lwe_size(),
///     lwe_count,
///     ciphertext_modulus,
/// );
///
/// let msg_2 = 2u64;
/// let plaintext_list_2 = PlaintextList::new(msg_2 * scale, PlaintextCount(lwe_count.0));
///
/// encrypt_lwe_ciphertext_list(
///     &lwe_secret_key,
///     &mut lwe_ctxt_list_2,
///     &plaintext_list_2,
///     lwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// let mut output_lwe_ciphertext = LweCiphertext::new(
///     0_u64,
///     LweDimension(glwe_dimension.0 * polynomial_size.0).to_lwe_size(),
///     ciphertext_modulus,
/// );
///
/// packed_sum_product_via_trace_packing(
///     &lwe_ctxt_list_1,
///     &lwe_ctxt_list_2,
///     &lwe_tpksk,
///     &glwe_relin_key,
///     scale,
///     &mut output_lwe_ciphertext,
/// );
///
/// // Round and remove encoding
/// // First create a decomposer working on the high 6 bits corresponding to our encoding.
/// let decomposer = SignedDecomposerNonNative::new(
///     DecompositionBaseLog(6),
///     DecompositionLevelCount(1),
///     ciphertext_modulus,
/// );
///
/// let output_lwe_secret_key = glwe_secret_key.into_lwe_secret_key();
///
/// let output_plaintext = decrypt_lwe_ciphertext(
///     &output_lwe_secret_key,
///     &output_lwe_ciphertext,
/// );
///
/// let rounded = decomposer.closest_representable(output_plaintext.0);
///
/// let cleartext = (rounded + (scale/2))/scale;
///
/// // Check we recovered the original message for each plaintext we encrypted
/// assert_eq!(cleartext, (msg_1 * msg_2 * lwe_count.0 as u64) % 64);
/// ```
pub fn packed_sum_product_via_trace_packing<InputCont, KeyCont, OutputCont, Scalar>(
    input_lwe_ciphertext_list_1: &LweCiphertextList<InputCont>,
    input_lwe_ciphertext_list_2: &LweCiphertextList<InputCont>,
    lwe_tpksk: &LweTracePackingKeyswitchKey<KeyCont>,
    relinearisation_key: &GlweRelinearisationKey<KeyCont>,
    scale: Scalar,
    output_lwe_ciphertext: &mut LweCiphertext<OutputCont>,
) where
    Scalar: UnsignedTorus + CastInto<u128> + CastFrom<u128>,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    let mut packed_glwe_1 =
        GlweCiphertext::new(Scalar::ZERO,
            lwe_tpksk.output_glwe_size(),
            lwe_tpksk.polynomial_size(),
            lwe_tpksk.ciphertext_modulus());
    let mut indices_1 = vec![0_usize; input_lwe_ciphertext_list_1.lwe_ciphertext_count().0];
    indices_1.iter_mut().enumerate().for_each(|(index, val)| *val = index);
    trace_packing_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext(
        &lwe_tpksk,
        &mut packed_glwe_1,
        &input_lwe_ciphertext_list_1,
        indices_1,
        );
    let mut packed_glwe_2 =
        GlweCiphertext::new(Scalar::ZERO,
            lwe_tpksk.output_glwe_size(),
            lwe_tpksk.polynomial_size(),
            lwe_tpksk.ciphertext_modulus());
    let mut indices_2 = vec![0_usize; input_lwe_ciphertext_list_2.lwe_ciphertext_count().0];
    indices_2.iter_mut().rev().enumerate().for_each(|(index, val)| *val = index);
    trace_packing_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext(
        &lwe_tpksk,
        &mut packed_glwe_2,
        &input_lwe_ciphertext_list_2,
        indices_2,
        );
    let mut relin_glwe_ciphertext =
        GlweCiphertext::new(Scalar::ZERO, lwe_tpksk.output_glwe_size(),
            lwe_tpksk.polynomial_size(),
            lwe_tpksk.ciphertext_modulus());
    tensor_mult_with_relin(
        &packed_glwe_1,
        &packed_glwe_2,
        scale,
        &relinearisation_key,
        &mut relin_glwe_ciphertext,
        );

    extract_lwe_sample_from_glwe_ciphertext(&relin_glwe_ciphertext,
        output_lwe_ciphertext,
        MonomialDegree(input_lwe_ciphertext_list_1.lwe_ciphertext_count().0-1));
}
