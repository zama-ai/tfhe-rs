use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::math::decomposition::{
    SignedDecomposer, SignedDecomposerNonNative,
};
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::*;

/// Converts a Scalar into a u128 via its signed value.
/// This is needed for the tensor product operation.
fn convert_scalar_to_u128<Scalar>(x: Scalar) -> u128
where
    Scalar: UnsignedInteger,
{
    let y = x.into_signed();
    if y < Scalar::Signed::ZERO {
        let neg_x = x.wrapping_neg();
        let neg_x_u128 = <Scalar as CastInto<u128>>::cast_into(neg_x);
        neg_x_u128.wrapping_neg()
    } else {
        <Scalar as CastInto<u128>>::cast_into(x)
    }
}

/// Converts a polynomial via the above function
fn convert_polynomial<Scalar, InputCont>(poly: &Polynomial<InputCont>) -> Polynomial<Vec<u128>>
where
    Scalar: UnsignedInteger,
    InputCont: Container<Element = Scalar>,
{
    Polynomial::from_container(
        poly.as_ref()
            .iter()
            .map(|&x| convert_scalar_to_u128(x))
            .collect::<Vec<_>>(),
    )
}

/// Converts a polynomial list via the above function
fn convert_polynomial_list<Scalar, InputCont>(
    poly_list: &PolynomialList<InputCont>,
) -> PolynomialList<Vec<u128>>
where
    Scalar: UnsignedInteger,
    InputCont: Container<Element = Scalar>,
{
    PolynomialList::from_container(
        poly_list
            .as_ref()
            .iter()
            .map(|&x| convert_scalar_to_u128(x))
            .collect::<Vec<_>>(),
        poly_list.polynomial_size(),
    )
}

/// Converts a Scalar into a u128 via its signed value
/// for a custom modulus.
/// This is needed for the tensor product operation.
fn convert_scalar_to_u128_custom_mod<Scalar>(
    x: Scalar,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    square_ct_mod: u128,
) -> u128
where
    Scalar: UnsignedInteger,
{
    let custom_modulus = ciphertext_modulus
        .get_custom_modulus_as_optional_scalar()
        .unwrap();
    let half_ct_mod = custom_modulus / Scalar::TWO;
    if x > half_ct_mod {
        let neg_x = x.wrapping_neg_custom_mod(custom_modulus);
        let neg_x_u128 = <Scalar as CastInto<u128>>::cast_into(neg_x);
        neg_x_u128.wrapping_neg_custom_mod(square_ct_mod)
    } else {
        <Scalar as CastInto<u128>>::cast_into(x)
    }
}

/// Converts a polynomial via the above function
fn convert_polynomial_custom_mod<Scalar, InputCont>(
    poly: &Polynomial<InputCont>,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    square_ct_mod: u128,
) -> Polynomial<Vec<u128>>
where
    Scalar: UnsignedInteger,
    InputCont: Container<Element = Scalar>,
{
    Polynomial::from_container(
        poly.as_ref()
            .iter()
            .map(|&x| convert_scalar_to_u128_custom_mod(x, ciphertext_modulus, square_ct_mod))
            .collect::<Vec<_>>(),
    )
}

/// Converts a polynomial list via the above function
fn convert_polynomial_list_custom_mod<Scalar, InputCont>(
    poly_list: &PolynomialList<InputCont>,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    square_ct_mod: u128,
) -> PolynomialList<Vec<u128>>
where
    Scalar: UnsignedInteger,
    InputCont: Container<Element = Scalar>,
{
    PolynomialList::from_container(
        poly_list
            .as_ref()
            .iter()
            .map(|&x| convert_scalar_to_u128_custom_mod(x, ciphertext_modulus, square_ct_mod))
            .collect::<Vec<_>>(),
        poly_list.polynomial_size(),
    )
}

/// Converts a u128 to a Scalar by dividing by scale while keeping its sign.
/// This is needed for the tensor product operation.
fn scale_down_u128_to_scalar<Scalar>(x: u128, scale: Scalar) -> Scalar
where
    Scalar: UnsignedInteger,
{
    let y = x as i128;
    let scale_u128 = <Scalar as CastInto<u128>>::cast_into(scale);
    if y < 0i128 {
        let neg_x = x.wrapping_neg();
        let neg_x_scaled = Scalar::cast_from((neg_x + (scale_u128 / 2)) / scale_u128);
        neg_x_scaled.wrapping_neg()
    } else {
        Scalar::cast_from((x + (scale_u128 / 2)) / scale_u128)
    }
}

/// Apply the above function to a polynomial component-wise.
fn scale_down_polynomial<Scalar, InputCont, OutputCont>(
    input_poly: &Polynomial<InputCont>,
    output_poly: &mut Polynomial<OutputCont>,
    scale: Scalar,
) where
    Scalar: UnsignedInteger,
    InputCont: Container<Element = u128>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    output_poly
        .as_mut()
        .iter_mut()
        .zip(input_poly.as_ref().iter())
        .for_each(|(dst, &src)| *dst = scale_down_u128_to_scalar(src, scale));
}

/// Converts a u128 to a Scalar by dividing by scale while keeping its sign
/// for a custom modulus.
/// This is needed for the tensor product operation.
fn scale_down_u128_to_scalar_custom_mod<Scalar>(
    x: u128,
    scale: Scalar,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    square_ct_mod: u128,
) -> Scalar
where
    Scalar: UnsignedInteger,
{
    let custom_modulus = ciphertext_modulus
        .get_custom_modulus_as_optional_scalar()
        .unwrap();
    let custom_mod_u128 = <Scalar as CastInto<u128>>::cast_into(custom_modulus);
    let half_square_ct_mod = square_ct_mod / 2u128;
    let scale_u128 = <Scalar as CastInto<u128>>::cast_into(scale);
    if x > half_square_ct_mod {
        let neg_x = x.wrapping_neg_custom_mod(square_ct_mod);
        let neg_x_scaled = (neg_x + (scale_u128 / 2)) / scale_u128;
        let neg_x_scaled_and_reduced = neg_x_scaled.wrapping_rem(custom_mod_u128);
        Scalar::cast_from(neg_x_scaled_and_reduced).wrapping_neg_custom_mod(custom_modulus)
    } else {
        let x_scaled = (x + (scale_u128 / 2)) / scale_u128;
        let x_scaled_and_reduced = x_scaled.wrapping_rem(custom_mod_u128);
        Scalar::cast_from(x_scaled_and_reduced)
    }
}

/// Apply the above function to a polynomial component-wise.
fn scale_down_polynomial_custom_mod<Scalar, InputCont, OutputCont>(
    input_poly: &Polynomial<InputCont>,
    output_poly: &mut Polynomial<OutputCont>,
    scale: Scalar,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    square_ct_mod: u128,
) where
    Scalar: UnsignedInteger,
    InputCont: Container<Element = u128>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    output_poly
        .as_mut()
        .iter_mut()
        .zip(input_poly.as_ref().iter())
        .for_each(|(dst, &src)| {
            *dst =
                scale_down_u128_to_scalar_custom_mod(src, scale, ciphertext_modulus, square_ct_mod)
        });
}

/// Attempts to compute a product between u128s with a custom modulus that is also a u128.
/// This works only because the inputs are "small".
/// Further, the assumption is that the inputs are signed.
/// This product is used in the tensor product operation.
fn wrapping_mul_custom_mod_u128(lhs: u128, rhs: u128, custom_modulus: u128) -> u128 {
    let half_custom_mod = custom_modulus / 2;
    let lhs_neg = lhs > half_custom_mod;
    let abs_lhs = if lhs_neg {
        lhs.wrapping_neg_custom_mod(custom_modulus)
    } else {
        lhs
    };
    let rhs_neg = rhs > half_custom_mod;
    let abs_rhs = if rhs_neg {
        rhs.wrapping_neg_custom_mod(custom_modulus)
    } else {
        rhs
    };
    let prod_neg = lhs_neg ^ rhs_neg;
    let (mut abs_prod, err) = abs_lhs.overflowing_mul(abs_rhs);
    if err {
        // The assumption here is that abs_lhs * abs_rhs are not much larger than 2**64.
        // Thus the product is (a + b*2^64)*(c + d*2^64) = ac + (bc + ad)*2^64 + bd*2^128
        // where b and d and thus bd is very small.
        // Further set bc + ad = e + f*2^64 where f should be small if b and d are.
        // Then the product is ac + e*2^64 + (bd + f)*2^128
        // with (bd + f) small
        // Write 2^128 = r modulo the custom modulus so that the product is
        // ac + e*2^64 + (bd + f)*r   for a small signed r
        // This can be computed without wrapping around modulo 2^128 if
        // (bd + f)*|r| < 2^128 otherwise there is an error
        // There should be no error if the modulus is not close to 2^128 or is equal to
        // 2^128 - r with r not close to 2^128
        let b = abs_lhs >> 64;
        let d = abs_rhs >> 64;
        let a = abs_lhs - (b << 64);
        let c = abs_rhs - (d << 64);
        let ac = a.wrapping_mul(c); // this is the first term
        let ad = a.wrapping_mul(d);
        let bc = b.wrapping_mul(c);
        let (bcpad, err) = bc.overflowing_add(ad);
        assert!(!err, "multiplication of custom u128s failed: {lhs}, {rhs}",);
        let f = bcpad >> 64;
        let e = bcpad - (f << 64);
        let middle_term = (e << 64).wrapping_rem(custom_modulus);
        let r = u128::MAX.wrapping_rem(custom_modulus).wrapping_add(1u128);
        let neg_r = r > half_custom_mod;
        let abs_r = if neg_r { r.wrapping_neg() } else { r };
        let bd = b.wrapping_mul(d);
        let (bdpf, err) = bd.overflowing_add(f);
        assert!(!err, "multiplication of custom u128s failed: {lhs}, {rhs}",);
        let (bdpfr, err) = bdpf.overflowing_mul(abs_r);
        assert!(!err, "multiplication of custom u128s failed: {lhs}, {rhs}",);
        let last_term = bdpfr.wrapping_rem(custom_modulus);
        if neg_r {
            abs_prod = ac
                .wrapping_add_custom_mod(middle_term, custom_modulus)
                .wrapping_sub_custom_mod(last_term, custom_modulus);
        } else {
            abs_prod = ac
                .wrapping_add_custom_mod(middle_term, custom_modulus)
                .wrapping_add_custom_mod(last_term, custom_modulus);
        }
    } else {
        abs_prod = abs_prod.wrapping_rem(custom_modulus);
    }
    let mut prod = abs_prod;
    if prod_neg {
        prod = prod.wrapping_neg_custom_mod(custom_modulus);
    }
    prod
}

// What follows is a copy of the polynomial multiplication algorithms updated to use the
// above product specialised to a custom u128 modulus.

fn polynomial_karatsuba_wrapping_mul_custom_mod_u128<OutputCont, LhsCont, RhsCont>(
    output: &mut Polynomial<OutputCont>,
    p: &Polynomial<LhsCont>,
    q: &Polynomial<RhsCont>,
    custom_modulus: u128,
) where
    OutputCont: ContainerMut<Element = u128>,
    LhsCont: Container<Element = u128>,
    RhsCont: Container<Element = u128>,
{
    // check same dimensions
    assert!(
        output.polynomial_size() == p.polynomial_size(),
        "Output polynomial size {:?} is not the same as input lhs polynomial {:?}.",
        output.polynomial_size(),
        p.polynomial_size(),
    );
    assert!(
        output.polynomial_size() == q.polynomial_size(),
        "Output polynomial size {:?} is not the same as input rhs polynomial {:?}.",
        output.polynomial_size(),
        q.polynomial_size(),
    );

    let poly_size = output.polynomial_size().0;

    // check dimensions are a power of 2
    assert!(poly_size.is_power_of_two());

    // allocate slices for the rec
    let mut a0 = vec![0u128; poly_size];
    let mut a1 = vec![0u128; poly_size];
    let mut a2 = vec![0u128; poly_size];
    let mut input_a2_p = vec![0u128; poly_size / 2];
    let mut input_a2_q = vec![0u128; poly_size / 2];

    // prepare for splitting
    let bottom = 0..(poly_size / 2);
    let top = (poly_size / 2)..poly_size;

    // induction
    induction_karatsuba_custom_mod_u128(
        &mut a0,
        &p[bottom.clone()],
        &q[bottom.clone()],
        custom_modulus,
    );
    induction_karatsuba_custom_mod_u128(&mut a1, &p[top.clone()], &q[top.clone()], custom_modulus);
    slice_wrapping_add_custom_mod(
        &mut input_a2_p,
        &p[bottom.clone()],
        &p[top.clone()],
        custom_modulus,
    );
    slice_wrapping_add_custom_mod(
        &mut input_a2_q,
        &q[bottom.clone()],
        &q[top.clone()],
        custom_modulus,
    );
    induction_karatsuba_custom_mod_u128(&mut a2, &input_a2_p, &input_a2_q, custom_modulus);

    // rebuild the result
    let output: &mut [u128] = output.as_mut();
    slice_wrapping_sub_custom_mod(output, &a0, &a1, custom_modulus);
    slice_wrapping_sub_assign_custom_mod(
        &mut output[bottom.clone()],
        &a2[top.clone()],
        custom_modulus,
    );
    slice_wrapping_add_assign_custom_mod(
        &mut output[bottom.clone()],
        &a0[top.clone()],
        custom_modulus,
    );
    slice_wrapping_add_assign_custom_mod(
        &mut output[bottom.clone()],
        &a1[top.clone()],
        custom_modulus,
    );
    slice_wrapping_add_assign_custom_mod(
        &mut output[top.clone()],
        &a2[bottom.clone()],
        custom_modulus,
    );
    slice_wrapping_sub_assign_custom_mod(
        &mut output[top.clone()],
        &a0[bottom.clone()],
        custom_modulus,
    );
    slice_wrapping_sub_assign_custom_mod(&mut output[top], &a1[bottom], custom_modulus);
}

const KARATUSBA_STOP: usize = 64;
fn induction_karatsuba_custom_mod_u128(
    res: &mut [u128],
    p: &[u128],
    q: &[u128],
    custom_modulus: u128,
) {
    // stop the induction when polynomials have KARATUSBA_STOP elements
    if p.len() <= KARATUSBA_STOP {
        // schoolbook algorithm
        for (lhs_degree, &lhs_elt) in p.iter().enumerate() {
            let res = &mut res[lhs_degree..];
            for (&rhs_elt, res) in q.iter().zip(res) {
                *res = (*res).wrapping_add_custom_mod(
                    wrapping_mul_custom_mod_u128(lhs_elt, rhs_elt, custom_modulus),
                    custom_modulus,
                )
            }
        }
    } else {
        let poly_size = res.len();

        // allocate slices for the rec
        let mut a0 = vec![0u128; poly_size / 2];
        let mut a1 = vec![0u128; poly_size / 2];
        let mut a2 = vec![0u128; poly_size / 2];
        let mut input_a2_p = vec![0u128; poly_size / 4];
        let mut input_a2_q = vec![0u128; poly_size / 4];

        // prepare for splitting
        let bottom = 0..(poly_size / 4);
        let top = (poly_size / 4)..(poly_size / 2);

        // rec
        induction_karatsuba_custom_mod_u128(
            &mut a0,
            &p[bottom.clone()],
            &q[bottom.clone()],
            custom_modulus,
        );
        induction_karatsuba_custom_mod_u128(
            &mut a1,
            &p[top.clone()],
            &q[top.clone()],
            custom_modulus,
        );
        slice_wrapping_add_custom_mod(
            &mut input_a2_p,
            &p[bottom.clone()],
            &p[top.clone()],
            custom_modulus,
        );
        slice_wrapping_add_custom_mod(&mut input_a2_q, &q[bottom], &q[top], custom_modulus);
        induction_karatsuba_custom_mod_u128(&mut a2, &input_a2_p, &input_a2_q, custom_modulus);

        // rebuild the result
        slice_wrapping_sub_custom_mod(
            &mut res[(poly_size / 4)..(3 * poly_size / 4)],
            &a2,
            &a0,
            custom_modulus,
        );
        slice_wrapping_sub_assign_custom_mod(
            &mut res[(poly_size / 4)..(3 * poly_size / 4)],
            &a1,
            custom_modulus,
        );
        slice_wrapping_add_assign_custom_mod(&mut res[0..(poly_size / 2)], &a0, custom_modulus);
        slice_wrapping_add_assign_custom_mod(
            &mut res[(poly_size / 2)..poly_size],
            &a1,
            custom_modulus,
        );
    }
}

fn polynomial_wrapping_add_mul_schoolbook_assign_custom_mod_u128<
    OutputCont,
    InputCont1,
    InputCont2,
>(
    output: &mut Polynomial<OutputCont>,
    lhs: &Polynomial<InputCont1>,
    rhs: &Polynomial<InputCont2>,
    custom_modulus: u128,
) where
    OutputCont: ContainerMut<Element = u128>,
    InputCont1: Container<Element = u128>,
    InputCont2: Container<Element = u128>,
{
    fn implementation(
        mut output: Polynomial<&mut [u128]>,
        lhs: Polynomial<&[u128]>,
        rhs: Polynomial<&[u128]>,
        custom_modulus: u128,
    ) {
        let polynomial_size = output.polynomial_size();
        let degree = output.degree();
        for (lhs_degree, &lhs_coeff) in lhs.iter().enumerate() {
            for (rhs_degree, &rhs_coeff) in rhs.iter().enumerate() {
                let target_degree = lhs_degree + rhs_degree;
                if target_degree <= degree {
                    let output_coefficient = &mut output.as_mut()[target_degree];

                    *output_coefficient = (*output_coefficient).wrapping_add_custom_mod(
                        wrapping_mul_custom_mod_u128(lhs_coeff, rhs_coeff, custom_modulus),
                        custom_modulus,
                    );
                } else {
                    let target_degree = target_degree % polynomial_size.0;
                    let output_coefficient = &mut output.as_mut()[target_degree];

                    *output_coefficient = (*output_coefficient).wrapping_sub_custom_mod(
                        wrapping_mul_custom_mod_u128(lhs_coeff, rhs_coeff, custom_modulus),
                        custom_modulus,
                    );
                }
            }
        }
    }
    implementation(
        output.as_mut_view(),
        lhs.as_view(),
        rhs.as_view(),
        custom_modulus,
    );
}

fn polynomial_wrapping_add_mul_assign_custom_mod_u128<OutputCont, InputCont1, InputCont2>(
    output: &mut Polynomial<OutputCont>,
    lhs: &Polynomial<InputCont1>,
    rhs: &Polynomial<InputCont2>,
    custom_modulus: u128,
) where
    OutputCont: ContainerMut<Element = u128>,
    InputCont1: Container<Element = u128>,
    InputCont2: Container<Element = u128>,
{
    assert!(
        output.polynomial_size() == lhs.polynomial_size(),
        "Output polynomial size {:?} is not the same as input lhs polynomial {:?}.",
        output.polynomial_size(),
        lhs.polynomial_size(),
    );
    assert!(
        output.polynomial_size() == rhs.polynomial_size(),
        "Output polynomial size {:?} is not the same as input rhs polynomial {:?}.",
        output.polynomial_size(),
        rhs.polynomial_size(),
    );

    let polynomial_size = output.polynomial_size();

    if polynomial_size.0.is_power_of_two() && polynomial_size.0 > KARATUSBA_STOP {
        let mut tmp = Polynomial::new(0u128, polynomial_size);

        polynomial_karatsuba_wrapping_mul_custom_mod_u128(&mut tmp, lhs, rhs, custom_modulus);
        polynomial_wrapping_add_assign_custom_mod(output, &tmp, custom_modulus);
    } else {
        polynomial_wrapping_add_mul_schoolbook_assign_custom_mod_u128(
            output,
            lhs,
            rhs,
            custom_modulus,
        )
    }
}

/// Compute the tensor product of the left-hand side [`GLWE ciphertext`](`GlweCiphertext`) with the
/// right-hand side [`GLWE ciphertext`](`GlweCiphertext`)
/// writing the result in the output [`GlweCiphertext<Vec<Scalar>>`](`GlweCiphertext<Vec<Scalar>>`).
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::algorithms::polynomial_algorithms::*;
/// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposerNonNative;
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GlweCiphertext creation
/// let glwe_size = GlweSize(3);
/// let polynomial_size = PolynomialSize(256);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let decomp_base_log = DecompositionBaseLog(21);
/// let decomp_level_count = DecompositionLevelCount(2);
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
///     glwe_noise_distribution,
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
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// // Create the output GlweCiphertext
/// let tensor_glwe_dim = GlweDimension((glwe_size.0 - 1) * (glwe_size.0 + 2) / 2);
/// let mut tensor_output = GlweCiphertext::new(
///     0u64,
///     tensor_glwe_dim.to_glwe_size(),
///     polynomial_size,
///     ciphertext_modulus,
/// );
///
/// // Perform the tensor product
/// glwe_tensor_product(&glwe_1, &glwe_2, &mut tensor_output, delta);
///
/// // Compute the tensor product key
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
///     polynomial_wrapping_add_assign_custom_mod(
///         &mut key_pol,
///         &glwe_secret_key.as_polynomial_list().get(i),
///         ciphertext_modulus.get_custom_modulus().cast_into(),
///     );
/// }
///
/// let tensor_key = GlweSecretKey::from_container(tensor_key_poly_list.as_ref(), polynomial_size);
///
/// // Decrypt the tensor product ciphertext
/// let mut output_plaintext = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
///
/// decrypt_glwe_ciphertext(&tensor_key, &tensor_output, &mut output_plaintext);
///
/// // Get the raw vector
/// let mut cleartext = output_plaintext.into_container();
/// // Remove the encoding
/// cleartext
///     .iter_mut()
///     .for_each(|elt| *elt = decomposer.decode_plaintext(*elt));
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
///         *dest =
///             u64::cast_from(source / <u64 as CastInto<u128>>::cast_into(delta)) / output_delta
///     });
///
/// // Check we recovered the correct message
/// cleartext
///     .iter()
///     .zip(scaled_product.iter())
///     .for_each(|(&elt, coeff)| assert_eq!(elt, *coeff));
///
/// let glwe_relin_key = allocate_and_generate_glwe_relinearization_key(
///     &glwe_secret_key,
///     decomp_base_log,
///     decomp_level_count,
///     glwe_noise_distribution,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// let mut output_glwe_ciphertext =
///     GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
///
/// glwe_relinearization(&tensor_output, &glwe_relin_key, &mut output_glwe_ciphertext);
///
/// // Decrypt the output glwe ciphertext
/// let mut output_plaintext = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
///
/// decrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &output_glwe_ciphertext,
///     &mut output_plaintext,
/// );
///
/// // Get the raw vector
/// let mut cleartext = output_plaintext.into_container();
/// // Remove the encoding
/// cleartext
///     .iter_mut()
///     .for_each(|elt| *elt = decomposer.decode_plaintext(*elt));
/// // Get the list immutably
/// let cleartext = cleartext;
///
/// // Check we recovered the correct message
/// cleartext
///     .iter()
///     .zip(scaled_product.iter())
///     .for_each(|(&elt, coeff)| assert_eq!(elt, *coeff));
/// ```
/// based on algorithm 1 of `<https://eprint.iacr.org/2021/729.pdf>`
pub fn glwe_tensor_product<Scalar, LhsCont, RhsCont, OutputCont>(
    input_glwe_ciphertext_lhs: &GlweCiphertext<LhsCont>,
    input_glwe_ciphertext_rhs: &GlweCiphertext<RhsCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
    scale: Scalar,
) where
    Scalar: UnsignedInteger,
    LhsCont: Container<Element = Scalar>,
    RhsCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        Scalar::BITS <= 64,
        "The tensor product is not implemented for bit-widths larger than 64."
    );

    assert_eq!(
        input_glwe_ciphertext_lhs.ciphertext_modulus(),
        input_glwe_ciphertext_rhs.ciphertext_modulus(),
        "Mismatched moduli between lhs ({:?}) and rhs ({:?}) GlweCiphertext",
        input_glwe_ciphertext_lhs.ciphertext_modulus(),
        input_glwe_ciphertext_rhs.ciphertext_modulus()
    );

    assert_eq!(
        input_glwe_ciphertext_lhs.ciphertext_modulus(),
        output_glwe_ciphertext.ciphertext_modulus(),
        "Mismatched moduli between input ({:?}) and output ({:?}) GlweCiphertext",
        input_glwe_ciphertext_lhs.ciphertext_modulus(),
        output_glwe_ciphertext.ciphertext_modulus()
    );

    let ciphertext_modulus = input_glwe_ciphertext_lhs.ciphertext_modulus();

    if ciphertext_modulus.is_compatible_with_native_modulus() {
        glwe_tensor_product_native_mod_compatible(
            input_glwe_ciphertext_lhs,
            input_glwe_ciphertext_rhs,
            output_glwe_ciphertext,
            scale,
        )
    } else {
        glwe_tensor_product_other_mod(
            input_glwe_ciphertext_lhs,
            input_glwe_ciphertext_rhs,
            output_glwe_ciphertext,
            scale,
        )
    }
}

pub fn glwe_tensor_product_native_mod_compatible<Scalar, LhsCont, RhsCont, OutputCont>(
    input_glwe_ciphertext_lhs: &GlweCiphertext<LhsCont>,
    input_glwe_ciphertext_rhs: &GlweCiphertext<RhsCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
    scale: Scalar,
) where
    Scalar: UnsignedInteger,
    LhsCont: Container<Element = Scalar>,
    RhsCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        input_glwe_ciphertext_lhs.polynomial_size().0
            == input_glwe_ciphertext_rhs.polynomial_size().0,
        "The input glwe ciphertexts do not have the same polynomial size. The polynomial size of \
        the lhs is {}, while for the rhs it is {}.",
        input_glwe_ciphertext_lhs.polynomial_size().0,
        input_glwe_ciphertext_rhs.polynomial_size().0,
    );

    assert!(
        input_glwe_ciphertext_lhs.polynomial_size().0
            == output_glwe_ciphertext.polynomial_size().0,
        "The input glwe ciphertexts do not have the same polynomial size as the output glwe ciphertext. \
        The polynomial size of the inputs is {}, while for the output it is {}.",
        input_glwe_ciphertext_lhs.polynomial_size().0,
        output_glwe_ciphertext.polynomial_size().0,
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

    assert!(
        output_glwe_ciphertext.glwe_size().to_glwe_dimension().0 == new_k.0,
        "The output glwe ciphertext does not have the correct glwe dimension. The dimension dictated by \
        the inputs is {}, while for the given output it is {}.",
        new_k.0,
        output_glwe_ciphertext.glwe_size().to_glwe_dimension().0,
    );

    let input_ciphertext_modulus = input_glwe_ciphertext_lhs.ciphertext_modulus();

    assert!(
        input_ciphertext_modulus.is_compatible_with_native_modulus(),
        "This operation currently only supports power of 2 moduli"
    );

    let mut output_mask = output_glwe_ciphertext.get_mut_mask();
    let mut output_mask_poly_list = output_mask.as_mut_polynomial_list();
    let mut iter_output_mask = output_mask_poly_list.iter_mut();

    let a_lhs = convert_polynomial_list(&input_glwe_ciphertext_lhs.get_mask().as_polynomial_list());
    let a_rhs = convert_polynomial_list(&input_glwe_ciphertext_rhs.get_mask().as_polynomial_list());

    let b_lhs = convert_polynomial(&input_glwe_ciphertext_lhs.get_body().as_polynomial());
    let b_rhs = convert_polynomial(&input_glwe_ciphertext_rhs.get_body().as_polynomial());

    for (i, a_lhs_i) in a_lhs.iter().enumerate() {
        for (j, a_rhs_j) in a_rhs.iter().enumerate() {
            if i == j {
                //tensor elements corresponding to key -s_i^2
                let mut temp_poly_sq = Polynomial::new(0u128, a_lhs_i.polynomial_size());
                polynomial_wrapping_add_mul_assign(&mut temp_poly_sq, &a_lhs_i, &a_rhs_j);

                let mut output_poly_sq = iter_output_mask.next().unwrap();
                scale_down_polynomial(&temp_poly_sq, &mut output_poly_sq, scale);

                //tensor elements corresponding to key s_i
                let mut temp_poly_s = Polynomial::new(0u128, a_lhs_i.polynomial_size());
                polynomial_wrapping_add_mul_assign(&mut temp_poly_s, &a_lhs_i, &b_rhs);
                polynomial_wrapping_add_mul_assign(&mut temp_poly_s, &b_lhs, &a_rhs_j);

                let mut output_poly_s = iter_output_mask.next().unwrap();
                scale_down_polynomial(&temp_poly_s, &mut output_poly_s, scale);
            } else {
                //when i and j are different we only compute the terms where j < i
                if j < i {
                    //tensor element corresponding to key -s_i*s_j
                    let mut temp_poly = Polynomial::new(0u128, a_lhs_i.polynomial_size());
                    polynomial_wrapping_add_mul_assign(&mut temp_poly, &a_lhs_i, &a_rhs_j);
                    polynomial_wrapping_add_mul_assign(
                        &mut temp_poly,
                        &a_lhs.get(j),
                        &a_rhs.get(i),
                    );

                    let mut output_poly = iter_output_mask.next().unwrap();
                    scale_down_polynomial(&temp_poly, &mut output_poly, scale);
                }
            }
        }
    }

    //tensor element corresponding to the body
    let mut temp_poly_body = Polynomial::new(0u128, input_glwe_ciphertext_lhs.polynomial_size());
    polynomial_wrapping_add_mul_assign(&mut temp_poly_body, &b_lhs, &b_rhs);
    let mut output_body = output_glwe_ciphertext.get_mut_body();
    let mut output_poly_body = output_body.as_mut_polynomial();
    scale_down_polynomial(&temp_poly_body, &mut output_poly_body, scale);
}

pub fn glwe_tensor_product_other_mod<Scalar, LhsCont, RhsCont, OutputCont>(
    input_glwe_ciphertext_lhs: &GlweCiphertext<LhsCont>,
    input_glwe_ciphertext_rhs: &GlweCiphertext<RhsCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
    scale: Scalar,
) where
    Scalar: UnsignedInteger,
    LhsCont: Container<Element = Scalar>,
    RhsCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
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
        input_glwe_ciphertext_lhs.polynomial_size().0
            == output_glwe_ciphertext.polynomial_size().0,
        "The input glwe ciphertexts do not have the same polynomial size as the output glwe ciphertext. \
        The polynomial size of the inputs is {}, while for the output it is {}.",
        input_glwe_ciphertext_lhs.polynomial_size().0,
        output_glwe_ciphertext.polynomial_size().0,
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

    assert!(
        output_glwe_ciphertext.glwe_size().to_glwe_dimension().0 == new_k.0,
        "The output glwe ciphertext does not have the correct glwe dimension. The dimension dictated by \
        the inputs is {}, while for the given output it is {}.",
        new_k.0,
        output_glwe_ciphertext.glwe_size().to_glwe_dimension().0,
    );

    let ciphertext_modulus = input_glwe_ciphertext_lhs.ciphertext_modulus();
    let square_ct_mod = ciphertext_modulus.get_custom_modulus().pow(2);

    assert!(
        !ciphertext_modulus.is_compatible_with_native_modulus(),
        "This operation currently only supports non power of 2 moduli"
    );

    let mut output_mask = output_glwe_ciphertext.get_mut_mask();
    let mut output_mask_poly_list = output_mask.as_mut_polynomial_list();
    let mut iter_output_mask = output_mask_poly_list.iter_mut();

    let a_lhs = convert_polynomial_list_custom_mod(
        &input_glwe_ciphertext_lhs.get_mask().as_polynomial_list(),
        ciphertext_modulus,
        square_ct_mod,
    );
    let a_rhs = convert_polynomial_list_custom_mod(
        &input_glwe_ciphertext_rhs.get_mask().as_polynomial_list(),
        ciphertext_modulus,
        square_ct_mod,
    );

    let b_lhs = convert_polynomial_custom_mod(
        &input_glwe_ciphertext_lhs.get_body().as_polynomial(),
        ciphertext_modulus,
        square_ct_mod,
    );
    let b_rhs = convert_polynomial_custom_mod(
        &input_glwe_ciphertext_rhs.get_body().as_polynomial(),
        ciphertext_modulus,
        square_ct_mod,
    );

    for (i, a_lhs_i) in a_lhs.iter().enumerate() {
        for (j, a_rhs_j) in a_rhs.iter().enumerate() {
            if i == j {
                //tensor elements corresponding to key -s_i^2
                let mut temp_poly_sq = Polynomial::new(0u128, a_lhs_i.polynomial_size());
                polynomial_wrapping_add_mul_assign_custom_mod_u128(
                    &mut temp_poly_sq,
                    &a_lhs_i,
                    &a_rhs_j,
                    square_ct_mod,
                );

                let mut output_poly_sq = iter_output_mask.next().unwrap();
                scale_down_polynomial_custom_mod(
                    &temp_poly_sq,
                    &mut output_poly_sq,
                    scale,
                    ciphertext_modulus,
                    square_ct_mod,
                );

                //tensor elements corresponding to key s_i
                let mut temp_poly_s = Polynomial::new(0u128, a_lhs_i.polynomial_size());
                polynomial_wrapping_add_mul_assign_custom_mod_u128(
                    &mut temp_poly_s,
                    &a_lhs_i,
                    &b_rhs,
                    square_ct_mod,
                );
                polynomial_wrapping_add_mul_assign_custom_mod_u128(
                    &mut temp_poly_s,
                    &b_lhs,
                    &a_rhs_j,
                    square_ct_mod,
                );

                let mut output_poly_s = iter_output_mask.next().unwrap();
                scale_down_polynomial_custom_mod(
                    &temp_poly_s,
                    &mut output_poly_s,
                    scale,
                    ciphertext_modulus,
                    square_ct_mod,
                );
            } else {
                //when i and j are different we only compute the terms where j < i
                if j < i {
                    //tensor element corresponding to key -s_i*s_j
                    let mut temp_poly = Polynomial::new(0u128, a_lhs_i.polynomial_size());
                    polynomial_wrapping_add_mul_assign_custom_mod_u128(
                        &mut temp_poly,
                        &a_lhs_i,
                        &a_rhs_j,
                        square_ct_mod,
                    );
                    polynomial_wrapping_add_mul_assign_custom_mod_u128(
                        &mut temp_poly,
                        &a_lhs.get(j),
                        &a_rhs.get(i),
                        square_ct_mod,
                    );

                    let mut output_poly = iter_output_mask.next().unwrap();
                    scale_down_polynomial_custom_mod(
                        &temp_poly,
                        &mut output_poly,
                        scale,
                        ciphertext_modulus,
                        square_ct_mod,
                    );
                }
            }
        }
    }

    //tensor element corresponding to the body
    let mut temp_poly_body = Polynomial::new(0u128, input_glwe_ciphertext_lhs.polynomial_size());
    polynomial_wrapping_add_mul_assign_custom_mod_u128(
        &mut temp_poly_body,
        &b_lhs,
        &b_rhs,
        square_ct_mod,
    );
    let mut output_body = output_glwe_ciphertext.get_mut_body();
    let mut output_poly_body = output_body.as_mut_polynomial();
    scale_down_polynomial_custom_mod(
        &temp_poly_body,
        &mut output_poly_body,
        scale,
        ciphertext_modulus,
        square_ct_mod,
    );
}

/// Relinearize the [`GLWE ciphertext`](`GlweCiphertext`) that is output by the
/// glwe_tensor_product operation using a [`GLWE relinearization key`](`GlweRelinearizationKey`).
pub fn glwe_relinearization<Scalar, InputCont, KeyCont, OutputCont>(
    input_glwe_ciphertext: &GlweCiphertext<InputCont>,
    relinearization_key: &GlweRelinearizationKey<KeyCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
) where
    Scalar: UnsignedInteger,
    InputCont: Container<Element = Scalar>,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert_eq!(
        input_glwe_ciphertext.ciphertext_modulus(),
        relinearization_key.ciphertext_modulus(),
    );
    assert_eq!(
        input_glwe_ciphertext.ciphertext_modulus(),
        output_glwe_ciphertext.ciphertext_modulus(),
    );

    let ciphertext_modulus = input_glwe_ciphertext.ciphertext_modulus();

    if ciphertext_modulus.is_compatible_with_native_modulus() {
        glwe_relinearization_native_mod_compatible(
            input_glwe_ciphertext,
            relinearization_key,
            output_glwe_ciphertext,
        )
    } else {
        glwe_relinearization_other_mod(
            input_glwe_ciphertext,
            relinearization_key,
            output_glwe_ciphertext,
        )
    }
}

pub fn glwe_relinearization_native_mod_compatible<Scalar, InputCont, KeyCont, OutputCont>(
    input_glwe_ciphertext: &GlweCiphertext<InputCont>,
    relinearization_key: &GlweRelinearizationKey<KeyCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
) where
    Scalar: UnsignedInteger,
    InputCont: Container<Element = Scalar>,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert_eq!(
        relinearization_key.glwe_dimension().0 * (relinearization_key.glwe_dimension().0 + 3) / 2,
        input_glwe_ciphertext.glwe_size().to_glwe_dimension().0
    );
    assert_eq!(
        relinearization_key.glwe_size(),
        output_glwe_ciphertext.glwe_size()
    );
    assert_eq!(
        relinearization_key.polynomial_size(),
        input_glwe_ciphertext.polynomial_size()
    );
    assert_eq!(
        relinearization_key.polynomial_size(),
        output_glwe_ciphertext.polynomial_size()
    );
    assert!(relinearization_key
        .ciphertext_modulus()
        .is_compatible_with_native_modulus());

    // Clear the output ciphertext, as it will get updated gradually
    output_glwe_ciphertext.as_mut().fill(Scalar::ZERO);

    // Copy the input body to the output ciphertext
    polynomial_wrapping_add_assign(
        &mut output_glwe_ciphertext.get_mut_body().as_mut_polynomial(),
        &input_glwe_ciphertext.get_body().as_polynomial(),
    );

    // We instantiate a decomposer
    let decomposer = SignedDecomposer::new(
        relinearization_key.decomposition_base_log(),
        relinearization_key.decomposition_level_count(),
    );

    let mut relin_key_iter = relinearization_key.iter();
    let input_glwe_mask = input_glwe_ciphertext.get_mask();
    let input_glwe_mask_poly_list = input_glwe_mask.as_polynomial_list();
    let mut input_poly_iter = input_glwe_mask_poly_list.iter();

    for i in 0..relinearization_key.glwe_size().0 - 1 {
        for _ in 0..i + 1 {
            let ksk = relin_key_iter.next().unwrap();
            let pol = input_poly_iter.next().unwrap();
            let mut decomposition_iter = decomposer.decompose_slice(pol.as_ref());
            // loop over the number of levels
            for level_key_ciphertext in ksk.iter() {
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

pub fn glwe_relinearization_other_mod<Scalar, InputCont, KeyCont, OutputCont>(
    input_glwe_ciphertext: &GlweCiphertext<InputCont>,
    relinearization_key: &GlweRelinearizationKey<KeyCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
) where
    Scalar: UnsignedInteger,
    InputCont: Container<Element = Scalar>,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert_eq!(
        relinearization_key.glwe_dimension().0 * (relinearization_key.glwe_dimension().0 + 3) / 2,
        input_glwe_ciphertext.glwe_size().to_glwe_dimension().0
    );
    assert_eq!(
        relinearization_key.glwe_size(),
        output_glwe_ciphertext.glwe_size()
    );
    assert_eq!(
        relinearization_key.polynomial_size(),
        input_glwe_ciphertext.polynomial_size()
    );
    assert_eq!(
        relinearization_key.polynomial_size(),
        output_glwe_ciphertext.polynomial_size()
    );

    let ciphertext_modulus = input_glwe_ciphertext.ciphertext_modulus();

    assert!(
        !ciphertext_modulus.is_compatible_with_native_modulus(),
        "This operation currently only supports non power of 2 moduli"
    );

    // Clear the output ciphertext, as it will get updated gradually
    output_glwe_ciphertext.as_mut().fill(Scalar::ZERO);

    // Copy the input body to the output ciphertext (no need to use non native addition here)
    polynomial_wrapping_add_assign(
        &mut output_glwe_ciphertext.get_mut_body().as_mut_polynomial(),
        &input_glwe_ciphertext.get_body().as_polynomial(),
    );

    // We instantiate a decomposer
    let decomposer = SignedDecomposerNonNative::new(
        relinearization_key.decomposition_base_log(),
        relinearization_key.decomposition_level_count(),
        ciphertext_modulus,
    );

    let mut relin_key_iter = relinearization_key.iter();
    let input_glwe_mask = input_glwe_ciphertext.get_mask();
    let input_glwe_mask_poly_list = input_glwe_mask.as_polynomial_list();
    let mut input_poly_iter = input_glwe_mask_poly_list.iter();
    let mut scalar_poly = Polynomial::new(Scalar::ZERO, input_glwe_ciphertext.polynomial_size());

    for i in 0..relinearization_key.glwe_size().0 - 1 {
        for _ in 0..i + 1 {
            let ksk = relin_key_iter.next().unwrap();
            let pol = input_poly_iter.next().unwrap();
            let mut decomposition_iter = decomposer.decompose_slice(pol.as_ref());
            // loop over the number of levels
            for level_key_ciphertext in ksk.iter() {
                let decomposed = decomposition_iter.next_term().unwrap();
                decomposed.modular_value(scalar_poly.as_mut());
                polynomial_list_wrapping_sub_scalar_mul_assign_custom_mod(
                    &mut output_glwe_ciphertext.as_mut_polynomial_list(),
                    &level_key_ciphertext.as_polynomial_list(),
                    &scalar_poly,
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

pub fn tensor_mult_with_relin<Scalar, LhsCont, RhsCont, KeyCont, OutputCont>(
    input_glwe_ciphertext_lhs: &GlweCiphertext<LhsCont>,
    input_glwe_ciphertext_rhs: &GlweCiphertext<RhsCont>,
    scale: Scalar,
    relinearization_key: &GlweRelinearizationKey<KeyCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
) where
    Scalar: UnsignedInteger,
    LhsCont: Container<Element = Scalar>,
    RhsCont: Container<Element = Scalar>,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    let k = input_glwe_ciphertext_lhs.glwe_size().to_glwe_dimension().0;
    let tensor_k = GlweDimension(k * (k + 3) / 2);

    let mut tensor_product_ciphertext = GlweCiphertextOwned::new(
        Scalar::ZERO,
        tensor_k.to_glwe_size(),
        input_glwe_ciphertext_lhs.polynomial_size(),
        input_glwe_ciphertext_lhs.ciphertext_modulus(),
    );

    glwe_tensor_product(
        input_glwe_ciphertext_lhs,
        input_glwe_ciphertext_rhs,
        &mut tensor_product_ciphertext,
        scale,
    );
    glwe_relinearization(
        &tensor_product_ciphertext,
        relinearization_key,
        output_glwe_ciphertext,
    );
}

/// Compute the result of a dot product between two LWE lists
/// using the LWE Packing Keyswitch operation.
/// If we have two list of LWEs encrypting the values (v_i)_i and (w_i)_i
/// respectively this will compute an LWE ciphertext encrypting the dot product
/// of (v_i)_i and (w_i)_i, namely sum_i v_i*w_i
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters
/// let input_lwe_dimension = LweDimension(742);
/// let lwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let output_glwe_dimension = GlweDimension(1);
/// let output_polynomial_size = PolynomialSize(2048);
/// let decomp_base_log = DecompositionBaseLog(23);
/// let decomp_level_count = DecompositionLevelCount(1);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// // Create the LweSecretKey
/// let input_lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(input_lwe_dimension, &mut secret_generator);
/// let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     output_glwe_dimension,
///     output_polynomial_size,
///     &mut secret_generator,
/// );
///
/// let pksk = allocate_and_generate_new_lwe_packing_keyswitch_key(
///     &input_lwe_secret_key,
///     &output_glwe_secret_key,
///     decomp_base_log,
///     decomp_level_count,
///     glwe_noise_distribution,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// let number_of_lwes = 4;
///
/// // Create the first LweCiphertextList
/// let mut input_lwe_list_lhs = LweCiphertextList::new(
///     0u64,
///     input_lwe_dimension.to_lwe_size(),
///     LweCiphertextCount(number_of_lwes),
///     ciphertext_modulus,
/// );
///
/// let input_plaintext_list_lhs =
///     PlaintextList::from_container(vec![1u64 << 60, 0, 1 << 60, 1 << 60]);
///
/// encrypt_lwe_ciphertext_list(
///     &input_lwe_secret_key,
///     &mut input_lwe_list_lhs,
///     &input_plaintext_list_lhs,
///     lwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// // Create the second LweCiphertextList
/// let mut input_lwe_list_rhs = LweCiphertextList::new(
///     0u64,
///     input_lwe_dimension.to_lwe_size(),
///     LweCiphertextCount(number_of_lwes),
///     ciphertext_modulus,
/// );
///
/// let input_plaintext_list_rhs =
///     PlaintextList::from_container(vec![1u64 << 61, 1 << 60, 1 << 60, 0]);
///
/// encrypt_lwe_ciphertext_list(
///     &input_lwe_secret_key,
///     &mut input_lwe_list_rhs,
///     &input_plaintext_list_rhs,
///     lwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// let relin_key = allocate_and_generate_glwe_relinearization_key(
///     &output_glwe_secret_key,
///     decomp_base_log,
///     decomp_level_count,
///     glwe_noise_distribution,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// // Define the output lwe secret key
/// let output_lwe_secret_key =
///     LweSecretKey::from_container(output_glwe_secret_key.into_container());
///
/// // Create the output LweCiphertext
/// let mut output_lwe = LweCiphertext::new(
///     0u64,
///     output_lwe_secret_key.lwe_dimension().to_lwe_size(),
///     ciphertext_modulus,
/// );
///
/// lwe_dot_product_via_packing_keyswitch(
///     &input_lwe_list_lhs,
///     &input_lwe_list_rhs,
///     &pksk,
///     &relin_key,
///     1u64 << 60,
///     &mut output_lwe,
/// );
///
/// let decrypted_plaintext = decrypt_lwe_ciphertext(&output_lwe_secret_key, &output_lwe);
///
/// // Round and remove encoding
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// let rounded = decomposer.closest_representable(decrypted_plaintext.0);
///
/// let cleartext = rounded >> 60;
/// // result should be 1*2 + 0*1 + 1*1 + 1*0 = 3
/// assert_eq!(cleartext, 3u64);
/// ```
pub fn lwe_dot_product_via_packing_keyswitch<InputCont, KeyCont, OutputCont, Scalar>(
    input_lwe_ciphertext_list_1: &LweCiphertextList<InputCont>,
    input_lwe_ciphertext_list_2: &LweCiphertextList<InputCont>,
    lwe_pksk: &LwePackingKeyswitchKey<KeyCont>,
    relinearization_key: &GlweRelinearizationKey<KeyCont>,
    scale: Scalar,
    output_lwe_ciphertext: &mut LweCiphertext<OutputCont>,
) where
    Scalar: UnsignedInteger,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert_eq!(
        input_lwe_ciphertext_list_1.lwe_ciphertext_count(),
        input_lwe_ciphertext_list_2.lwe_ciphertext_count()
    );

    let mut packed_glwe_1 = GlweCiphertextOwned::new(
        Scalar::ZERO,
        lwe_pksk.output_glwe_size(),
        lwe_pksk.output_polynomial_size(),
        lwe_pksk.ciphertext_modulus(),
    );
    keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
        lwe_pksk,
        input_lwe_ciphertext_list_1,
        &mut packed_glwe_1,
    );
    let mut packed_glwe_2 = GlweCiphertextOwned::new(
        Scalar::ZERO,
        lwe_pksk.output_glwe_size(),
        lwe_pksk.output_polynomial_size(),
        lwe_pksk.ciphertext_modulus(),
    );
    keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
        lwe_pksk,
        input_lwe_ciphertext_list_2,
        &mut packed_glwe_2,
    );
    let mut relin_glwe_ciphertext = GlweCiphertextOwned::new(
        Scalar::ZERO,
        lwe_pksk.output_glwe_size(),
        lwe_pksk.output_polynomial_size(),
        lwe_pksk.ciphertext_modulus(),
    );
    tensor_mult_with_relin(
        &packed_glwe_1,
        &packed_glwe_2,
        scale,
        relinearization_key,
        &mut relin_glwe_ciphertext,
    );

    extract_lwe_sample_from_glwe_ciphertext(
        &relin_glwe_ciphertext,
        output_lwe_ciphertext,
        MonomialDegree(input_lwe_ciphertext_list_1.lwe_ciphertext_count().0 - 1),
    );
}

/// Compute the result of a dot product between two LWE lists
/// using the LWE Trace Packing Keyswitch operation,
/// If we have two lists of LWEs encrypting the values (v_i)_i and (w_i)_i
/// respectively, this will compute an LWE ciphertext encrypting the dot product
/// of (v_i)_i and (w_i)_i, namely sum_i v_i*w_i
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters
/// let input_lwe_dimension = LweDimension(742);
/// let lwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let output_glwe_dimension = GlweDimension(1);
/// let output_polynomial_size = PolynomialSize(1024);
/// let decomp_base_log = DecompositionBaseLog(23);
/// let decomp_level_count = DecompositionLevelCount(1);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// // Create the LweSecretKey
/// let input_lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(input_lwe_dimension, &mut secret_generator);
///
/// let mut glwe_secret_key =
///     GlweSecretKey::new_empty_key(0u64, output_glwe_dimension, output_polynomial_size);
///
/// generate_tpksk_output_glwe_secret_key(
///     &input_lwe_secret_key,
///     &mut glwe_secret_key,
///     ciphertext_modulus,
///     &mut secret_generator,
/// );
///
/// let mut lwe_tpksk = LweTracePackingKeyswitchKey::new(
///     0u64,
///     decomp_base_log,
///     decomp_level_count,
///     input_lwe_dimension.to_lwe_size(),
///     output_glwe_dimension.to_glwe_size(),
///     output_polynomial_size,
///     ciphertext_modulus,
/// );
///
/// generate_lwe_trace_packing_keyswitch_key(
///     &glwe_secret_key,
///     &mut lwe_tpksk,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// let number_of_lwes = 4;
///
/// // Create the first LweCiphertextList
/// let mut input_lwe_list_lhs = LweCiphertextList::new(
///     0u64,
///     input_lwe_dimension.to_lwe_size(),
///     LweCiphertextCount(number_of_lwes),
///     ciphertext_modulus,
/// );
///
/// let input_plaintext_list_lhs =
///     PlaintextList::from_container(vec![1u64 << 60, 0, 1 << 60, 1 << 60]);
///
/// encrypt_lwe_ciphertext_list(
///     &input_lwe_secret_key,
///     &mut input_lwe_list_lhs,
///     &input_plaintext_list_lhs,
///     lwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// // Create the second LweCiphertextList
/// let mut input_lwe_list_rhs = LweCiphertextList::new(
///     0u64,
///     input_lwe_dimension.to_lwe_size(),
///     LweCiphertextCount(number_of_lwes),
///     ciphertext_modulus,
/// );
///
/// let input_plaintext_list_rhs =
///     PlaintextList::from_container(vec![1u64 << 61, 1 << 60, 1 << 60, 0]);
///
/// encrypt_lwe_ciphertext_list(
///     &input_lwe_secret_key,
///     &mut input_lwe_list_rhs,
///     &input_plaintext_list_rhs,
///     lwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// let glwe_relin_key = allocate_and_generate_glwe_relinearization_key(
///     &glwe_secret_key,
///     decomp_base_log,
///     decomp_level_count,
///     glwe_noise_distribution,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// // Define the output lwe secret key
/// let output_lwe_secret_key = glwe_secret_key.into_lwe_secret_key();
///
/// // Create the output LweCiphertext
/// let mut output_lwe_ciphertext = LweCiphertext::new(
///     0_u64,
///     output_lwe_secret_key.lwe_dimension().to_lwe_size(),
///     ciphertext_modulus,
/// );
///
/// lwe_dot_product_via_trace_packing_keyswitch(
///     &input_lwe_list_lhs,
///     &input_lwe_list_rhs,
///     &lwe_tpksk,
///     &glwe_relin_key,
///     1u64 << 60,
///     &mut output_lwe_ciphertext,
/// );
///
/// let output_plaintext = decrypt_lwe_ciphertext(&output_lwe_secret_key, &output_lwe_ciphertext);
///
/// // Round and remove encoding
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// let rounded = decomposer.closest_representable(output_plaintext.0);
///
/// let cleartext = rounded >> 60;
/// // result should be 1*2 + 0*1 + 1*1 + 1*0 = 3
/// assert_eq!(cleartext, 3u64);
/// ```
pub fn lwe_dot_product_via_trace_packing_keyswitch<InputCont, KeyCont, OutputCont, Scalar>(
    input_lwe_ciphertext_list_1: &LweCiphertextList<InputCont>,
    input_lwe_ciphertext_list_2: &LweCiphertextList<InputCont>,
    lwe_tpksk: &LweTracePackingKeyswitchKey<KeyCont>,
    relinearization_key: &GlweRelinearizationKey<KeyCont>,
    scale: Scalar,
    output_lwe_ciphertext: &mut LweCiphertext<OutputCont>,
) where
    Scalar: UnsignedInteger,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert_eq!(
        input_lwe_ciphertext_list_1.lwe_ciphertext_count(),
        input_lwe_ciphertext_list_2.lwe_ciphertext_count()
    );

    let mut packed_glwe_1 = GlweCiphertext::new(
        Scalar::ZERO,
        lwe_tpksk.output_glwe_size(),
        lwe_tpksk.polynomial_size(),
        lwe_tpksk.ciphertext_modulus(),
    );
    let mut indices_1 = vec![0_usize; input_lwe_ciphertext_list_1.lwe_ciphertext_count().0];
    indices_1
        .iter_mut()
        .enumerate()
        .for_each(|(index, val)| *val = index);
    trace_packing_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext(
        lwe_tpksk,
        &mut packed_glwe_1,
        input_lwe_ciphertext_list_1,
        &indices_1,
    );
    let mut packed_glwe_2 = GlweCiphertext::new(
        Scalar::ZERO,
        lwe_tpksk.output_glwe_size(),
        lwe_tpksk.polynomial_size(),
        lwe_tpksk.ciphertext_modulus(),
    );
    let mut indices_2 = vec![0_usize; input_lwe_ciphertext_list_2.lwe_ciphertext_count().0];
    indices_2
        .iter_mut()
        .rev()
        .enumerate()
        .for_each(|(index, val)| *val = index);
    trace_packing_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext(
        lwe_tpksk,
        &mut packed_glwe_2,
        input_lwe_ciphertext_list_2,
        &indices_2,
    );
    let mut relin_glwe_ciphertext = GlweCiphertext::new(
        Scalar::ZERO,
        lwe_tpksk.output_glwe_size(),
        lwe_tpksk.polynomial_size(),
        lwe_tpksk.ciphertext_modulus(),
    );
    tensor_mult_with_relin(
        &packed_glwe_1,
        &packed_glwe_2,
        scale,
        relinearization_key,
        &mut relin_glwe_ciphertext,
    );

    extract_lwe_sample_from_glwe_ciphertext(
        &relin_glwe_ciphertext,
        output_lwe_ciphertext,
        MonomialDegree(input_lwe_ciphertext_list_1.lwe_ciphertext_count().0 - 1),
    );
}

/// Compute the result of a component-wise product of LWE lists
/// using the LWE Trace Packing Keyswitch operation.
/// If we have two lists of LWEs encrypting the values (v_i)_i and (w_i)_i
/// respectively, this will compute a list of LWE ciphertext encrypting the
/// products v_i*w_i
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters
/// let input_lwe_dimension = LweDimension(742);
/// let lwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let output_glwe_dimension = GlweDimension(1);
/// let output_polynomial_size = PolynomialSize(1024);
/// let decomp_base_log = DecompositionBaseLog(23);
/// let decomp_level_count = DecompositionLevelCount(1);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// // Create the LweSecretKey
/// let input_lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(input_lwe_dimension, &mut secret_generator);
///
/// let mut glwe_secret_key =
///     GlweSecretKey::new_empty_key(0u64, output_glwe_dimension, output_polynomial_size);
///
/// generate_tpksk_output_glwe_secret_key(
///     &input_lwe_secret_key,
///     &mut glwe_secret_key,
///     ciphertext_modulus,
///     &mut secret_generator,
/// );
///
/// let mut lwe_tpksk = LweTracePackingKeyswitchKey::new(
///     0u64,
///     decomp_base_log,
///     decomp_level_count,
///     input_lwe_dimension.to_lwe_size(),
///     output_glwe_dimension.to_glwe_size(),
///     output_polynomial_size,
///     ciphertext_modulus,
/// );
///
/// generate_lwe_trace_packing_keyswitch_key(
///     &glwe_secret_key,
///     &mut lwe_tpksk,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// let number_of_lwes = 4;
///
/// // Create the first LweCiphertextList
/// let mut input_lwe_list_lhs = LweCiphertextList::new(
///     0u64,
///     input_lwe_dimension.to_lwe_size(),
///     LweCiphertextCount(number_of_lwes),
///     ciphertext_modulus,
/// );
///
/// let input_plaintext_list_lhs =
///     PlaintextList::from_container(vec![1u64 << 60, 1 << 60, 2 << 60, 3 << 60]);
///
/// encrypt_lwe_ciphertext_list(
///     &input_lwe_secret_key,
///     &mut input_lwe_list_lhs,
///     &input_plaintext_list_lhs,
///     lwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// // Create the second LweCiphertextList
/// let mut input_lwe_list_rhs = LweCiphertextList::new(
///     0u64,
///     input_lwe_dimension.to_lwe_size(),
///     LweCiphertextCount(number_of_lwes),
///     ciphertext_modulus,
/// );
///
/// let input_plaintext_list_rhs =
///     PlaintextList::from_container(vec![2u64 << 60, 3 << 60, 1 << 60, 0 << 60]);
///
/// encrypt_lwe_ciphertext_list(
///     &input_lwe_secret_key,
///     &mut input_lwe_list_rhs,
///     &input_plaintext_list_rhs,
///     lwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// let glwe_relin_key = allocate_and_generate_glwe_relinearization_key(
///     &glwe_secret_key,
///     decomp_base_log,
///     decomp_level_count,
///     glwe_noise_distribution,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// // Define the output lwe secret key
/// let output_lwe_secret_key = glwe_secret_key.into_lwe_secret_key();
///
/// // Create the output LweCiphertext
/// let mut output_lwe_ciphertext_list = LweCiphertextList::new(
///     0_u64,
///     output_lwe_secret_key.lwe_dimension().to_lwe_size(),
///     LweCiphertextCount(number_of_lwes),
///     ciphertext_modulus,
/// );
///
/// packed_lwe_multiplication_via_trace_packing_keyswitch(
///     &input_lwe_list_lhs,
///     &input_lwe_list_rhs,
///     &lwe_tpksk,
///     &glwe_relin_key,
///     1u64 << 60,
///     &mut output_lwe_ciphertext_list,
/// );
///
/// let mut output_plaintext_list = PlaintextList::new(0u64, PlaintextCount(number_of_lwes));
/// decrypt_lwe_ciphertext_list(
///     &output_lwe_secret_key,
///     &output_lwe_ciphertext_list,
///     &mut output_plaintext_list,
/// );
///
/// // Round and remove encoding
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// output_plaintext_list
///     .iter_mut()
///     .for_each(|elt| *elt.0 = decomposer.closest_representable(*elt.0));
///
/// // Get the raw vector
/// let mut cleartext_list = output_plaintext_list.into_container();
/// // Remove the encoding
/// cleartext_list.iter_mut().for_each(|elt| *elt >>= 60);
/// // Get the list immutably
/// let cleartext_list = cleartext_list;
///
/// let expected_result = [2u64, 3, 2, 0];
/// for (cleartext, expected) in cleartext_list.iter().zip(expected_result.iter()) {
///     assert_eq!(cleartext, expected);
/// }
/// ```
pub fn packed_lwe_multiplication_via_trace_packing_keyswitch<
    Scalar,
    InputCont,
    KeyCont,
    OutputCont,
>(
    input_lwe_ciphertext_list_1: &LweCiphertextList<InputCont>,
    input_lwe_ciphertext_list_2: &LweCiphertextList<InputCont>,
    lwe_tpksk: &LweTracePackingKeyswitchKey<KeyCont>,
    relinearization_key: &GlweRelinearizationKey<KeyCont>,
    scale: Scalar,
    output_lwe_ciphertext_list: &mut LweCiphertextList<OutputCont>,
) where
    Scalar: UnsignedTorus + CastInto<u128> + CastFrom<u128>,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    let lwe_count = input_lwe_ciphertext_list_1.lwe_ciphertext_count();
    assert_eq!(
        input_lwe_ciphertext_list_2.lwe_ciphertext_count(),
        lwe_count
    );
    assert_eq!(output_lwe_ciphertext_list.lwe_ciphertext_count(), lwe_count);
    assert!(
        lwe_count.0.pow(2) <= lwe_tpksk.polynomial_size().0,
        "Too many input LWEs. The number of LWEs in each input lwe list must
        be at most the square root of the polynomial size.",
    );

    let mut packed_glwe_1 = GlweCiphertext::new(
        Scalar::ZERO,
        lwe_tpksk.output_glwe_size(),
        lwe_tpksk.polynomial_size(),
        lwe_tpksk.ciphertext_modulus(),
    );
    let mut indices_1 = vec![0_usize; lwe_count.0];
    indices_1
        .iter_mut()
        .enumerate()
        .for_each(|(index, val)| *val = index);
    trace_packing_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext(
        lwe_tpksk,
        &mut packed_glwe_1,
        input_lwe_ciphertext_list_1,
        &indices_1,
    );
    let mut packed_glwe_2 = GlweCiphertext::new(
        Scalar::ZERO,
        lwe_tpksk.output_glwe_size(),
        lwe_tpksk.polynomial_size(),
        lwe_tpksk.ciphertext_modulus(),
    );
    let mut indices_2 = vec![0_usize; lwe_count.0];
    indices_2
        .iter_mut()
        .enumerate()
        .for_each(|(index, val)| *val = index * lwe_count.0);
    trace_packing_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext(
        lwe_tpksk,
        &mut packed_glwe_2,
        input_lwe_ciphertext_list_2,
        &indices_2,
    );
    let mut relin_glwe_ciphertext = GlweCiphertext::new(
        Scalar::ZERO,
        lwe_tpksk.output_glwe_size(),
        lwe_tpksk.polynomial_size(),
        lwe_tpksk.ciphertext_modulus(),
    );
    tensor_mult_with_relin(
        &packed_glwe_1,
        &packed_glwe_2,
        scale,
        relinearization_key,
        &mut relin_glwe_ciphertext,
    );

    output_lwe_ciphertext_list
        .iter_mut()
        .enumerate()
        .for_each(|(iter, mut el)| {
            extract_lwe_sample_from_glwe_ciphertext(
                &relin_glwe_ciphertext,
                &mut el,
                MonomialDegree(iter * (lwe_count.0 + 1)),
            )
        });
}
