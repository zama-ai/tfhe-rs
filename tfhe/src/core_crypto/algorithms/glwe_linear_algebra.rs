//! Module containing primitives pertaining to [`GLWE ciphertext`](`GlweCiphertext`) linear algebra,
//! like addition, multiplication, etc.

use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Add the right-hand side [`GLWE ciphertext`](`GlweCiphertext`) to the left-hand side [`GLWE
/// ciphertext`](`GlweCiphertext`) updating it in-place.
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GlweCiphertext creation
/// let glwe_dimension = GlweDimension(1);
/// let polynomial_size = PolynomialSize(2048);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_dimension,
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the plaintext
/// let msg = 3u64;
/// let encoded_msg = msg << 60;
/// let plaintext_list = PlaintextList::new(encoded_msg, PlaintextCount(polynomial_size.0));
///
/// // Create a new GlweCiphertext
/// let mut glwe = GlweCiphertext::new(
///     0u64,
///     glwe_dimension.to_glwe_size(),
///     polynomial_size,
///     ciphertext_modulus,
/// );
/// encrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &mut glwe,
///     &plaintext_list,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// let rhs = glwe.clone();
///
/// glwe_ciphertext_add_assign(&mut glwe, &rhs);
///
/// let mut output_plaintext_list =
///     PlaintextList::new(0u64, PlaintextCount(glwe.polynomial_size().0));
///
/// decrypt_glwe_ciphertext(&glwe_secret_key, &glwe, &mut output_plaintext_list);
///
/// // Round and remove encoding
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// // Round and remove encoding in the output plaintext list
/// output_plaintext_list
///     .iter_mut()
///     .for_each(|x| *x.0 = decomposer.closest_representable(*x.0) >> 60);
///
/// // Check we recovered the expected result
/// assert!(output_plaintext_list.iter().all(|x| *x.0 == msg + msg));
/// ```
pub fn glwe_ciphertext_add_assign<Scalar, LhsCont, RhsCont>(
    lhs: &mut GlweCiphertext<LhsCont>,
    rhs: &GlweCiphertext<RhsCont>,
) where
    Scalar: UnsignedInteger,
    LhsCont: ContainerMut<Element = Scalar>,
    RhsCont: Container<Element = Scalar>,
{
    assert_eq!(
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus(),
        "Mismatched moduli between lhs ({:?}) and rhs ({:?}) GlweCiphertext",
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus()
    );

    slice_wrapping_add_assign(lhs.as_mut(), rhs.as_ref());
}

/// Add the right-hand side [`GLWE ciphertext`](`GlweCiphertext`) to the left-hand side [`GLWE
/// ciphertext`](`GlweCiphertext`) writing the result in the output [`GLWE
/// ciphertext`](`GlweCiphertext`).
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GlweCiphertext creation
/// let glwe_dimension = GlweDimension(1);
/// let polynomial_size = PolynomialSize(2048);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_dimension,
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the plaintext
/// let msg = 3u64;
/// let encoded_msg = msg << 60;
/// let plaintext_list = PlaintextList::new(encoded_msg, PlaintextCount(polynomial_size.0));
///
/// // Create a new GlweCiphertext
/// let mut glwe = GlweCiphertext::new(
///     0u64,
///     glwe_dimension.to_glwe_size(),
///     polynomial_size,
///     ciphertext_modulus,
/// );
/// encrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &mut glwe,
///     &plaintext_list,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// let rhs = glwe.clone();
///
/// let mut output = rhs.clone();
///
/// glwe_ciphertext_add(&mut output, &glwe, &rhs);
///
/// let mut output_plaintext_list =
///     PlaintextList::new(0u64, PlaintextCount(output.polynomial_size().0));
///
/// decrypt_glwe_ciphertext(&glwe_secret_key, &output, &mut output_plaintext_list);
///
/// // Round and remove encoding
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// // Round and remove encoding in the output plaintext list
/// output_plaintext_list
///     .iter_mut()
///     .for_each(|x| *x.0 = decomposer.closest_representable(*x.0) >> 60);
///
/// // Check we recovered the expected result
/// assert!(output_plaintext_list.iter().all(|x| *x.0 == msg + msg));
/// ```
pub fn glwe_ciphertext_add<Scalar, OutputCont, LhsCont, RhsCont>(
    output: &mut GlweCiphertext<OutputCont>,
    lhs: &GlweCiphertext<LhsCont>,
    rhs: &GlweCiphertext<RhsCont>,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    LhsCont: Container<Element = Scalar>,
    RhsCont: Container<Element = Scalar>,
{
    assert_eq!(
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus(),
        "Mismatched moduli between lhs ({:?}) and rhs ({:?}) GlweCiphertext",
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus()
    );

    assert_eq!(
        output.ciphertext_modulus(),
        rhs.ciphertext_modulus(),
        "Mismatched moduli between output ({:?}) and rhs ({:?}) GlweCiphertext",
        output.ciphertext_modulus(),
        rhs.ciphertext_modulus()
    );

    slice_wrapping_add(output.as_mut(), lhs.as_ref(), rhs.as_ref());
}

/// Add the right-hand side encoded [`PlaintextList`] to the left-hand side [`GLWE
/// ciphertext`](`GlweCiphertext`) updating it in-place.
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GlweCiphertext creation
/// let glwe_dimension = GlweDimension(1);
/// let polynomial_size = PolynomialSize(2048);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_dimension,
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the plaintext
/// let msg = 3u64;
/// let encoded_msg = msg << 60;
/// let plaintext_list = PlaintextList::new(encoded_msg, PlaintextCount(polynomial_size.0));
///
/// // Create a new GlweCiphertext
/// let mut glwe = GlweCiphertext::new(
///     0u64,
///     glwe_dimension.to_glwe_size(),
///     polynomial_size,
///     ciphertext_modulus,
/// );
/// encrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &mut glwe,
///     &plaintext_list,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// glwe_ciphertext_plaintext_list_add_assign(&mut glwe, &plaintext_list);
///
/// let mut output_plaintext_list =
///     PlaintextList::new(0u64, PlaintextCount(glwe.polynomial_size().0));
///
/// decrypt_glwe_ciphertext(&glwe_secret_key, &glwe, &mut output_plaintext_list);
///
/// // Round and remove encoding
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// // Round and remove encoding in the output plaintext list
/// output_plaintext_list
///     .iter_mut()
///     .for_each(|x| *x.0 = decomposer.closest_representable(*x.0) >> 60);
///
/// // Check we recovered the expected result
/// assert!(output_plaintext_list.iter().all(|x| *x.0 == msg + msg));
/// ```
pub fn glwe_ciphertext_plaintext_list_add_assign<Scalar, InCont, PlainCont>(
    lhs: &mut GlweCiphertext<InCont>,
    rhs: &PlaintextList<PlainCont>,
) where
    Scalar: UnsignedInteger,
    InCont: ContainerMut<Element = Scalar>,
    PlainCont: Container<Element = Scalar>,
{
    let mut body = lhs.get_mut_body();
    let ciphertext_modulus = body.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    if ciphertext_modulus.is_native_modulus() {
        slice_wrapping_add_assign(body.as_mut(), rhs.as_ref());
    } else {
        // Power of 2 case
        let power_of_two_scaling = ciphertext_modulus.get_power_of_two_scaling_to_native_torus();
        slice_wrapping_add_scalar_mul_assign(body.as_mut(), rhs.as_ref(), power_of_two_scaling);
    }
}

/// Subtract the right-hand side encoded [`PlaintextList`] to the left-hand side [`GLWE
/// ciphertext`](`GlweCiphertext`) updating it in-place.
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GlweCiphertext creation
/// let glwe_dimension = GlweDimension(1);
/// let polynomial_size = PolynomialSize(2048);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_dimension,
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the plaintext
/// let msg = 3u64;
/// let encoded_msg = msg << 60;
/// let plaintext_list = PlaintextList::new(encoded_msg, PlaintextCount(polynomial_size.0));
///
/// // Create a new GlweCiphertext
/// let mut glwe = GlweCiphertext::new(
///     0u64,
///     glwe_dimension.to_glwe_size(),
///     polynomial_size,
///     ciphertext_modulus,
/// );
/// encrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &mut glwe,
///     &plaintext_list,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// glwe_ciphertext_plaintext_list_sub_assign(&mut glwe, &plaintext_list);
///
/// let mut output_plaintext_list =
///     PlaintextList::new(0u64, PlaintextCount(glwe.polynomial_size().0));
///
/// decrypt_glwe_ciphertext(&glwe_secret_key, &glwe, &mut output_plaintext_list);
///
/// // Round and remove encoding
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// // Round and remove encoding in the output plaintext list
/// output_plaintext_list
///     .iter_mut()
///     .for_each(|x| *x.0 = decomposer.closest_representable(*x.0) >> 60);
///
/// // Check we recovered the expected result
/// assert!(output_plaintext_list.iter().all(|x| *x.0 == 0));
/// ```
pub fn glwe_ciphertext_plaintext_list_sub_assign<Scalar, InCont, PlainCont>(
    lhs: &mut GlweCiphertext<InCont>,
    rhs: &PlaintextList<PlainCont>,
) where
    Scalar: UnsignedInteger,
    InCont: ContainerMut<Element = Scalar>,
    PlainCont: Container<Element = Scalar>,
{
    let mut body = lhs.get_mut_body();
    let ciphertext_modulus = body.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    if ciphertext_modulus.is_native_modulus() {
        slice_wrapping_sub_assign(body.as_mut(), rhs.as_ref());
    } else {
        // Power of 2 case
        let power_of_two_scaling = ciphertext_modulus.get_power_of_two_scaling_to_native_torus();
        slice_wrapping_sub_scalar_mul_assign(body.as_mut(), rhs.as_ref(), power_of_two_scaling);
    }
}

/// Add the right-hand side encoded [`Plaintext`] to every body coefficient of the left-hand side
/// [`GLWE ciphertext`](`GlweCiphertext`) updating it in-place.
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GlweCiphertext creation
/// let glwe_dimension = GlweDimension(1);
/// let polynomial_size = PolynomialSize(2048);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_dimension,
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the plaintext
/// let msg = 3u64;
/// let encoded_msg = msg << 60;
/// let plaintext_list = PlaintextList::new(encoded_msg, PlaintextCount(polynomial_size.0));
///
/// // Create a new GlweCiphertext
/// let mut glwe = GlweCiphertext::new(
///     0u64,
///     glwe_dimension.to_glwe_size(),
///     polynomial_size,
///     ciphertext_modulus,
/// );
/// encrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &mut glwe,
///     &plaintext_list,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// glwe_ciphertext_plaintext_add_assign(&mut glwe, Plaintext(encoded_msg));
///
/// let mut output_plaintext_list =
///     PlaintextList::new(0u64, PlaintextCount(glwe.polynomial_size().0));
///
/// decrypt_glwe_ciphertext(&glwe_secret_key, &glwe, &mut output_plaintext_list);
///
/// // Round and remove encoding
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// // Round and remove encoding in the output plaintext list
/// output_plaintext_list
///     .iter_mut()
///     .for_each(|x| *x.0 = decomposer.closest_representable(*x.0) >> 60);
///
/// // Check we recovered the expected result
/// assert!(output_plaintext_list.iter().all(|x| *x.0 == msg + msg));
/// ```
pub fn glwe_ciphertext_plaintext_add_assign<Scalar, InCont>(
    lhs: &mut GlweCiphertext<InCont>,
    rhs: Plaintext<Scalar>,
) where
    Scalar: UnsignedInteger,
    InCont: ContainerMut<Element = Scalar>,
{
    let mut body = lhs.get_mut_body();
    let ciphertext_modulus = body.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    if ciphertext_modulus.is_native_modulus() {
        slice_wrapping_scalar_add_assign(body.as_mut(), rhs.0);
    } else {
        // Power of 2 case
        let power_of_two_scaling = ciphertext_modulus.get_power_of_two_scaling_to_native_torus();
        let rhs_scaled = rhs.0.wrapping_mul(power_of_two_scaling);
        slice_wrapping_scalar_add_assign(body.as_mut(), rhs_scaled);
    }
}

/// Subtract the right-hand side encoded [`Plaintext`] to every body coefficient of the left-hand
/// side [`GLWE ciphertext`](`GlweCiphertext`) updating it in-place.
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GlweCiphertext creation
/// let glwe_dimension = GlweDimension(1);
/// let polynomial_size = PolynomialSize(2048);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_dimension,
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the plaintext
/// let msg = 3u64;
/// let encoded_msg = msg << 60;
/// let plaintext_list = PlaintextList::new(encoded_msg, PlaintextCount(polynomial_size.0));
///
/// // Create a new GlweCiphertext
/// let mut glwe = GlweCiphertext::new(
///     0u64,
///     glwe_dimension.to_glwe_size(),
///     polynomial_size,
///     ciphertext_modulus,
/// );
/// encrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &mut glwe,
///     &plaintext_list,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// glwe_ciphertext_plaintext_sub_assign(&mut glwe, Plaintext(encoded_msg));
///
/// let mut output_plaintext_list =
///     PlaintextList::new(0u64, PlaintextCount(glwe.polynomial_size().0));
///
/// decrypt_glwe_ciphertext(&glwe_secret_key, &glwe, &mut output_plaintext_list);
///
/// // Round and remove encoding
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// // Round and remove encoding in the output plaintext list
/// output_plaintext_list
///     .iter_mut()
///     .for_each(|x| *x.0 = decomposer.closest_representable(*x.0) >> 60);
///
/// // Check we recovered the expected result
/// assert!(output_plaintext_list.iter().all(|x| *x.0 == 0));
/// ```
pub fn glwe_ciphertext_plaintext_sub_assign<Scalar, InCont>(
    lhs: &mut GlweCiphertext<InCont>,
    rhs: Plaintext<Scalar>,
) where
    Scalar: UnsignedInteger,
    InCont: ContainerMut<Element = Scalar>,
{
    let mut body = lhs.get_mut_body();
    let ciphertext_modulus = body.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    if ciphertext_modulus.is_native_modulus() {
        slice_wrapping_scalar_sub_assign(body.as_mut(), rhs.0);
    } else {
        // Power of 2 case
        let power_of_two_scaling = ciphertext_modulus.get_power_of_two_scaling_to_native_torus();
        let rhs_scaled = rhs.0.wrapping_mul(power_of_two_scaling);
        slice_wrapping_scalar_sub_assign(body.as_mut(), rhs_scaled);
    }
}

/// Compute the opposite of the input [`GLWE ciphertext`](`GlweCiphertext`) and update it in place.
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GlweCiphertext creation
/// let glwe_dimension = GlweDimension(1);
/// let polynomial_size = PolynomialSize(2048);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_dimension,
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the plaintext
/// let msg = 3u64;
/// let encoded_msg = msg << 60;
/// let plaintext_list = PlaintextList::new(encoded_msg, PlaintextCount(polynomial_size.0));
///
/// // Create a new GlweCiphertext
/// let mut glwe = GlweCiphertext::new(
///     0u64,
///     glwe_dimension.to_glwe_size(),
///     polynomial_size,
///     ciphertext_modulus,
/// );
/// encrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &mut glwe,
///     &plaintext_list,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// glwe_ciphertext_opposite_assign(&mut glwe);
///
/// let mut output_plaintext_list =
///     PlaintextList::new(0u64, PlaintextCount(glwe.polynomial_size().0));
///
/// decrypt_glwe_ciphertext(&glwe_secret_key, &glwe, &mut output_plaintext_list);
///
/// // Round and remove encoding
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// // Round and remove encoding in the output plaintext list
/// output_plaintext_list
///     .iter_mut()
///     .for_each(|x| *x.0 = decomposer.closest_representable(*x.0) >> 60);
///
/// // Check we recovered the expected result
/// assert!(output_plaintext_list
///     .iter()
///     .all(|x| *x.0 == msg.wrapping_neg() % (1 << 4)));
/// ```
pub fn glwe_ciphertext_opposite_assign<Scalar, InCont>(ct: &mut GlweCiphertext<InCont>)
where
    Scalar: UnsignedInteger,
    InCont: ContainerMut<Element = Scalar>,
{
    slice_wrapping_opposite_assign(ct.as_mut());
}

/// Multiply the left-hand side [`GLWE ciphertext`](`GlweCiphertext`) by the right-hand side
/// cleartext updating it in-place.
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GlweCiphertext creation
/// let glwe_dimension = GlweDimension(1);
/// let polynomial_size = PolynomialSize(2048);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_dimension,
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the plaintext
/// let msg = 3u64;
/// let encoded_msg = msg << 60;
/// let cleartext_mul = Cleartext(2);
/// let plaintext_list = PlaintextList::new(encoded_msg, PlaintextCount(polynomial_size.0));
///
/// // Create a new GlweCiphertext
/// let mut glwe = GlweCiphertext::new(
///     0u64,
///     glwe_dimension.to_glwe_size(),
///     polynomial_size,
///     ciphertext_modulus,
/// );
/// encrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &mut glwe,
///     &plaintext_list,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// glwe_ciphertext_cleartext_mul_assign(&mut glwe, cleartext_mul);
///
/// let mut output_plaintext_list =
///     PlaintextList::new(0u64, PlaintextCount(glwe.polynomial_size().0));
///
/// decrypt_glwe_ciphertext(&glwe_secret_key, &glwe, &mut output_plaintext_list);
///
/// // Round and remove encoding
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// // Round and remove encoding in the output plaintext list
/// output_plaintext_list
///     .iter_mut()
///     .for_each(|x| *x.0 = decomposer.closest_representable(*x.0) >> 60);
///
/// // Check we recovered the expected result
/// assert!(output_plaintext_list
///     .iter()
///     .all(|x| *x.0 == msg * cleartext_mul.0));
/// ```
pub fn glwe_ciphertext_cleartext_mul_assign<Scalar, InCont>(
    lhs: &mut GlweCiphertext<InCont>,
    rhs: Cleartext<Scalar>,
) where
    Scalar: UnsignedInteger,
    InCont: ContainerMut<Element = Scalar>,
{
    slice_wrapping_scalar_mul_assign(lhs.as_mut(), rhs.0);
}

/// Multiply the left-hand side [`GLWE ciphertext`](`GlweCiphertext`) by the right-hand side
/// cleartext writing the result in the output [`GLWE ciphertext`](`GlweCiphertext`).
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GlweCiphertext creation
/// let glwe_dimension = GlweDimension(1);
/// let polynomial_size = PolynomialSize(2048);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_dimension,
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the plaintext
/// let msg = 3u64;
/// let encoded_msg = msg << 60;
/// let cleartext_mul = Cleartext(2);
/// let plaintext_list = PlaintextList::new(encoded_msg, PlaintextCount(polynomial_size.0));
///
/// // Create a new GlweCiphertext
/// let mut glwe = GlweCiphertext::new(
///     0u64,
///     glwe_dimension.to_glwe_size(),
///     polynomial_size,
///     ciphertext_modulus,
/// );
/// encrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &mut glwe,
///     &plaintext_list,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// let mut output = glwe.clone();
///
/// glwe_ciphertext_cleartext_mul(&mut output, &glwe, cleartext_mul);
///
/// let mut output_plaintext_list =
///     PlaintextList::new(0u64, PlaintextCount(output.polynomial_size().0));
///
/// decrypt_glwe_ciphertext(&glwe_secret_key, &output, &mut output_plaintext_list);
///
/// // Round and remove encoding
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// // Round and remove encoding in the output plaintext list
/// output_plaintext_list
///     .iter_mut()
///     .for_each(|x| *x.0 = decomposer.closest_representable(*x.0) >> 60);
///
/// // Check we recovered the expected result
/// assert!(output_plaintext_list
///     .iter()
///     .all(|x| *x.0 == msg * cleartext_mul.0));
/// ```
pub fn glwe_ciphertext_cleartext_mul<Scalar, InputCont, OutputCont>(
    output: &mut GlweCiphertext<OutputCont>,
    lhs: &GlweCiphertext<InputCont>,
    rhs: Cleartext<Scalar>,
) where
    Scalar: UnsignedInteger,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert_eq!(
        output.ciphertext_modulus(),
        lhs.ciphertext_modulus(),
        "Mismatched moduli between output ({:?}) and lhs ({:?}) GlweCiphertext",
        output.ciphertext_modulus(),
        lhs.ciphertext_modulus()
    );
    output.as_mut().copy_from_slice(lhs.as_ref());
    glwe_ciphertext_cleartext_mul_assign(output, rhs);
}

/// Subtract the right-hand side [`GLWE ciphertext`](`GlweCiphertext`) to the left-hand side [`GLWE
/// ciphertext`](`GlweCiphertext`) updating it in-place.
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GlweCiphertext creation
/// let glwe_dimension = GlweDimension(1);
/// let polynomial_size = PolynomialSize(2048);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_dimension,
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the plaintext
/// let msg = 3u64;
/// let encoded_msg = msg << 60;
/// let plaintext_list = PlaintextList::new(encoded_msg, PlaintextCount(polynomial_size.0));
///
/// // Create a new GlweCiphertext
/// let mut glwe = GlweCiphertext::new(
///     0u64,
///     glwe_dimension.to_glwe_size(),
///     polynomial_size,
///     ciphertext_modulus,
/// );
/// encrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &mut glwe,
///     &plaintext_list,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// let rhs = glwe.clone();
///
/// glwe_ciphertext_sub_assign(&mut glwe, &rhs);
///
/// let mut output_plaintext_list =
///     PlaintextList::new(0u64, PlaintextCount(glwe.polynomial_size().0));
///
/// decrypt_glwe_ciphertext(&glwe_secret_key, &glwe, &mut output_plaintext_list);
///
/// // Round and remove encoding
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// // Round and remove encoding in the output plaintext list
/// output_plaintext_list
///     .iter_mut()
///     .for_each(|x| *x.0 = decomposer.closest_representable(*x.0) >> 60);
///
/// // Check we recovered the expected result
/// assert!(output_plaintext_list.iter().all(|x| *x.0 == 0));
/// ```
pub fn glwe_ciphertext_sub_assign<Scalar, LhsCont, RhsCont>(
    lhs: &mut GlweCiphertext<LhsCont>,
    rhs: &GlweCiphertext<RhsCont>,
) where
    Scalar: UnsignedInteger,
    LhsCont: ContainerMut<Element = Scalar>,
    RhsCont: Container<Element = Scalar>,
{
    assert_eq!(
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus(),
        "Mismatched moduli between lhs ({:?}) and rhs ({:?}) GlweCiphertext",
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus()
    );

    slice_wrapping_sub_assign(lhs.as_mut(), rhs.as_ref());
}

/// Subtract the right-hand side [`GLWE ciphertext`](`GlweCiphertext`) to the left-hand side [`GLWE
/// ciphertext`](`GlweCiphertext`) writing the result in the output [`GLWE
/// ciphertext`](`GlweCiphertext`).
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GlweCiphertext creation
/// let glwe_dimension = GlweDimension(1);
/// let polynomial_size = PolynomialSize(2048);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_dimension,
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the plaintext
/// let msg = 3u64;
/// let encoded_msg = msg << 60;
/// let plaintext_list = PlaintextList::new(encoded_msg, PlaintextCount(polynomial_size.0));
///
/// // Create a new GlweCiphertext
/// let mut glwe = GlweCiphertext::new(
///     0u64,
///     glwe_dimension.to_glwe_size(),
///     polynomial_size,
///     ciphertext_modulus,
/// );
/// encrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &mut glwe,
///     &plaintext_list,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// let rhs = glwe.clone();
///
/// let mut output = rhs.clone();
///
/// glwe_ciphertext_sub(&mut output, &glwe, &rhs);
///
/// let mut output_plaintext_list =
///     PlaintextList::new(0u64, PlaintextCount(output.polynomial_size().0));
///
/// decrypt_glwe_ciphertext(&glwe_secret_key, &output, &mut output_plaintext_list);
///
/// // Round and remove encoding
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// // Round and remove encoding in the output plaintext list
/// output_plaintext_list
///     .iter_mut()
///     .for_each(|x| *x.0 = decomposer.closest_representable(*x.0) >> 60);
///
/// // Check we recovered the expected result
/// assert!(output_plaintext_list.iter().all(|x| *x.0 == 0));
/// ```
pub fn glwe_ciphertext_sub<Scalar, OutputCont, LhsCont, RhsCont>(
    output: &mut GlweCiphertext<OutputCont>,
    lhs: &GlweCiphertext<LhsCont>,
    rhs: &GlweCiphertext<RhsCont>,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    LhsCont: Container<Element = Scalar>,
    RhsCont: Container<Element = Scalar>,
{
    assert_eq!(
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus(),
        "Mismatched moduli between lhs ({:?}) and rhs ({:?}) GlweCiphertext",
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus()
    );

    assert_eq!(
        output.ciphertext_modulus(),
        rhs.ciphertext_modulus(),
        "Mismatched moduli between output ({:?}) and rhs ({:?}) GlweCiphertext",
        output.ciphertext_modulus(),
        rhs.ciphertext_modulus()
    );

    output.as_mut().copy_from_slice(lhs.as_ref());
    glwe_ciphertext_sub_assign(output, rhs);
}
