// //! Module containing primitives pertaining to the [`LWE programmable
// //! bootstrap`](`LweBootstrapKey#programmable-bootstrapping`).
//
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft64::crypto::pseudo_ggsw::{
    add_external_product_pseudo_ggsw_assign as impl_add_external_product_assign,
    add_external_product_pseudo_ggsw_assign_scratch as impl_add_external_product_assign_scratch,
    PseudoFourierGgswCiphertext,
};
use crate::core_crypto::fft_impl::fft64::math::fft::FftView;
use concrete_fft::c64;
use dyn_stack::{PodStack, SizeOverflow, StackReq};
//
//
// /// Memory optimized version of [`add_external_product_assign`], the caller must provide a
// properly /// configured [`FftView`] object and a `PodStack` used as a memory buffer having a
// capacity at /// least as large as the result of
// [`add_external_product_assign_mem_optimized_requirement`]. ///
// /// Compute the external product of `ggsw` and `glwe`, and add the result to `out`.
// ///
// /// Strictly speaking this function computes:
// ///
// /// ```text
// /// out <- out + glwe * ggsw
// /// ```
// ///
/// # Example
///
/// ```
/// use tfhe::core_crypto::prelude::*;
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GgswCiphertext creation
/// let glwe_size_out = GlweSize(2);
/// let glwe_size_in = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let decomp_base_log = DecompositionBaseLog(8);
/// let decomp_level_count = DecompositionLevelCount(2);
/// let glwe_modular_std_dev = StandardDev(5.96046447753906e-25);
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
/// // Create the GlweSecretKey
/// let glwe_secret_key_out = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_size_out.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
/// //let glwe_secret_key_out = GlweSecretKey::new_empty_key(0u64, glwe_size_out
/// //.to_glwe_dimension(),
/// //polynomial_size);
///
/// // Create the GlweSecretKey
/// let glwe_secret_key_in = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_size_in.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
/// //let mut cont = vec![0u64; polynomial_size.0*glwe_size_in.to_glwe_dimension().0];
/// // cont[0] = 1;
/// //let glwe_secret_key_in = GlweSecretKey::from_container(cont,polynomial_size);
///
/// // Create a new GgswCiphertext
/// let mut ggsw = PseudoGgswCiphertext::new(
///     0u64,
///     glwe_size_in,
///     glwe_size_out,
///     polynomial_size,
///     decomp_base_log,
///     decomp_level_count,
///     ciphertext_modulus,
/// );
///
/// encrypt_pseudo_ggsw_ciphertext(
///     &glwe_secret_key_out,
///     &glwe_secret_key_in,
///     &mut ggsw,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// let ct_plaintext = Plaintext(3 << 60);
///
/// let ct_plaintexts = PlaintextList::new(ct_plaintext.0, PlaintextCount(polynomial_size.0));
/// //let ct_cont = vec![0_u64; polynomial_size.0*glwe_size_in.0];
/// //let mut ct = GlweCiphertext::from_container(ct_cont, polynomial_size, ciphertext_modulus);
/// //ct.get_mut_body().as_mut_polynomial()[0] = 1<<60;
/// let mut ct = GlweCiphertext::new(0u64, glwe_size_in, polynomial_size, ciphertext_modulus);
///
/// //trivially_encrypt_glwe_ciphertext(&mut ct, &ct_plaintexts);
/// encrypt_glwe_ciphertext(
///     &glwe_secret_key_in,
///     &mut ct,
///     &ct_plaintexts,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// let fft = Fft::new(polynomial_size);
/// let fft = fft.as_view();
/// let mut buffers = ComputationBuffers::new();
///
/// let buffer_size_req =
///     add_external_product_fast_keyswitch_assign_mem_optimized_requirement::<u64>(
///         glwe_size_out.to_glwe_dimension(),
///         polynomial_size,
///         fft,
///     )
///     .unwrap()
///     .unaligned_bytes_required();
///
/// let buffer_size_req = buffer_size_req.max(
///     convert_standard_ggsw_ciphertext_to_fourier_mem_optimized_requirement(fft)
///         .unwrap()
///         .unaligned_bytes_required(),
/// );
///
/// buffers.resize(10 * buffer_size_req);
///
/// let mut fourier_ggsw = PseudoFourierGgswCiphertext::new(
///     glwe_size_in,
///     glwe_size_out,
///     polynomial_size,
///     decomp_base_log,
///     decomp_level_count,
/// );
///
/// convert_standard_pseudo_ggsw_ciphertext_to_fourier_mem_optimized(
///     &ggsw,
///     &mut fourier_ggsw,
///     fft,
///     buffers.stack(),
/// );
///
/// //println!("Fourier GGSW = {:?}", fourier_ggsw);
///
/// let mut ct_out = GlweCiphertext::new(0u64, glwe_size_out, polynomial_size, ciphertext_modulus);
///
/// println!("Input Secret Key: {:?}\n", glwe_secret_key_in);
/// println!("Ouput Secret Key: {:?}\n", glwe_secret_key_out);
/// println!("Ct IN = {:?}\n", ct);
/// println!("GGSW = {:?}\n", ggsw);
/// println!("GGSW Fourier = {:?}\n", fourier_ggsw);
///
/// add_external_product_fast_keyswitch_assign_mem_optimized(
///     &mut ct_out,
///     &fourier_ggsw,
///     &ct,
///     fft,
///     buffers.stack(),
/// );
///
/// println!("Ct OUT = {:?}\n", ct_out);
///
/// let mut output_plaintext_list = PlaintextList::new(0u64, ct_plaintexts.plaintext_count());
///
/// decrypt_glwe_ciphertext(&glwe_secret_key_out, &ct_out, &mut output_plaintext_list);
///
/// let signed_decomposer =
///     SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// output_plaintext_list
///     .iter_mut()
///     .for_each(|x| *x.0 = signed_decomposer.closest_representable(*x.0));
///
/// println!("PlaintextList OUT = {:?}\n", output_plaintext_list);
///
/// // As we cloned the input ciphertext for the output, the external product result is added to the
/// // originally contained value, hence why we expect ct_plaintext + ct_plaintext * msg_ggsw
/// //assert!(output_plaintext_list
/// //    .iter()
/// //    .all(|x| *x.0 == ct_plaintext.0), "{:?}", output_plaintext_list);
/// assert_eq!(output_plaintext_list.into_container()[0], ct_plaintext.0);
/// ```
pub fn add_external_product_fast_keyswitch_assign_mem_optimized<
    Scalar,
    OutputGlweCont,
    InputGlweCont,
    GgswCont,
>(
    out: &mut GlweCiphertext<OutputGlweCont>,
    ggsw: &PseudoFourierGgswCiphertext<GgswCont>,
    glwe: &GlweCiphertext<InputGlweCont>,
    fft: FftView<'_>,
    stack: PodStack<'_>,
) where
    Scalar: UnsignedTorus,
    OutputGlweCont: ContainerMut<Element = Scalar>,
    GgswCont: Container<Element = c64>,
    InputGlweCont: Container<Element = Scalar>,
{
    assert_eq!(out.ciphertext_modulus(), glwe.ciphertext_modulus());

    impl_add_external_product_assign(out.as_mut_view(), ggsw.as_view(), glwe, fft, stack);

    let ciphertext_modulus = out.ciphertext_modulus();
    if !ciphertext_modulus.is_native_modulus() {
        // When we convert back from the fourier domain, integer values will contain up to 53
        // MSBs with information. In our representation of power of 2 moduli < native modulus we
        // fill the MSBs and leave the LSBs empty, this usage of the signed decomposer allows to
        // round while keeping the data in the MSBs
        let signed_decomposer = SignedDecomposer::new(
            DecompositionBaseLog(ciphertext_modulus.get_custom_modulus().ilog2() as usize),
            DecompositionLevelCount(1),
        );
        out.as_mut()
            .iter_mut()
            .for_each(|x| *x = signed_decomposer.closest_representable(*x));
    }
}

/// Return the required memory for [`add_external_product_fast_keyswitch_assign_mem_optimized`].
pub fn add_external_product_fast_keyswitch_assign_mem_optimized_requirement<Scalar>(
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    //Trick to rebrand the dimension as a size to avoid code duplication
    impl_add_external_product_assign_scratch::<Scalar>(
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        fft,
    )
}
