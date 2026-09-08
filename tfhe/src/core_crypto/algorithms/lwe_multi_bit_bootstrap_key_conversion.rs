//! Module containing primitives pertaining to the conversion of
//! [`standard LWE multi_bit bootstrap keys`](`LweMultiBitBootstrapKey`) to various
//! representations/numerical domains like the Fourier domain.

use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::math::ntt::ntt64::Ntt64;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft128::math::fft::Fft128;
use crate::core_crypto::fft_impl::fft64::math::fft::{
    par_convert_polynomials_list_to_fourier, Fft, FftView,
};

use dyn_stack::{PodStack, StackReq};
use rayon::prelude::*;
use tfhe_fft::c64;

/// Convert an [`LWE multi_bit bootstrap key`](`LweMultiBitBootstrapKey`) with standard
/// coefficients to the Fourier domain.
///
/// See [`multi_bit_programmable_bootstrap_lwe_ciphertext`](`crate::core_crypto::algorithms::multi_bit_programmable_bootstrap_lwe_ciphertext`) for usage.
pub fn convert_standard_lwe_multi_bit_bootstrap_key_to_fourier<Scalar, InputCont, OutputCont>(
    input_bsk: &LweMultiBitBootstrapKey<InputCont>,
    output_bsk: &mut FourierLweMultiBitBootstrapKey<OutputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
{
    let mut buffers = ComputationBuffers::new();

    let fft = Fft::new(input_bsk.polynomial_size());
    let fft = fft.as_view();

    buffers.resize(
        convert_standard_lwe_multi_bit_bootstrap_key_to_fourier_mem_optimized_requirement(fft)
            .unaligned_bytes_required(),
    );

    let stack = buffers.stack();

    convert_standard_lwe_multi_bit_bootstrap_key_to_fourier_mem_optimized(
        input_bsk, output_bsk, fft, stack,
    );
}

/// Memory optimized version of [`convert_standard_lwe_multi_bit_bootstrap_key_to_fourier`].
pub fn convert_standard_lwe_multi_bit_bootstrap_key_to_fourier_mem_optimized<
    Scalar,
    InputCont,
    OutputCont,
>(
    input_bsk: &LweMultiBitBootstrapKey<InputCont>,
    output_bsk: &mut FourierLweMultiBitBootstrapKey<OutputCont>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
{
    let mut output_bsk_as_polynomial_list = output_bsk.as_mut_polynomial_list();
    let input_bsk_as_polynomial_list = input_bsk.as_polynomial_list();

    assert_eq!(
        output_bsk_as_polynomial_list.polynomial_count(),
        input_bsk_as_polynomial_list.polynomial_count()
    );

    for (fourier_poly, coef_poly) in output_bsk_as_polynomial_list
        .iter_mut()
        .zip(input_bsk_as_polynomial_list.iter())
    {
        // SAFETY: forward_as_torus doesn't write any uninitialized values into its output
        fft.forward_as_torus(fourier_poly, coef_poly, stack);
    }
}

/// Return the required memory for
/// [`convert_standard_lwe_multi_bit_bootstrap_key_to_fourier_mem_optimized`].
pub fn convert_standard_lwe_multi_bit_bootstrap_key_to_fourier_mem_optimized_requirement(
    fft: FftView<'_>,
) -> StackReq {
    fft.forward_scratch()
}

pub fn par_convert_standard_lwe_multi_bit_bootstrap_key_to_fourier<Scalar, InputCont, OutputCont>(
    input_bsk: &LweMultiBitBootstrapKey<InputCont>,
    output_bsk: &mut FourierLweMultiBitBootstrapKey<OutputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = c64>,
{
    let fft = Fft::new(input_bsk.polynomial_size());
    let fft = fft.as_view();

    par_convert_polynomials_list_to_fourier(
        output_bsk.as_mut_view().data(),
        input_bsk.as_view().into_container(),
        input_bsk.polynomial_size(),
        fft,
    );
}

pub fn par_convert_standard_lwe_multi_bit_bootstrap_key_to_fourier_128<
    Scalar,
    InputCont,
    OutputCont,
>(
    input_bsk: &LweMultiBitBootstrapKey<InputCont>,
    output_bsk: &mut Fourier128LweMultiBitBootstrapKey<OutputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = f64>,
{
    let fft = Fft128::new(input_bsk.polynomial_size());
    let fft = fft.as_view();

    assert_eq!(input_bsk.polynomial_size(), output_bsk.polynomial_size());

    let fourier_poly_size = output_bsk.polynomial_size().to_fourier_polynomial_size();

    let (data_re0, data_re1, data_im0, data_im1) = output_bsk.as_mut_view().data();

    data_re0
        .par_chunks_exact_mut(fourier_poly_size.0)
        .zip(
            data_re1.par_chunks_exact_mut(fourier_poly_size.0).zip(
                data_im0
                    .par_chunks_exact_mut(fourier_poly_size.0)
                    .zip(data_im1.par_chunks_exact_mut(fourier_poly_size.0)),
            ),
        )
        .zip(input_bsk.as_polynomial_list().par_iter())
        .for_each(
            |((fourier_re0, (fourier_re1, (fourier_im0, fourier_im1))), coef_poly)| {
                fft.forward_as_torus(
                    fourier_re0,
                    fourier_re1,
                    fourier_im0,
                    fourier_im1,
                    coef_poly.as_ref(),
                );
            },
        );
}

/// Check the inputs of the modulus switch of an [`LweMultiBitBootstrapKey`] to the modulus of a 64
/// bits NTT and return the corresponding [`Ntt64`] along with the width of the (power of two) input
/// modulus.
fn modulus_switch_lwe_multi_bit_bootstrap_key_to_ntt64_modulus_setup<InputCont, OutputCont>(
    input_bsk: &LweMultiBitBootstrapKey<InputCont>,
    output_bsk: &LweMultiBitBootstrapKey<OutputCont>,
) -> (Ntt64, u32)
where
    InputCont: Container<Element = u64>,
    OutputCont: Container<Element = u64>,
{
    assert_eq!(
        input_bsk.polynomial_size(),
        output_bsk.polynomial_size(),
        "Mismatched PolynomialSize between input_bsk {:?} and output_bsk {:?}",
        input_bsk.polynomial_size(),
        output_bsk.polynomial_size(),
    );

    assert_eq!(
        input_bsk.glwe_size(),
        output_bsk.glwe_size(),
        "Mismatched GlweSize between input_bsk {:?} and output_bsk {:?}",
        input_bsk.glwe_size(),
        output_bsk.glwe_size(),
    );

    assert_eq!(
        input_bsk.decomposition_base_log(),
        output_bsk.decomposition_base_log(),
        "Mismatched DecompositionBaseLog between input_bsk {:?} and output_bsk {:?}",
        input_bsk.decomposition_base_log(),
        output_bsk.decomposition_base_log(),
    );

    assert_eq!(
        input_bsk.decomposition_level_count(),
        output_bsk.decomposition_level_count(),
        "Mismatched DecompositionLevelCount between input_bsk {:?} and output_bsk {:?}",
        input_bsk.decomposition_level_count(),
        output_bsk.decomposition_level_count(),
    );

    assert_eq!(
        input_bsk.input_lwe_dimension(),
        output_bsk.input_lwe_dimension(),
        "Mismatched input LweDimension between input_bsk {:?} and output_bsk {:?}",
        input_bsk.input_lwe_dimension(),
        output_bsk.input_lwe_dimension(),
    );

    assert_eq!(
        input_bsk.grouping_factor(),
        output_bsk.grouping_factor(),
        "Mismatched LweBskGroupingFactor between input_bsk {:?} and output_bsk {:?}",
        input_bsk.grouping_factor(),
        output_bsk.grouping_factor(),
    );

    assert!(
        input_bsk
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "The input_bsk is required to have a power of two CiphertextModulus, got {:?}",
        input_bsk.ciphertext_modulus(),
    );

    assert!(
        !output_bsk
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "The output_bsk is required to have a non power of two (NTT prime) CiphertextModulus, \
        got {:?}",
        output_bsk.ciphertext_modulus(),
    );

    // Also checks that the output modulus is usable with a 64 bits NTT of the given size
    let ntt = Ntt64::new(
        output_bsk.ciphertext_modulus(),
        output_bsk.polynomial_size(),
    );

    let input_modulus_width = ntt
        .as_view()
        .modswitch_requirement(input_bsk.ciphertext_modulus())
        .unwrap();

    (ntt, input_modulus_width)
}

/// Switch the modulus of an [`LWE multi_bit bootstrap key`](`LweMultiBitBootstrapKey`) having a
/// power of two [`CiphertextModulus`](`crate::core_crypto::commons::parameters::CiphertextModulus`)
/// to the (prime) modulus of the `output_bsk`, which is required to be usable with a 64 bits NTT
/// for the [`PolynomialSize`](`crate::core_crypto::commons::parameters::PolynomialSize`) of the
/// key.
///
/// The output key stays in the standard (coefficient) domain, this is the key format expected by
/// the 64 bits NTT "back and forth" multi-bit programmable bootstrapping.
///
/// See [`multi_bit_programmable_bootstrap_ntt64_bnf_lwe_ciphertext`](`crate::core_crypto::algorithms::multi_bit_programmable_bootstrap_ntt64_bnf_lwe_ciphertext`) for usage.
pub fn modulus_switch_lwe_multi_bit_bootstrap_key_to_ntt64_modulus<InputCont, OutputCont>(
    input_bsk: &LweMultiBitBootstrapKey<InputCont>,
    output_bsk: &mut LweMultiBitBootstrapKey<OutputCont>,
) where
    InputCont: Container<Element = u64>,
    OutputCont: ContainerMut<Element = u64>,
{
    let (ntt, input_modulus_width) =
        modulus_switch_lwe_multi_bit_bootstrap_key_to_ntt64_modulus_setup(input_bsk, output_bsk);
    let ntt = ntt.as_view();

    output_bsk.as_mut().copy_from_slice(input_bsk.as_ref());
    ntt.modswitch_from_power_of_two_to_ntt_prime(input_modulus_width, output_bsk.as_mut());
}
