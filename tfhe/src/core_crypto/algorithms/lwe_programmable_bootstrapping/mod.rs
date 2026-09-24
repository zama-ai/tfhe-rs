pub mod fft128_pbs;
pub mod fft64_pbs;
pub mod karatsuba_pbs;
pub mod ntt64_bnf_pbs;
pub mod ntt64_pbs;

pub use fft128_pbs::*;
pub use fft64_pbs::*;
pub use karatsuba_pbs::*;
pub use ntt64_bnf_pbs::*;
pub use ntt64_pbs::*;

use crate::core_crypto::algorithms::slice_algorithms::slice_wrapping_scalar_mul_assign;
use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulusKind;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Helper function to generate an accumulator for a PBS
///
/// message_modulus is the number of values that can be encoded (without filling the padding bit)
/// it must be a power of 2
///
/// delta is a constant by which the outputs of the LUT are scaled to be encoded
///
/// see [programmable_bootstrap_lwe_ciphertext#example] for usage
pub fn generate_programmable_bootstrap_glwe_lut<F, Scalar: UnsignedTorus + CastFrom<usize>>(
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    message_modulus: usize,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    delta: Scalar,
    f: F,
) -> GlweCiphertextOwned<Scalar>
where
    F: Fn(Scalar) -> Scalar,
{
    let mut lut =
        GlweCiphertextOwned::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);

    fill_programmable_bootstrap_glwe_lut(&mut lut, message_modulus, delta, f);

    lut
}

/// Variant of [`generate_programmable_bootstrap_glwe_lut`] writing into an already allocated
/// [`GlweCiphertext`], whose previous content is entirely overwritten.
pub fn fill_programmable_bootstrap_glwe_lut<F, Scalar, OutputCont>(
    lut: &mut GlweCiphertext<OutputCont>,
    message_modulus: usize,
    delta: Scalar,
    f: F,
) where
    Scalar: UnsignedTorus + CastFrom<usize>,
    OutputCont: ContainerMut<Element = Scalar>,
    F: Fn(Scalar) -> Scalar,
{
    let polynomial_size = lut.polynomial_size();

    assert!(message_modulus.is_power_of_two());
    assert!(polynomial_size.0.is_multiple_of(message_modulus));

    // N = polynomial_size
    // p = message_modulus
    // N/p = size of each box, to correct noise from the input we introduce the
    // notion of box, which manages redundancy to yield a denoised value
    // for several noisy values around a true input value.
    let box_size = polynomial_size.0 / message_modulus;
    let ciphertext_modulus = lut.ciphertext_modulus();

    let (mut mask, mut body) = lut.get_mut_mask_and_body();
    mask.as_mut().fill(Scalar::ZERO);
    let accumulator_scalar = body.as_mut();

    // Fill each box with the encoded denoised value
    for i in 0..message_modulus {
        let index = i * box_size;
        accumulator_scalar[index..index + box_size]
            .iter_mut()
            .for_each(|a| *a = f(Scalar::cast_from(i)) * delta);
    }

    let half_box_size = box_size / 2;

    if ciphertext_modulus.is_compatible_with_native_modulus() {
        // Negate the first half_box_size coefficients to manage negacyclicity and rotate
        for a_i in accumulator_scalar[0..half_box_size].iter_mut() {
            *a_i = (*a_i).wrapping_neg();
        }
    } else {
        let modulus: Scalar = ciphertext_modulus.get_custom_modulus().cast_into();
        for a_i in accumulator_scalar[0..half_box_size].iter_mut() {
            *a_i = (*a_i).wrapping_neg_custom_mod(modulus);
        }
    }

    accumulator_scalar.rotate_left(half_box_size);

    // Manage the non native power of 2 encoding
    if ciphertext_modulus.kind() == CiphertextModulusKind::NonNativePowerOfTwo {
        slice_wrapping_scalar_mul_assign(
            accumulator_scalar,
            ciphertext_modulus.get_power_of_two_scaling_to_native_torus(),
        );
    }
}

// ============== Noise measurement trait implementations ============== //
use crate::core_crypto::commons::noise_formulas::noise_simulation::traits::{
    AllocateLweBootstrapResult, AllocateLweMultiBitBlindRotateResult,
};

impl<Scalar: UnsignedInteger, AccCont: Container<Element = Scalar>> AllocateLweBootstrapResult
    for GlweCiphertext<AccCont>
{
    type Output = LweCiphertextOwned<Scalar>;
    type SideResources = ();

    fn allocate_lwe_bootstrap_result(
        &self,
        _side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        let glwe_dim = self.glwe_size().to_glwe_dimension();
        let poly_size = self.polynomial_size();
        let equivalent_lwe_dim = glwe_dim.to_equivalent_lwe_dimension(poly_size);

        LweCiphertext::new(
            Scalar::ZERO,
            equivalent_lwe_dim.to_lwe_size(),
            self.ciphertext_modulus(),
        )
    }
}

impl<Scalar: UnsignedInteger, AccCont: Container<Element = Scalar>>
    AllocateLweMultiBitBlindRotateResult for GlweCiphertext<AccCont>
{
    type Output = LweCiphertextOwned<Scalar>;
    type SideResources = ();

    fn allocate_lwe_multi_bit_blind_rotate_result(
        &self,
        _side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        let glwe_dim = self.glwe_size().to_glwe_dimension();
        let poly_size = self.polynomial_size();
        let equivalent_lwe_dim = glwe_dim.to_equivalent_lwe_dimension(poly_size);

        LweCiphertext::new(
            Scalar::ZERO,
            equivalent_lwe_dim.to_lwe_size(),
            self.ciphertext_modulus(),
        )
    }
}
