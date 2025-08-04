pub mod fft128_pbs;
pub mod fft64_pbs;
pub mod ntt64_bnf_pbs;
pub mod ntt64_pbs;

pub use fft128_pbs::*;
pub use fft64_pbs::*;
pub use ntt64_bnf_pbs::*;
pub use ntt64_pbs::*;

use crate::core_crypto::algorithms::glwe_encryption::allocate_and_trivially_encrypt_new_glwe_ciphertext;
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
    // N/(p/2) = size of each block, to correct noise from the input we introduce the
    // notion of box, which manages redundancy to yield a denoised value
    // for several noisy values around a true input value.
    let box_size = polynomial_size.0 / message_modulus;

    // Create the accumulator
    let mut accumulator_scalar = vec![Scalar::ZERO; polynomial_size.0];

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

    // Rotate the accumulator
    accumulator_scalar.rotate_left(half_box_size);

    let accumulator_plaintext = PlaintextList::from_container(accumulator_scalar);

    allocate_and_trivially_encrypt_new_glwe_ciphertext(
        glwe_size,
        &accumulator_plaintext,
        ciphertext_modulus,
    )
}

// ============== Noise measurement trait implementations ============== //
use crate::core_crypto::commons::noise_formulas::noise_simulation::traits::AllocateLweBootstrapResult;

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
