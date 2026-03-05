//! Experimental module containing implementations of extended bootstrapping algorithms.
//!
//! See [this paper](https://eprint.iacr.org/2025/2214.pdf).

use crate::core_crypto::algorithms::glwe_linear_algebra::glwe_ciphertext_sub_assign;
use crate::core_crypto::algorithms::glwe_sample_extraction::extract_lwe_sample_from_glwe_ciphertext;
use crate::core_crypto::algorithms::modulus_switch::{
    lwe_ciphertext_modulus_switch, ModulusSwitchedLweCiphertext,
};
use crate::core_crypto::algorithms::polynomial_algorithms::{
    polynomial_wrapping_monic_monomial_div, polynomial_wrapping_monic_monomial_mul,
};
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::{CastInto, UnsignedInteger};
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, MonomialDegree, PolynomialSize,
};
use crate::core_crypto::commons::traits::{
    Container, ContainerMut, ContiguousEntityContainer, ContiguousEntityContainerMut,
};
use crate::core_crypto::entities::glwe_ciphertext::GlweCiphertext;
use crate::core_crypto::entities::lwe_ciphertext::LweCiphertext;
use crate::core_crypto::experimental::commons::parameters::LweBootstrapExtensionFactor;
use crate::core_crypto::fft_impl::fft64::c64;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::FourierLweBootstrapKey;
use crate::core_crypto::fft_impl::fft64::crypto::ggsw::{
    add_external_product_assign, add_external_product_assign_scratch,
};
use crate::core_crypto::fft_impl::fft64::math::fft::FftView;
use aligned_vec::CACHELINE_ALIGN;
use dyn_stack::{PodStack, StackReq};
use itertools::izip;

use std::cell::UnsafeCell;

#[derive(Copy, Clone)]
pub struct UnsafeSlice<'a, T> {
    slice: &'a [UnsafeCell<T>],
}
unsafe impl<T: Send + Sync> Send for UnsafeSlice<'_, T> {}
unsafe impl<T: Send + Sync> Sync for UnsafeSlice<'_, T> {}

impl<'a, T> UnsafeSlice<'a, T> {
    pub fn new(slice: &'a mut [T]) -> Self {
        let ptr = std::ptr::from_mut::<[T]>(slice) as *const [UnsafeCell<T>];
        Self {
            slice: unsafe { &*ptr },
        }
    }

    /// # Safety
    ///
    /// The caller must make sure that no concurrent read and write access occur for a given index
    pub unsafe fn read(&self, idx: usize) -> &T {
        let ptr = self.slice[idx].get();
        &*ptr
    }

    /// # Safety
    ///
    /// The caller must make sure that no concurrent read and write access occur for a given index
    #[allow(clippy::mut_from_ref)] // that's the point of the UnsafeSlice in that case
    pub unsafe fn write(&self, idx: usize) -> &mut T {
        let ptr = self.slice[idx].get();
        &mut *ptr
    }
}

/// Requires all GlweCiphertexts in `split_luts` to have the same GlweSize and PolynomialSize and
/// the input `lut` PolynomialSize to be equal to : small_luts PolynomialSize times extension_factor
pub fn unchecked_split_extended_lut_into_small_luts<Scalar, ExtendedLutCont, SplitLutCont>(
    lut: &GlweCiphertext<ExtendedLutCont>,
    split_luts: &mut [GlweCiphertext<SplitLutCont>],
    extension_factor: LweBootstrapExtensionFactor,
) where
    Scalar: UnsignedInteger,
    ExtendedLutCont: Container<Element = Scalar>,
    SplitLutCont: ContainerMut<Element = Scalar>,
{
    for (idx, &coeff) in lut.as_ref().iter().enumerate() {
        let dst_lut = &mut split_luts[idx % extension_factor.get()];
        dst_lut.as_mut()[idx / extension_factor.get()] = coeff;
    }
}

/// Given an hat(ai) = mod_switch(ai, 2*N') where N' = 2^nu * N is the polynomial size of the
/// extended ring; this function gives the monomial multiplication to apply to a small (split) lut
/// to compute the end of the rotation of the corresponding extended lut
///
/// N' = 2^nu * N
///
/// With 2^nu split small LUTs of size N, to compute the full rotation of the extended lut of size
/// N' by X^hat(ai) one needs to:
///
/// Move the lut at old_lut_idx to new_lut_idx:
/// new_lut_idx = (ai + old_lut_idx) % 2^nu
///
/// In the lut at new_lut_idx apply a monomial rotation whose exponent is:
/// exponent = (2^nu + hat(ai) - 1 - new_lut_idx) / 2^nu
///
/// The result of this function is the above exponent.
/// `extended_lut_monomial_degree` is hat(ai)
/// `extension_factor` is 2^nu
///
/// Explanation of the formula:
///
/// All rotations are negacyclic:
///
/// with N = 2 and extension_factor = ef = 2^nu = 4
/// N' = 2^nu * N = ef * N = 8
///
/// a0_b0_c0_d0_a1_b1_c1_d1 as list of ef small LUTs each of size N [a0_a1, b0_b1, c0_c1, d0_d1]
///
/// rotated by 1:
/// -d1_a0_b0_c0_d0_a1_b1_c1 as list of small LUTs [-d1_d0, a0_a1, b0_b1, c0_c1]
///
/// Rotating the big LUT by 1 to the right corresponds to rotating the list of small LUTs by 1 then
/// the first small lut (which was the last one) by 1.
///
/// A rotation by ai corresponds to ai rotations by 1.
///
/// Let's divide ai by ef as ai = k * ef + r (remember ai is modulo 2*N' during the blind rotation)
///
/// Rotating by ef is equivalent to rotating each small LUT by 1.
/// Rotating by k * ef is equivalent to rotating each small LUT by k.
/// Then rotating by r is equivalent to rotating the list of LUTs by r and then the first r small
/// LUTs (which were the last ones) by 1.
///
/// In the end,
///
/// With j=new_lut_idx indexing on the output small LUTs list
///
/// new_small_LUT[j] = if j < r {
///     rotate(small_LUT[ef + j - r], k+1)
/// } else {
///     rotate(small_LUT[j - r], k)
/// }
///
/// new_small_LUT[j] = rotate(small_LUT[(ef + j - r)%ef], if j < r { k+1 } else { k })
///
/// (ef + ai - 1 - j)/ef
/// = (ef + k * ef + r - 1 - j)/ef
/// = k + (ef + r - 1 - j)/ef
/// = k + if 0 <= r - 1 - j { 1 } else { 0 }
/// = k + if j+1 <= r  { 1 } else { 0 }
/// = k + if j < r { 1 } else { 0 }
///
/// In the end:
/// new_small_LUT[j] = rotate(small_LUT[(ef + j - r)%ef], (ef + ai - 1 - j)/ef)
pub(crate) fn small_lut_monomial_degree_from_extended_lut_monomial_degree(
    extended_lut_monomial_degree: MonomialDegree,
    extension_factor: LweBootstrapExtensionFactor,
    // The index of the small lut being rotated
    new_lut_idx: usize,
) -> MonomialDegree {
    // extension_factor being a power of two we shift by the ilog2 to divide by extension_factor
    MonomialDegree(
        (extension_factor.get() + extended_lut_monomial_degree.0 - 1 - new_lut_idx)
            >> extension_factor.get().ilog2(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn extended_programmable_bootstrap_lwe_ciphertext_mem_optimized_parallelized<
    Scalar,
    KeyCont,
    OutputCont,
    InputCont,
    AccCont,
>(
    bsk: &FourierLweBootstrapKey<KeyCont>,
    lwe_out: &mut LweCiphertext<OutputCont>,
    lwe_in: &LweCiphertext<InputCont>,
    accumulator: &GlweCiphertext<AccCont>,
    extension_factor: LweBootstrapExtensionFactor,
    fft: FftView<'_>,
    stack: &mut PodStack,
    thread_buffers: &mut [&mut PodStack],
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
    KeyCont: Container<Element = c64> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    AccCont: Container<Element = Scalar>,
{
    assert_eq!(
        lwe_out.ciphertext_modulus(),
        accumulator.ciphertext_modulus()
    );

    assert_eq!(
        bsk.polynomial_size().0 * extension_factor.get(),
        accumulator.polynomial_size().0
    );

    // For the extended bootstrap the mod switch is done using the extended polynomial size
    let msed = lwe_ciphertext_modulus_switch(
        lwe_in.as_view(),
        accumulator
            .polynomial_size()
            .to_blind_rotation_input_modulus_log(),
    );

    extended_programmable_bootstrap_lwe_ciphertext_mem_optimized_parallelized_impl(
        bsk,
        extension_factor,
        accumulator,
        &msed,
        lwe_out.as_mut_view(),
        fft,
        stack,
        thread_buffers,
    );
}

#[allow(clippy::too_many_arguments)]
fn extended_programmable_bootstrap_lwe_ciphertext_mem_optimized_parallelized_impl<
    Scalar,
    KeyCont,
    LutCont,
    MsedLwe,
>(
    bsk: &FourierLweBootstrapKey<KeyCont>,
    extension_factor: LweBootstrapExtensionFactor,
    input_lut: &GlweCiphertext<LutCont>,
    msed_lwe: &MsedLwe,
    mut lwe_out: LweCiphertext<&mut [Scalar]>,
    fft: FftView<'_>,
    stack: &mut PodStack,
    thread_stacks: &mut [&mut PodStack],
) where
    Scalar: UnsignedTorus + CastInto<usize>,
    KeyCont: Container<Element = c64> + Sync,
    LutCont: Container<Element = Scalar>,
    MsedLwe: ModulusSwitchedLweCiphertext<usize> + Sync,
{
    assert_eq!(thread_stacks.len(), extension_factor.get());

    let lut_poly_size = input_lut.polynomial_size();
    let ciphertext_modulus = input_lut.ciphertext_modulus();

    assert!(ciphertext_modulus.is_compatible_with_native_modulus());
    assert_eq!(
        bsk.polynomial_size().0 * extension_factor.get(),
        lut_poly_size.0
    );
    assert_eq!(
        msed_lwe.log_modulus(),
        lut_poly_size.to_blind_rotation_input_modulus_log()
    );

    let monomial_degree = MonomialDegree(msed_lwe.body());

    let (lut_data, stack) = stack.make_aligned_raw(input_lut.as_ref().len(), CACHELINE_ALIGN);

    let mut lut = GlweCiphertext::from_container(
        &mut *lut_data,
        input_lut.polynomial_size(),
        input_lut.ciphertext_modulus(),
    );

    lut.as_mut_polynomial_list()
        .iter_mut()
        .zip(input_lut.as_polynomial_list().iter())
        .for_each(|(mut dst_poly, src_poly)| {
            polynomial_wrapping_monic_monomial_div(&mut dst_poly, &src_poly, monomial_degree)
        });

    // Remove mutability to make things more readable and use 0/1 notation to refer to computation
    // buffers
    let ct0 = lut;

    let mut split_ct0 = Vec::with_capacity(extension_factor.get());
    let mut split_ct1 = Vec::with_capacity(extension_factor.get());

    let substack0 = {
        let mut current_stack = stack;
        for _ in 0..extension_factor.get() {
            let (glwe_cont, substack) = current_stack.make_aligned_raw::<Scalar>(
                bsk.glwe_size().0 * bsk.polynomial_size().0,
                CACHELINE_ALIGN,
            );
            split_ct0.push(GlweCiphertext::from_container(
                glwe_cont,
                bsk.polynomial_size(),
                ciphertext_modulus,
            ));
            current_stack = substack;
        }
        current_stack
    };

    let _substack1 = {
        let mut current_stack = substack0;
        for _ in 0..extension_factor.get() {
            let (glwe_cont, substack) = current_stack.make_aligned_raw::<Scalar>(
                bsk.glwe_size().0 * bsk.polynomial_size().0,
                CACHELINE_ALIGN,
            );
            split_ct1.push(GlweCiphertext::from_container(
                glwe_cont,
                bsk.polynomial_size(),
                ciphertext_modulus,
            ));
            current_stack = substack;
        }
        current_stack
    };

    unchecked_split_extended_lut_into_small_luts(&ct0, &mut split_ct0, extension_factor);

    let thread_split_ct0 = UnsafeSlice::new(&mut split_ct0);
    let thread_split_ct1 = UnsafeSlice::new(&mut split_ct1);

    use std::sync::Barrier;
    let barrier = Barrier::new(extension_factor.get());

    std::thread::scope(|s| {
        let thread_processing = |id: usize, stack: &mut PodStack| {
            // ===== Setup thread local resources =====
            let ct_dst_idx = id;
            let extension_factor_rem_mask = extension_factor.get() - 1;

            let (diff_dyn_array, stack) = stack.make_aligned_raw::<Scalar>(
                bsk.glwe_size().0 * bsk.polynomial_size().0,
                CACHELINE_ALIGN,
            );

            let mut diff_buffer = GlweCiphertext::from_container(
                diff_dyn_array,
                bsk.polynomial_size(),
                ciphertext_modulus,
            );

            // ===== Perform the subpart of the rotation the thread is responsible for =====
            for (mask_idx, (monomial_degree, ggsw)) in msed_lwe
                .mask()
                .map(MonomialDegree)
                .zip(bsk.as_view().into_ggsw_iter())
                .enumerate()
            {
                // Update the LUT the current thread looks at simulating the rotation in the
                // extended LUT
                //
                // One thread is responsible of a destination LUT index at all times (alternating
                // between two work buffers), we simulate the rotation by seeing which "source" LUT
                // would end up in the index the thread is responsible for, this avoids memory
                // copies
                //
                // The index mapping combined with a well chosen monomial multiplication simulates
                // the rotation in the extended LUT from rotations of the small split LUTs
                let ct_src_idx =
                    (ct_dst_idx.wrapping_sub(monomial_degree.0)) & extension_factor_rem_mask;

                // The well chosen monomial degree allowing to complete the simulated rotation in
                // the extended LUT, see function comment for the formula
                let small_monomial_degree =
                    small_lut_monomial_degree_from_extended_lut_monomial_degree(
                        monomial_degree,
                        extension_factor,
                        ct_dst_idx,
                    );

                let rotated_buffer = {
                    let (src_to_rotate, dst_rotated, src_unrotated) = if (mask_idx % 2) == 0 {
                        unsafe {
                            (
                                thread_split_ct0.read(ct_src_idx),
                                thread_split_ct1.write(ct_dst_idx),
                                thread_split_ct0.read(ct_dst_idx),
                            )
                        }
                    } else {
                        unsafe {
                            (
                                thread_split_ct1.read(ct_src_idx),
                                thread_split_ct0.write(ct_dst_idx),
                                thread_split_ct1.read(ct_dst_idx),
                            )
                        }
                    };

                    // Prepare the destination for the ext prod by copying the unrotated
                    // accumulator there
                    dst_rotated.as_mut().copy_from_slice(src_unrotated.as_ref());

                    for (mut diff_poly, src_to_rotate_poly) in izip!(
                        diff_buffer.as_mut_polynomial_list().iter_mut(),
                        src_to_rotate.as_polynomial_list().iter(),
                    ) {
                        // Rotate the lut that ends up in our slot and add to the
                        // destination
                        // This is computing Rot(ACCj)
                        polynomial_wrapping_monic_monomial_mul(
                            &mut diff_poly,
                            &src_to_rotate_poly,
                            small_monomial_degree,
                        );
                    }

                    // This is computing Rot(ACCj) - ACCj
                    glwe_ciphertext_sub_assign(&mut diff_buffer, src_unrotated);

                    dst_rotated
                };

                // ACCj ← BSKi x (Rot(ACCj) - ACCj) + ACCj
                add_external_product_assign(
                    rotated_buffer.as_mut_view(),
                    ggsw,
                    diff_buffer.as_view(),
                    fft,
                    stack,
                );

                let _ = barrier.wait();
            }
        };

        #[allow(clippy::needless_collect)]
        let threads: Vec<_> = thread_stacks
            .iter_mut()
            .enumerate()
            .map(|(id, stack)| s.spawn(move || thread_processing(id, stack)))
            .collect();

        for t in threads {
            t.join().unwrap();
        }
    });

    let lwe_dimension = bsk.input_lwe_dimension().0;
    let buffer_to_use = if lwe_dimension.is_multiple_of(2) {
        split_ct0
    } else {
        split_ct1
    };

    let mut lut_0 = buffer_to_use.into_iter().next().unwrap();

    if !ciphertext_modulus.is_native_modulus() {
        // When we convert back from the fourier domain, integer values will contain up to 53
        // MSBs with information. In our representation of power of 2 moduli < native modulus we
        // fill the MSBs and leave the LSBs empty, this usage of the signed decomposer allows to
        // round while keeping the data in the MSBs
        let signed_decomposer = SignedDecomposer::new(
            DecompositionBaseLog(ciphertext_modulus.get_custom_modulus().ilog2() as usize),
            DecompositionLevelCount(1),
        );
        lut_0
            .as_mut()
            .iter_mut()
            .for_each(|x| *x = signed_decomposer.closest_representable(*x));
    }

    let split_accumulator = GlweCiphertext::from_container(
        lut_0.as_ref().to_vec(),
        lut_0.polynomial_size(),
        lut_0.ciphertext_modulus(),
    );

    extract_lwe_sample_from_glwe_ciphertext(&split_accumulator, &mut lwe_out, MonomialDegree(0));
}

/// Return the required memory for
/// [`extended_programmable_bootstrap_lwe_ciphertext_mem_optimized_parallelized`].
pub fn extended_programmable_bootstrap_lwe_ciphertext_mem_optimized_parallelized_requirement<
    OutputScalar,
>(
    glwe_size: GlweSize,
    small_polynomial_size: PolynomialSize,
    extension_factor: LweBootstrapExtensionFactor,
    fft: FftView<'_>,
) -> StackReq {
    let local_accumulator_req = StackReq::new_aligned::<OutputScalar>(
        glwe_size.0 * small_polynomial_size.0 * extension_factor.get(),
        CACHELINE_ALIGN,
    );

    // split ct0 allocation
    // we need (k + 1) * N * 2^nu
    let split_ct0_req = StackReq::new_aligned::<OutputScalar>(
        glwe_size.0 * small_polynomial_size.0 * extension_factor.get(),
        CACHELINE_ALIGN,
    );

    // split ct1 allocation
    // we need (k + 1) * N * 2^nu
    let split_ct1_req = StackReq::new_aligned::<OutputScalar>(
        glwe_size.0 * small_polynomial_size.0 * extension_factor.get(),
        CACHELINE_ALIGN,
    );

    StackReq::all_of(&[
        local_accumulator_req,
        split_ct0_req,
        split_ct1_req,
        // diff_buffer allocation
        // we need (k + 1) * N
        StackReq::new_aligned::<OutputScalar>(
            glwe_size.0 * small_polynomial_size.0,
            CACHELINE_ALIGN,
        ),
        // external product
        add_external_product_assign_scratch::<OutputScalar>(glwe_size, small_polynomial_size, fft),
    ])
}
