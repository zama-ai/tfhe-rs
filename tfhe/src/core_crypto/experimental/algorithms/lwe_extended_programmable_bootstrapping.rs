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
use crate::core_crypto::entities::glwe_ciphertext::{GlweCiphertext, GlweCiphertextOwned};
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
pub fn split_extended_lut_into_small_luts<Scalar, ExtendedLutCont, SplitLutCont>(
    lut: &GlweCiphertext<ExtendedLutCont>,
    split_luts: &mut [GlweCiphertext<SplitLutCont>],
    extension_factor: LweBootstrapExtensionFactor,
) where
    Scalar: UnsignedInteger,
    ExtendedLutCont: Container<Element = Scalar>,
    SplitLutCont: ContainerMut<Element = Scalar>,
{
    for (idx, &coeff) in lut.as_ref().iter().enumerate() {
        let dst_lut = &mut split_luts[idx % extension_factor.0];
        dst_lut.as_mut()[idx / extension_factor.0] = coeff;
    }
}

/// Given an ai mod switched under the extended polynomial size N' = 2^nu * N
/// This function gives the monomial multiplication to apply to a small (split) lut to compute the
/// end of the rotation
/// N' = 2^nu * N
/// new_lut_idx = (ai + old_lut_idx) % 2^nu
/// (2^nu + (ai % 2N') - 1 - new_lut_idx)/2^nu seems to work for the multiplication by X^ai
pub(crate) fn small_lut_monomial_degree_from_extended_lut_monomial_degree(
    extended_lut_monomial_degree: MonomialDegree,
    extension_factor: LweBootstrapExtensionFactor,
    // The index of the small lut being rotated
    small_lut_idx: usize,
) -> MonomialDegree {
    MonomialDegree(
        (extension_factor.0 + extended_lut_monomial_degree.0 - 1 - small_lut_idx)
            >> extension_factor.0.ilog2(),
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
    // extension factor == 1 means classic bootstrap which is already optimized
    if extension_factor.0 == 1 {
        return bsk.as_view().bootstrap(
            lwe_out.as_mut_view(),
            lwe_in.as_view(),
            accumulator.as_view(),
            fft,
            stack,
        );
    }

    assert_eq!(
        lwe_out.ciphertext_modulus(),
        accumulator.ciphertext_modulus()
    );

    assert_eq!(
        bsk.polynomial_size().0 * extension_factor.0,
        accumulator.polynomial_size().0
    );

    // For the extended bootstrap the mod switch is done using the extended polynomial size
    let msed = lwe_ciphertext_modulus_switch(
        lwe_in.as_view(),
        accumulator
            .polynomial_size()
            .to_blind_rotation_input_modulus_log(),
    );

    // TODO ? use only a split accumulator and an assign primitive ?
    let split_accumulator = extended_blind_rotate_mem_optimized_parallelized(
        bsk,
        accumulator,
        &msed,
        extension_factor,
        fft,
        stack,
        thread_buffers,
    );

    extract_lwe_sample_from_glwe_ciphertext(&split_accumulator, lwe_out, MonomialDegree(0));
}

pub fn extended_blind_rotate_mem_optimized_parallelized<Scalar, KeyCont, LutCont, MsedLwe>(
    bsk: &FourierLweBootstrapKey<KeyCont>,
    input_lut: &GlweCiphertext<LutCont>,
    msed_lwe: &MsedLwe,
    extension_factor: LweBootstrapExtensionFactor,
    fft: FftView<'_>,
    stack: &mut PodStack,
    thread_stacks: &mut [&mut PodStack],
) -> GlweCiphertextOwned<Scalar>
where
    Scalar: UnsignedTorus + CastInto<usize>,
    KeyCont: Container<Element = c64> + Sync,
    LutCont: Container<Element = Scalar>,
    MsedLwe: ModulusSwitchedLweCiphertext<usize> + Sync,
{
    assert_eq!(thread_stacks.len(), extension_factor.0);

    let lut_poly_size = input_lut.polynomial_size();
    let ciphertext_modulus = input_lut.ciphertext_modulus();

    assert!(ciphertext_modulus.is_compatible_with_native_modulus());
    assert_eq!(
        bsk.polynomial_size().0 * extension_factor.0,
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

    let mut split_ct0 = Vec::with_capacity(extension_factor.0);
    let mut split_ct1 = Vec::with_capacity(extension_factor.0);

    let substack0 = {
        let mut current_stack = stack;
        for _ in 0..extension_factor.0 {
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
        for _ in 0..extension_factor.0 {
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

    split_extended_lut_into_small_luts(&ct0, &mut split_ct0, extension_factor);

    let thread_split_ct0 = UnsafeSlice::new(&mut split_ct0);
    let thread_split_ct1 = UnsafeSlice::new(&mut split_ct1);

    use std::sync::Barrier;
    let barrier = Barrier::new(extension_factor.0);

    std::thread::scope(|s| {
        let thread_processing = |id: usize, stack: &mut PodStack| {
            let ct_dst_idx = id;
            let extension_factor_rem_mask = extension_factor.0 - 1;

            let (diff_dyn_array, stack) = stack.make_aligned_raw::<Scalar>(
                bsk.glwe_size().0 * bsk.polynomial_size().0,
                CACHELINE_ALIGN,
            );

            let mut diff_buffer = GlweCiphertext::from_container(
                diff_dyn_array,
                bsk.polynomial_size(),
                ciphertext_modulus,
            );

            for (mask_idx, (monomial_degree, ggsw)) in msed_lwe
                .mask()
                .map(MonomialDegree)
                .zip(bsk.as_view().into_ggsw_iter())
                .enumerate()
            {
                // Update the lut we look at simulating the rotation in the larger lut
                let ct_src_idx =
                    (ct_dst_idx.wrapping_sub(monomial_degree.0)) & extension_factor_rem_mask;

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

    GlweCiphertext::from_container(
        lut_0.as_ref().to_vec(),
        lut_0.polynomial_size(),
        lut_0.ciphertext_modulus(),
    )
}

/// Return the required memory for [`extended_blind_rotate_mem_optimized_parallelized`].
pub fn extended_blind_rotate_mem_optimized_parallelized_requirement<OutputScalar>(
    glwe_size: GlweSize,
    small_polynomial_size: PolynomialSize,
    extension_factor: LweBootstrapExtensionFactor,
    fft: FftView<'_>,
) -> StackReq {
    let local_accumulator_req = StackReq::new_aligned::<OutputScalar>(
        glwe_size.0 * small_polynomial_size.0 * extension_factor.0,
        CACHELINE_ALIGN,
    );

    // split ct0 allocation
    // we need (k + 1) * N * 2^nu
    let split_ct0_req = StackReq::new_aligned::<OutputScalar>(
        glwe_size.0 * small_polynomial_size.0 * extension_factor.0,
        CACHELINE_ALIGN,
    );

    // split ct1 allocation
    // we need (k + 1) * N * 2^nu
    let split_ct1_req = StackReq::new_aligned::<OutputScalar>(
        glwe_size.0 * small_polynomial_size.0 * extension_factor.0,
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
    extended_blind_rotate_mem_optimized_parallelized_requirement::<OutputScalar>(
        glwe_size,
        small_polynomial_size,
        extension_factor,
        fft,
    )
}
