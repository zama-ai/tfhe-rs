use crate::core_crypto::algorithms::glwe_linear_algebra::glwe_ciphertext_add_assign;
use crate::core_crypto::algorithms::glwe_sample_extraction::extract_lwe_sample_from_glwe_ciphertext;
use crate::core_crypto::algorithms::lwe_multi_bit_programmable_bootstrapping::{
    modulus_switch_multi_bit, selection_bit,
};
use crate::core_crypto::algorithms::lwe_programmable_bootstrapping::fft64::programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement_ly23;
use crate::core_crypto::algorithms::polynomial_algorithms::{
    polynomial_wrapping_monic_monomial_div, polynomial_wrapping_monic_monomial_mul,
};
use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::common::pbs_modulus_switch;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::{bootstrap_ly23_scratch, UnsafeSlice};
use crate::core_crypto::fft_impl::fft64::crypto::ggsw::add_external_product_assign;
use crate::core_crypto::fft_impl::fft64::math::fft::{Fft, FftView};
use aligned_vec::CACHELINE_ALIGN;
use concrete_fft::c64;
use dyn_stack::{PodStack, ReborrowMut, SizeOverflow, StackReq};

pub fn lwe_multi_bit_extended_programmable_bootstrapping<
    Scalar,
    InputCont,
    OutputCont,
    AccCont,
    KeyCont,
>(
    input: &LweCiphertext<InputCont>,
    output: &mut LweCiphertext<OutputCont>,
    accumulator: &GlweCiphertext<AccCont>,
    multi_bit_bsk: &FourierLweMultiBitBootstrapKey<KeyCont>,
    extension_factor: Ly23ExtensionFactor,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Sync,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    AccCont: Container<Element = Scalar>,
    KeyCont: Container<Element = c64> + Sync,
{
    let fft = Fft::new(multi_bit_bsk.polynomial_size());
    let fft = fft.as_view();

    let mut computation_buffers = ComputationBuffers::new();
    computation_buffers.resize(
        multi_bit_programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement_ly23::<Scalar>(
            multi_bit_bsk.glwe_size(),
            multi_bit_bsk.polynomial_size(),
            extension_factor,
            multi_bit_bsk.grouping_factor(),
            fft,
        )
        .unwrap()
        .try_unaligned_bytes_required()
        .unwrap(),
    );

    let mut buffers: Vec<_> = (0..extension_factor.0
        * multi_bit_bsk.grouping_factor().group_power_set_size())
        .map(|_| {
            let mut buffer = ComputationBuffers::new();
            buffer.resize(
                programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement_ly23::<Scalar>(
                    multi_bit_bsk.glwe_size(),
                    multi_bit_bsk.polynomial_size(),
                    extension_factor,
                    fft,
                )
                .unwrap()
                .try_unaligned_bytes_required()
                .unwrap(),
            );
            buffer
        })
        .collect();

    let mut thread_stacks: Vec<_> = buffers.iter_mut().map(|x| x.stack()).collect();

    lwe_multi_bit_extended_programmable_bootstrapping_mem_optimized(
        input,
        output,
        accumulator,
        multi_bit_bsk,
        extension_factor,
        fft,
        computation_buffers.stack(),
        &mut thread_stacks,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn lwe_multi_bit_extended_programmable_bootstrapping_mem_optimized<
    Scalar,
    InputCont,
    OutputCont,
    AccCont,
    KeyCont,
>(
    input: &LweCiphertext<InputCont>,
    output: &mut LweCiphertext<OutputCont>,
    accumulator: &GlweCiphertext<AccCont>,
    multi_bit_bsk: &FourierLweMultiBitBootstrapKey<KeyCont>,
    extension_factor: Ly23ExtensionFactor,
    fft: FftView<'_>,
    stack: PodStack<'_>,
    thread_stacks: &mut [PodStack<'_>],
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Sync,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    AccCont: Container<Element = Scalar>,
    KeyCont: Container<Element = c64> + Sync,
{
    let (mut local_accumulator_data, stack) =
        stack.collect_aligned(CACHELINE_ALIGN, accumulator.as_ref().iter().copied());
    let mut local_accumulator = GlweCiphertextMutView::from_container(
        &mut *local_accumulator_data,
        accumulator.polynomial_size(),
        accumulator.ciphertext_modulus(),
    );

    let split_accumulator = lwe_multi_bit_extended_blind_rotate_assign(
        multi_bit_bsk.as_view(),
        local_accumulator.as_mut_view(),
        input.as_ref(),
        extension_factor,
        fft,
        stack,
        thread_stacks,
    );

    extract_lwe_sample_from_glwe_ciphertext(&split_accumulator, output, MonomialDegree(0));
}

#[allow(clippy::needless_collect)]
#[allow(clippy::needless_pass_by_value)]
pub fn lwe_multi_bit_extended_blind_rotate_assign<Scalar>(
    multi_bit_bsk: FourierLweMultiBitBootstrapKeyView<'_>,
    mut lut: GlweCiphertextMutView<'_, Scalar>,
    lwe: &[Scalar],
    extension_factor: Ly23ExtensionFactor,
    fft: FftView<'_>,
    mut stack: PodStack<'_>,
    thread_stacks: &mut [PodStack<'_>],
) -> GlweCiphertextOwned<Scalar>
where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Sync,
{
    let thread_count = extension_factor.0 * multi_bit_bsk.grouping_factor().group_power_set_size();
    assert_eq!(thread_stacks.len(), thread_count);

    let (lwe_body, lwe_mask) = lwe.split_last().unwrap();

    let lut_poly_size = lut.polynomial_size();
    let ciphertext_modulus = lut.ciphertext_modulus();
    let grouping_factor = multi_bit_bsk.grouping_factor();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());
    assert_eq!(
        multi_bit_bsk.polynomial_size().0 * extension_factor.0,
        lut_poly_size.0
    );
    let monomial_degree = MonomialDegree(pbs_modulus_switch(
        *lwe_body,
        // This one should be the extended polynomial size
        lut_poly_size,
    ));

    lut.as_mut_polynomial_list()
        .iter_mut()
        .for_each(|mut poly| {
            let (mut tmp_poly, _) = stack
                .rb_mut()
                .make_aligned_raw(poly.as_ref().len(), CACHELINE_ALIGN);

            let mut tmp_poly = Polynomial::from_container(&mut *tmp_poly);
            tmp_poly.as_mut().copy_from_slice(poly.as_ref());
            polynomial_wrapping_monic_monomial_div(&mut poly, &tmp_poly, monomial_degree)
        });

    let ct0 = &lut;

    let mut split_ct0 = Vec::with_capacity(thread_count);

    let mut split_ct1 = Vec::with_capacity(thread_count);

    let substack0 = {
        let mut current_stack = stack;
        for _ in 0..thread_count {
            let (glwe_cont, substack) = current_stack.make_aligned_raw::<Scalar>(
                multi_bit_bsk.glwe_size().0 * multi_bit_bsk.polynomial_size().0,
                CACHELINE_ALIGN,
            );
            split_ct0.push(GlweCiphertext::from_container(
                glwe_cont,
                multi_bit_bsk.polynomial_size(),
                ct0.ciphertext_modulus(),
            ));
            current_stack = substack;
        }
        current_stack
    };

    let _substack1 = {
        let mut current_stack = substack0;
        for _ in 0..thread_count {
            let (glwe_cont, substack) = current_stack.make_aligned_raw::<Scalar>(
                multi_bit_bsk.glwe_size().0 * multi_bit_bsk.polynomial_size().0,
                CACHELINE_ALIGN,
            );
            split_ct1.push(GlweCiphertext::from_container(
                glwe_cont,
                multi_bit_bsk.polynomial_size(),
                ct0.ciphertext_modulus(),
            ));
            current_stack = substack;
        }
        current_stack
    };

    // // Split the LUT into small LUTs
    // for (idx, coeff) in ct0.as_ref().iter().copied().enumerate() {
    //     let dst_lut = &mut split_ct0[idx % extension_factor.0];
    //     dst_lut.as_mut()[idx / extension_factor.0] = coeff;
    // }

    // Split the LUT into small LUTs
    for (idx, coeff) in ct0.as_ref().iter().copied().enumerate() {
        let ly23_dst_lut = idx % extension_factor.0;
        let ly23_dst_cell = idx / extension_factor.0;
        for group_idx in 0..grouping_factor.group_power_set_size() {
            let split_idx = group_idx * extension_factor.0 + ly23_dst_lut;
            let dst_lut = &mut split_ct0[split_idx];
            dst_lut.as_mut()[ly23_dst_cell] = coeff;
        }
    }

    let thread_split_ct0 = UnsafeSlice::new(&mut split_ct0);
    let thread_split_ct1 = UnsafeSlice::new(&mut split_ct1);

    use std::sync::Barrier;
    let barrier = Barrier::new(thread_count);

    let extension_factor_log2 = extension_factor.0.ilog2();
    let extension_factor_rem_mask = extension_factor.0 - 1;
    let mod_switch_modulus_log = lut_poly_size.to_blind_rotation_input_modulus_log();

    std::thread::scope(|s| {
        let thread_processing = |id: usize, stack: &mut PodStack<'_>| {
            let (curr_thread_group_idx, curr_thread_ly23_dst_idx) =
                (id / extension_factor.0, id % extension_factor.0);

            let (mut diff_dyn_array, mut stack) = stack.rb_mut().make_aligned_raw::<Scalar>(
                multi_bit_bsk.glwe_size().0 * multi_bit_bsk.polynomial_size().0,
                CACHELINE_ALIGN,
            );

            let mut rotated_buffer = GlweCiphertext::from_container(
                &mut *diff_dyn_array,
                multi_bit_bsk.polynomial_size(),
                ct0.ciphertext_modulus(),
            );

            let thread_split_ct0 = &thread_split_ct0;
            let thread_split_ct1 = &thread_split_ct1;

            for (loop_idx, (mask_elements, ggsw)) in lwe_mask
                .chunks_exact(grouping_factor.0)
                .zip(
                    multi_bit_bsk
                        .ggsw_iter()
                        .skip(curr_thread_group_idx)
                        .step_by(grouping_factor.ggsw_per_multi_bit_element().0),
                )
                .enumerate()
            {
                let monomial_degree = if curr_thread_group_idx == 0 {
                    // No rotation
                    MonomialDegree(0)
                } else {
                    let mod_switch_iter = modulus_switch_multi_bit(
                        mod_switch_modulus_log,
                        grouping_factor,
                        mask_elements,
                    );

                    // Mod switch does not return the 0 as first element
                    MonomialDegree(
                        mod_switch_iter
                            .into_iter()
                            .nth(curr_thread_group_idx - 1)
                            .unwrap(),
                    )
                };

                // Update the lut we look at simulating the rotation in the larger lut
                let curr_thread_ly23_src_idx = (curr_thread_ly23_dst_idx
                    .wrapping_sub(monomial_degree.0))
                    & extension_factor_rem_mask;

                // Compute the end of the rotation
                // N' = 2^nu * N
                // new_lut_idx = (ai + old_lut_idx) % 2^nu
                // (2^nu + (ai % 2N') - 1 - new_lut_idx)/2^nu a l'air de marcher pour x
                // X^ai monomial degree = mod switch(ai)
                // already % 2N'
                let small_monomial_degree = MonomialDegree(
                    (extension_factor.0 + monomial_degree.0 - 1 - curr_thread_ly23_dst_idx)
                        >> extension_factor_log2,
                );

                // Map to the linear buffer
                let ct_src_idx =
                    curr_thread_group_idx * extension_factor.0 + curr_thread_ly23_src_idx;
                let ct_dst_idx =
                    curr_thread_group_idx * extension_factor.0 + curr_thread_ly23_dst_idx;

                let res_buffer = {
                    let (src_to_rotate, dst_rotated) = if (loop_idx % 2) == 0 {
                        unsafe {
                            (
                                thread_split_ct0.read(ct_src_idx),
                                &mut *thread_split_ct1.write(ct_dst_idx),
                            )
                        }
                    } else {
                        unsafe {
                            (
                                thread_split_ct1.read(ct_src_idx),
                                &mut *thread_split_ct0.write(ct_dst_idx),
                            )
                        }
                    };

                    // Multi bit ext prod writes the CMUX result directly in the dst buffer
                    dst_rotated.as_mut().fill(Scalar::ZERO);

                    for (mut diff_poly, src_to_rotate_poly) in izip!(
                        rotated_buffer.as_mut_polynomial_list().iter_mut(),
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

                    dst_rotated
                };

                // ACCj ← BSKi x Rot(ACCj)
                add_external_product_assign(
                    res_buffer.as_mut_view(),
                    ggsw,
                    rotated_buffer.as_view(),
                    fft,
                    stack.rb_mut(),
                );

                let _ = barrier.wait();

                // One thread will sum the ly23 results in the group 0 buffers and then copy to
                // other groups
                if curr_thread_group_idx == 0 {
                    let dest_buffers = if (loop_idx % 2) == 0 {
                        thread_split_ct1
                    } else {
                        thread_split_ct0
                    };

                    // Sum to get the multi bit CMUX result
                    let sum_buffer = unsafe { &mut *dest_buffers.write(curr_thread_ly23_dst_idx) };
                    for other_gp_idx in 1..grouping_factor.group_power_set_size() {
                        unsafe {
                            glwe_ciphertext_add_assign(
                                sum_buffer,
                                dest_buffers.read(
                                    other_gp_idx * extension_factor.0 + curr_thread_ly23_dst_idx,
                                ),
                            );
                        }
                    }

                    // Copy to other threads buffers to start with the CMUX result
                    for other_gp_idx in 1..grouping_factor.group_power_set_size() {
                        let other_group_dst = unsafe {
                            &mut *dest_buffers
                                .write(other_gp_idx * extension_factor.0 + curr_thread_ly23_dst_idx)
                        };
                        other_group_dst
                            .as_mut()
                            .copy_from_slice(sum_buffer.as_ref());
                    }
                }

                let _ = barrier.wait();
            }
        };

        let threads: Vec<_> = thread_stacks
            .iter_mut()
            .enumerate()
            .map(|(id, stack)| s.spawn(move || thread_processing(id, stack)))
            .collect();

        threads.into_iter().for_each(|t| t.join().unwrap());
    });

    let lwe_dimension = multi_bit_bsk.multi_bit_input_lwe_dimension().0;
    let buffer_to_use = if lwe_dimension % 2 == 0 {
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

pub fn lwe_multi_bit_sorted_extended_programmable_bootstrapping<
    Scalar,
    InputCont,
    OutputCont,
    AccCont,
    KeyCont,
>(
    input: &LweCiphertext<InputCont>,
    output: &mut LweCiphertext<OutputCont>,
    accumulator: &GlweCiphertext<AccCont>,
    multi_bit_bsk: &FourierLweMultiBitBootstrapKey<KeyCont>,
    extension_factor: Ly23ExtensionFactor,
    shortcut_coeff_count: Ly23ShortcutCoeffCount,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Sync,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    AccCont: Container<Element = Scalar>,
    KeyCont: Container<Element = c64> + Sync,
{
    let fft = Fft::new(multi_bit_bsk.polynomial_size());
    let fft = fft.as_view();

    let mut computation_buffers = ComputationBuffers::new();
    computation_buffers.resize(
        multi_bit_programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement_ly23::<Scalar>(
            multi_bit_bsk.glwe_size(),
            multi_bit_bsk.polynomial_size(),
            extension_factor,
            multi_bit_bsk.grouping_factor(),
            fft,
        )
        .unwrap()
        .try_unaligned_bytes_required()
        .unwrap(),
    );

    let mut buffers: Vec<_> = (0..extension_factor.0
        * multi_bit_bsk.grouping_factor().group_power_set_size())
        .map(|_| {
            let mut buffer = ComputationBuffers::new();
            buffer.resize(
                programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement_ly23::<Scalar>(
                    multi_bit_bsk.glwe_size(),
                    multi_bit_bsk.polynomial_size(),
                    extension_factor,
                    fft,
                )
                .unwrap()
                .try_unaligned_bytes_required()
                .unwrap(),
            );
            buffer
        })
        .collect();

    let mut thread_stacks: Vec<_> = buffers.iter_mut().map(|x| x.stack()).collect();

    lwe_multi_bit_sorted_extended_programmable_bootstrapping_mem_optimized(
        input,
        output,
        accumulator,
        multi_bit_bsk,
        extension_factor,
        shortcut_coeff_count,
        fft,
        computation_buffers.stack(),
        &mut thread_stacks,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn lwe_multi_bit_sorted_extended_programmable_bootstrapping_mem_optimized<
    Scalar,
    InputCont,
    OutputCont,
    AccCont,
    KeyCont,
>(
    input: &LweCiphertext<InputCont>,
    output: &mut LweCiphertext<OutputCont>,
    accumulator: &GlweCiphertext<AccCont>,
    multi_bit_bsk: &FourierLweMultiBitBootstrapKey<KeyCont>,
    extension_factor: Ly23ExtensionFactor,
    shortcut_coeff_count: Ly23ShortcutCoeffCount,
    fft: FftView<'_>,
    stack: PodStack<'_>,
    thread_stacks: &mut [PodStack<'_>],
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Sync,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    AccCont: Container<Element = Scalar>,
    KeyCont: Container<Element = c64> + Sync,
{
    let (mut local_accumulator_data, stack) =
        stack.collect_aligned(CACHELINE_ALIGN, accumulator.as_ref().iter().copied());
    let mut local_accumulator = GlweCiphertextMutView::from_container(
        &mut *local_accumulator_data,
        accumulator.polynomial_size(),
        accumulator.ciphertext_modulus(),
    );

    let split_accumulator = lwe_multi_bit_sorted_extended_blind_rotate_assign(
        multi_bit_bsk.as_view(),
        local_accumulator.as_mut_view(),
        input.as_ref(),
        extension_factor,
        shortcut_coeff_count,
        fft,
        stack,
        thread_stacks,
    );

    extract_lwe_sample_from_glwe_ciphertext(&split_accumulator, output, MonomialDegree(0));
}

#[allow(clippy::needless_collect)]
#[allow(clippy::needless_pass_by_value)]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::needless_range_loop)]
pub fn lwe_multi_bit_sorted_extended_blind_rotate_assign<Scalar>(
    multi_bit_bsk: FourierLweMultiBitBootstrapKeyView<'_>,
    mut lut: GlweCiphertextMutView<'_, Scalar>,
    lwe: &[Scalar],
    extension_factor: Ly23ExtensionFactor,
    shortcut_coeff_count: Ly23ShortcutCoeffCount,
    fft: FftView<'_>,
    mut stack: PodStack<'_>,
    thread_stacks: &mut [PodStack<'_>],
) -> GlweCiphertextOwned<Scalar>
where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Sync,
{
    let thread_count = extension_factor.0 * multi_bit_bsk.grouping_factor().group_power_set_size();
    assert_eq!(thread_stacks.len(), thread_count);

    let (lwe_body, lwe_mask) = lwe.split_last().unwrap();

    let lut_poly_size = lut.polynomial_size();
    let ciphertext_modulus = lut.ciphertext_modulus();
    let grouping_factor = multi_bit_bsk.grouping_factor();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());
    assert_eq!(
        multi_bit_bsk.polynomial_size().0 * extension_factor.0,
        lut_poly_size.0
    );
    let monomial_degree = MonomialDegree(pbs_modulus_switch(
        *lwe_body,
        // This one should be the extended polynomial size
        lut_poly_size,
    ));

    lut.as_mut_polynomial_list()
        .iter_mut()
        .for_each(|mut poly| {
            let (mut tmp_poly, _) = stack
                .rb_mut()
                .make_aligned_raw(poly.as_ref().len(), CACHELINE_ALIGN);

            let mut tmp_poly = Polynomial::from_container(&mut *tmp_poly);
            tmp_poly.as_mut().copy_from_slice(poly.as_ref());
            polynomial_wrapping_monic_monomial_div(&mut poly, &tmp_poly, monomial_degree)
        });

    let ct0 = &lut;

    let mut split_ct0 = Vec::with_capacity(thread_count);

    let mut split_ct1 = Vec::with_capacity(thread_count);

    let substack0 = {
        let mut current_stack = stack;
        for _ in 0..thread_count {
            let (glwe_cont, substack) = current_stack.make_aligned_raw::<Scalar>(
                multi_bit_bsk.glwe_size().0 * multi_bit_bsk.polynomial_size().0,
                CACHELINE_ALIGN,
            );
            split_ct0.push(GlweCiphertext::from_container(
                glwe_cont,
                multi_bit_bsk.polynomial_size(),
                ct0.ciphertext_modulus(),
            ));
            current_stack = substack;
        }
        current_stack
    };

    let _substack1 = {
        let mut current_stack = substack0;
        for _ in 0..thread_count {
            let (glwe_cont, substack) = current_stack.make_aligned_raw::<Scalar>(
                multi_bit_bsk.glwe_size().0 * multi_bit_bsk.polynomial_size().0,
                CACHELINE_ALIGN,
            );
            split_ct1.push(GlweCiphertext::from_container(
                glwe_cont,
                multi_bit_bsk.polynomial_size(),
                ct0.ciphertext_modulus(),
            ));
            current_stack = substack;
        }
        current_stack
    };

    // // Split the LUT into small LUTs
    // for (idx, coeff) in ct0.as_ref().iter().copied().enumerate() {
    //     let dst_lut = &mut split_ct0[idx % extension_factor.0];
    //     dst_lut.as_mut()[idx / extension_factor.0] = coeff;
    // }

    // Split the LUT into small LUTs
    for (idx, coeff) in ct0.as_ref().iter().copied().enumerate() {
        let ly23_dst_lut = idx % extension_factor.0;
        let ly23_dst_cell = idx / extension_factor.0;
        for group_idx in 0..grouping_factor.group_power_set_size() {
            let split_idx = group_idx * extension_factor.0 + ly23_dst_lut;
            let dst_lut = &mut split_ct0[split_idx];
            dst_lut.as_mut()[ly23_dst_cell] = coeff;
        }
    }

    let thread_split_ct0 = UnsafeSlice::new(&mut split_ct0);
    let thread_split_ct1 = UnsafeSlice::new(&mut split_ct1);

    use std::sync::Barrier;
    let extension_factor_log2 = extension_factor.0.ilog2();
    let extension_factor_rem_mask = extension_factor.0 - 1;
    let congruence_classes_count = extension_factor_log2 as usize + 1;
    let mod_switch_modulus_log = lut_poly_size.to_blind_rotation_input_modulus_log();
    let mut congruence_classes: Vec<_> = (0..congruence_classes_count)
        .map(|idx| (vec![], Barrier::new(thread_count / (1 << idx))))
        .collect();

    // Will be stored by how many coeffs need flipping and then gap
    let mut shortcuts =
        vec![vec![vec![]; congruence_classes_count]; grouping_factor.group_power_set_size()];

    for (mask_group_idx, mask_elements) in lwe_mask.chunks_exact(grouping_factor.0).enumerate() {
        let mod_switched_group: Vec<_> =
            modulus_switch_multi_bit(mod_switch_modulus_log, grouping_factor, mask_elements)
                .collect();

        let mut group_congruence_table = vec![vec![]; congruence_classes_count];

        // By default we are the last congruence class
        let mut original_congruence_class = congruence_classes_count - 1;

        'coeffs: for (switched_idx, switched) in mod_switched_group.iter().enumerate() {
            // We skip the 0 for multi bit mod switch so we have to patch the switch index here
            let switched_idx = switched_idx + 1;
            for mod_idx in 0..congruence_classes_count - 1 {
                let mod_power = mod_idx + 1;
                let modulus: usize = (Scalar::ONE << mod_power).cast_into();
                // println!("modulus={modulus}");
                let expected_remainder = modulus >> 1;
                // println!("expected_remainder={expected_remainder}");

                if switched % modulus == expected_remainder {
                    original_congruence_class = original_congruence_class.min(mod_idx);
                    group_congruence_table[mod_idx].push(switched_idx);
                    continue 'coeffs;
                }
            }

            group_congruence_table[congruence_classes_count - 1].push(switched_idx);
        }

        assert_eq!(
            group_congruence_table.iter().map(Vec::len).sum::<usize>(),
            mod_switched_group.len()
        );

        // If we are not in the odd class, then store the mod switches and continue
        if original_congruence_class > 0 {
            congruence_classes[original_congruence_class]
                .0
                .push((mask_group_idx, mod_switched_group));
            continue;
        }

        let coeffs_that_need_flipping = group_congruence_table[0].len();
        let mut new_group_congruence_table = group_congruence_table.clone();
        new_group_congruence_table[0].clear();

        let mut altered_mod_switched_group = mod_switched_group.clone();

        // Odd indices
        for switched_idx in group_congruence_table[0].iter().copied() {
            let mut coeff_to_mod_switch = Scalar::ZERO;
            for (&mask_element, selection_bit) in mask_elements
                .iter()
                .zip(selection_bit(grouping_factor, switched_idx))
            {
                let selection_bit: Scalar = Scalar::cast_from(selection_bit);
                coeff_to_mod_switch =
                    coeff_to_mod_switch.wrapping_add(selection_bit.wrapping_mul(mask_element));
            }

            let mod_switched = pbs_modulus_switch(coeff_to_mod_switch, lut_poly_size);

            let modulus_switch_log = lut_poly_size.to_blind_rotation_input_modulus_log().0;

            let rounding_bit =
                (coeff_to_mod_switch >> (Scalar::BITS - modulus_switch_log)) & Scalar::ONE;
            let altered_mod_switch = if rounding_bit == Scalar::ZERO {
                mod_switched.wrapping_add(1) % (1 << modulus_switch_log)
            } else {
                mod_switched.wrapping_sub(1) % (1 << modulus_switch_log)
            };

            assert_eq!(altered_mod_switch % 2, 0);

            let mut set_class = false;
            for mod_idx in 0..congruence_classes_count - 1 {
                let mod_power = mod_idx + 1;
                let modulus: usize = (Scalar::ONE << mod_power).cast_into();
                // println!("modulus={modulus}");
                let expected_remainder = modulus >> 1;
                // println!("expected_remainder={expected_remainder}");

                if altered_mod_switch % modulus == expected_remainder {
                    new_group_congruence_table[mod_idx].push(switched_idx);
                    set_class = true;
                    break;
                }
            }

            altered_mod_switched_group[switched_idx - 1] = altered_mod_switch;

            if !set_class {
                new_group_congruence_table[congruence_classes_count - 1].push(switched_idx)
            }
        }

        assert_eq!(
            new_group_congruence_table
                .iter()
                .map(Vec::len)
                .sum::<usize>(),
            mod_switched_group.len()
        );

        let mut destination_congruence_class = 0;

        for (idx, switched_in_class) in new_group_congruence_table.iter().enumerate().skip(1) {
            if !switched_in_class.is_empty() {
                destination_congruence_class = idx;
                break;
            }
        }

        let congruence_gap = destination_congruence_class - original_congruence_class;

        assert_ne!(congruence_gap, 0);

        shortcuts[coeffs_that_need_flipping][congruence_gap].push((
            mask_group_idx,
            (
                destination_congruence_class,
                mod_switched_group,
                altered_mod_switched_group,
            ),
        ));
    }

    assert!(shortcuts[0].iter().all(Vec::is_empty));

    let mut shortcut_remaining = shortcut_coeff_count.0;
    for (coeffs_that_need_flipping, shortcuts_by_gap) in shortcuts.into_iter().enumerate().skip(1) {
        // Rev to start with larger gaps first
        for to_shortcut in shortcuts_by_gap.into_iter().rev() {
            for (
                mask_group_idx,
                (destination_congruence_class, mod_switched_group, altered_mod_switched_group),
            ) in to_shortcut
            {
                if shortcut_remaining >= coeffs_that_need_flipping {
                    // can flip
                    shortcut_remaining -= coeffs_that_need_flipping;
                    congruence_classes[destination_congruence_class]
                        .0
                        .push((mask_group_idx, altered_mod_switched_group))
                } else {
                    // cannot flip, go to odd congruence class
                    congruence_classes[0]
                        .0
                        .push((mask_group_idx, mod_switched_group));
                }
            }
        }
    }

    let gathered_dim = congruence_classes.iter().map(|x| x.0.len()).sum::<usize>();
    assert_eq!(gathered_dim * grouping_factor.0, lwe_mask.len());

    std::thread::scope(|s| {
        let thread_processing = |id: usize, stack: &mut PodStack<'_>| {
            let (curr_thread_group_idx, curr_thread_ly23_dst_idx) =
                (id / extension_factor.0, id % extension_factor.0);

            let (mut diff_dyn_array, mut stack) = stack.rb_mut().make_aligned_raw::<Scalar>(
                multi_bit_bsk.glwe_size().0 * multi_bit_bsk.polynomial_size().0,
                CACHELINE_ALIGN,
            );

            let mut rotated_buffer = GlweCiphertext::from_container(
                &mut *diff_dyn_array,
                multi_bit_bsk.polynomial_size(),
                ct0.ciphertext_modulus(),
            );

            let ggsw_vec = multi_bit_bsk.ggsw_iter().collect::<Vec<_>>();

            let thread_split_ct0 = &thread_split_ct0;
            let thread_split_ct1 = &thread_split_ct1;

            let mut overall_loop_idx = 0;

            for (congruence_class_idx, (mask_indices, barrier)) in
                congruence_classes.iter().enumerate()
            {
                // The skips are related to the LY23 slot
                let should_process = (curr_thread_ly23_dst_idx % (1 << congruence_class_idx)) == 0;
                if !should_process {
                    return;
                }
                for (mask_group_idx, mod_switched) in mask_indices.iter() {
                    let mask_group_idx = *mask_group_idx;

                    let ggsw = ggsw_vec[mask_group_idx
                        * grouping_factor.ggsw_per_multi_bit_element().0
                        + curr_thread_group_idx];

                    let monomial_degree = if curr_thread_group_idx == 0 {
                        // No rotation
                        MonomialDegree(0)
                    } else {
                        let mod_switch_iter = mod_switched.iter().copied();

                        // Mod switch does not return the 0 as first element
                        MonomialDegree(
                            mod_switch_iter
                                .into_iter()
                                .nth(curr_thread_group_idx - 1)
                                .unwrap(),
                        )
                    };

                    // Update the lut we look at simulating the rotation in the larger lut
                    let curr_thread_ly23_src_idx = (curr_thread_ly23_dst_idx
                        .wrapping_sub(monomial_degree.0))
                        & extension_factor_rem_mask;

                    // Compute the end of the rotation
                    // N' = 2^nu * N
                    // new_lut_idx = (ai + old_lut_idx) % 2^nu
                    // (2^nu + (ai % 2N') - 1 - new_lut_idx)/2^nu a l'air de marcher pour x
                    // X^ai monomial degree = mod switch(ai)
                    // already % 2N'
                    let small_monomial_degree = MonomialDegree(
                        (extension_factor.0 + monomial_degree.0 - 1 - curr_thread_ly23_dst_idx)
                            >> extension_factor_log2,
                    );

                    // Map to the linear buffer
                    let ct_src_idx =
                        curr_thread_group_idx * extension_factor.0 + curr_thread_ly23_src_idx;
                    let ct_dst_idx =
                        curr_thread_group_idx * extension_factor.0 + curr_thread_ly23_dst_idx;

                    let res_buffer = {
                        let (src_to_rotate, dst_rotated) = if (overall_loop_idx % 2) == 0 {
                            unsafe {
                                (
                                    thread_split_ct0.read(ct_src_idx),
                                    &mut *thread_split_ct1.write(ct_dst_idx),
                                )
                            }
                        } else {
                            unsafe {
                                (
                                    thread_split_ct1.read(ct_src_idx),
                                    &mut *thread_split_ct0.write(ct_dst_idx),
                                )
                            }
                        };

                        // Multi bit ext prod writes the CMUX result directly in the dst buffer
                        dst_rotated.as_mut().fill(Scalar::ZERO);

                        for (mut diff_poly, src_to_rotate_poly) in izip!(
                            rotated_buffer.as_mut_polynomial_list().iter_mut(),
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

                        dst_rotated
                    };

                    // ACCj ← BSKi x Rot(ACCj)
                    add_external_product_assign(
                        res_buffer.as_mut_view(),
                        ggsw,
                        rotated_buffer.as_view(),
                        fft,
                        stack.rb_mut(),
                    );

                    let _ = barrier.wait();

                    // One thread will sum the ly23 results in the group 0 buffers and then copy to
                    // other groups
                    if curr_thread_group_idx == 0 {
                        let dest_buffers = if (overall_loop_idx % 2) == 0 {
                            thread_split_ct1
                        } else {
                            thread_split_ct0
                        };

                        // Sum to get the multi bit CMUX result
                        let sum_buffer =
                            unsafe { &mut *dest_buffers.write(curr_thread_ly23_dst_idx) };
                        for other_gp_idx in 1..grouping_factor.group_power_set_size() {
                            unsafe {
                                glwe_ciphertext_add_assign(
                                    sum_buffer,
                                    dest_buffers.read(
                                        other_gp_idx * extension_factor.0
                                            + curr_thread_ly23_dst_idx,
                                    ),
                                );
                            }
                        }

                        // Copy to other threads buffers to start with the CMUX result
                        for other_gp_idx in 1..grouping_factor.group_power_set_size() {
                            let other_group_dst = unsafe {
                                &mut *dest_buffers.write(
                                    other_gp_idx * extension_factor.0 + curr_thread_ly23_dst_idx,
                                )
                            };
                            other_group_dst
                                .as_mut()
                                .copy_from_slice(sum_buffer.as_ref());
                        }
                    }

                    let _ = barrier.wait();
                    overall_loop_idx += 1;
                }
            }
        };

        let threads: Vec<_> = thread_stacks
            .iter_mut()
            .enumerate()
            .map(|(id, stack)| s.spawn(move || thread_processing(id, stack)))
            .collect();

        threads.into_iter().for_each(|t| t.join().unwrap());
    });

    let lwe_dimension = multi_bit_bsk.multi_bit_input_lwe_dimension().0;
    let buffer_to_use = if lwe_dimension % 2 == 0 {
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

pub fn multi_bit_programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement_ly23<Scalar>(
    glwe_size: GlweSize,
    small_polynomial_size: PolynomialSize,
    extension_factor: Ly23ExtensionFactor,
    grouping_factor: LweBskGroupingFactor,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    Ok(StackReq::all_of(
        core::iter::repeat(bootstrap_ly23_scratch::<Scalar>(
            glwe_size,
            small_polynomial_size,
            extension_factor,
            fft,
        )?)
        .take(grouping_factor.group_power_set_size()),
    ))
}
