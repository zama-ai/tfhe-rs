use super::pbs_modulus_switch;
use crate::core_crypto::algorithms::extract_lwe_sample_from_glwe_ciphertext;
use crate::core_crypto::algorithms::polynomial_algorithms::{
    polynomial_wrapping_monic_monomial_div_assign, polynomial_wrapping_monic_monomial_mul_assign,
};
use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::parameters::{
    CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension,
    MonomialDegree, PolynomialSize,
};
use crate::core_crypto::commons::traits::{
    Container, ContainerMut, ContiguousEntityContainer, ContiguousEntityContainerMut, Split,
};
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::entities::{
    ggsw_ciphertext_size, GlweCiphertext, GlweCiphertextMutView, GlweCiphertextView,
    LweBootstrapKey, LweCiphertext, NttGgswCiphertext,
};
use crate::core_crypto::fft_impl::fft64::crypto::ggsw::{
    collect_next_term, collect_take_next_term,
};
use crate::core_crypto::fft_impl::fft64::math::decomposition::TensorSignedDecompositionLendingIter;
use aligned_vec::CACHELINE_ALIGN;
use dyn_stack::{PodStack, ReborrowMut};
use rayon::prelude::*;
use tfhe_ntt::native128::Plan32;

pub struct CrtNtt128LweBsk<C: Container<Element = u32>> {
    mod_p0: C,
    mod_p1: C,
    mod_p2: C,
    mod_p3: C,
    mod_p4: C,
    mod_p5: C,
    mod_p6: C,
    mod_p7: C,
    mod_p8: C,
    mod_p9: C,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    ciphertext_modulus: CiphertextModulus<u128>,
}

impl CrtNtt128LweBsk<Vec<u32>> {
    pub fn new(
        input_lwe_dimension: LweDimension,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<u128>,
    ) -> Self {
        let ct_size = ggsw_ciphertext_size(glwe_size, polynomial_size, decomp_level_count);

        let container_len = input_lwe_dimension.0 * ct_size;

        Self {
            mod_p0: vec![0; container_len],
            mod_p1: vec![0; container_len],
            mod_p2: vec![0; container_len],
            mod_p3: vec![0; container_len],
            mod_p4: vec![0; container_len],
            mod_p5: vec![0; container_len],
            mod_p6: vec![0; container_len],
            mod_p7: vec![0; container_len],
            mod_p8: vec![0; container_len],
            mod_p9: vec![0; container_len],
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            ciphertext_modulus,
        }
    }
}

impl<C: Container<Element = u32>> CrtNtt128LweBsk<C> {
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    pub fn input_lwe_dimension(&self) -> LweDimension {
        LweDimension(
            self.mod_p0.container_len()
                / ggsw_ciphertext_size(
                    self.glwe_size,
                    self.polynomial_size,
                    self.decomp_level_count,
                ),
        )
    }

    pub fn as_ref(
        &self,
    ) -> (
        &[u32],
        &[u32],
        &[u32],
        &[u32],
        &[u32],
        &[u32],
        &[u32],
        &[u32],
        &[u32],
        &[u32],
    ) {
        let Self {
            mod_p0,
            mod_p1,
            mod_p2,
            mod_p3,
            mod_p4,
            mod_p5,
            mod_p6,
            mod_p7,
            mod_p8,
            mod_p9,
            glwe_size: _,
            polynomial_size: _,
            decomp_base_log: _,
            decomp_level_count: _,
            ciphertext_modulus: _,
        } = self;

        (
            mod_p0.as_ref(),
            mod_p1.as_ref(),
            mod_p2.as_ref(),
            mod_p3.as_ref(),
            mod_p4.as_ref(),
            mod_p5.as_ref(),
            mod_p6.as_ref(),
            mod_p7.as_ref(),
            mod_p8.as_ref(),
            mod_p9.as_ref(),
        )
    }

    pub fn into_ggsw_iter(
        &self,
    ) -> (
        impl DoubleEndedIterator<Item = NttGgswCiphertext<&[C::Element]>>,
        impl DoubleEndedIterator<Item = NttGgswCiphertext<&[C::Element]>>,
        impl DoubleEndedIterator<Item = NttGgswCiphertext<&[C::Element]>>,
        impl DoubleEndedIterator<Item = NttGgswCiphertext<&[C::Element]>>,
        impl DoubleEndedIterator<Item = NttGgswCiphertext<&[C::Element]>>,
        impl DoubleEndedIterator<Item = NttGgswCiphertext<&[C::Element]>>,
        impl DoubleEndedIterator<Item = NttGgswCiphertext<&[C::Element]>>,
        impl DoubleEndedIterator<Item = NttGgswCiphertext<&[C::Element]>>,
        impl DoubleEndedIterator<Item = NttGgswCiphertext<&[C::Element]>>,
        impl DoubleEndedIterator<Item = NttGgswCiphertext<&[C::Element]>>,
    ) {
        let ggsw_ciphertext_count = self.input_lwe_dimension();

        let (mod_p0, mod_p1, mod_p2, mod_p3, mod_p4, mod_p5, mod_p6, mod_p7, mod_p8, mod_p9) =
            self.as_ref();

        (
            mod_p0
                .split_into(ggsw_ciphertext_count.0)
                .map(move |slice| {
                    NttGgswCiphertext::from_container(
                        slice,
                        self.glwe_size,
                        self.polynomial_size,
                        self.decomp_base_log,
                        self.decomp_level_count,
                    )
                }),
            mod_p1
                .split_into(ggsw_ciphertext_count.0)
                .map(move |slice| {
                    NttGgswCiphertext::from_container(
                        slice,
                        self.glwe_size,
                        self.polynomial_size,
                        self.decomp_base_log,
                        self.decomp_level_count,
                    )
                }),
            mod_p2
                .split_into(ggsw_ciphertext_count.0)
                .map(move |slice| {
                    NttGgswCiphertext::from_container(
                        slice,
                        self.glwe_size,
                        self.polynomial_size,
                        self.decomp_base_log,
                        self.decomp_level_count,
                    )
                }),
            mod_p3
                .split_into(ggsw_ciphertext_count.0)
                .map(move |slice| {
                    NttGgswCiphertext::from_container(
                        slice,
                        self.glwe_size,
                        self.polynomial_size,
                        self.decomp_base_log,
                        self.decomp_level_count,
                    )
                }),
            mod_p4
                .split_into(ggsw_ciphertext_count.0)
                .map(move |slice| {
                    NttGgswCiphertext::from_container(
                        slice,
                        self.glwe_size,
                        self.polynomial_size,
                        self.decomp_base_log,
                        self.decomp_level_count,
                    )
                }),
            mod_p5
                .split_into(ggsw_ciphertext_count.0)
                .map(move |slice| {
                    NttGgswCiphertext::from_container(
                        slice,
                        self.glwe_size,
                        self.polynomial_size,
                        self.decomp_base_log,
                        self.decomp_level_count,
                    )
                }),
            mod_p6
                .split_into(ggsw_ciphertext_count.0)
                .map(move |slice| {
                    NttGgswCiphertext::from_container(
                        slice,
                        self.glwe_size,
                        self.polynomial_size,
                        self.decomp_base_log,
                        self.decomp_level_count,
                    )
                }),
            mod_p7
                .split_into(ggsw_ciphertext_count.0)
                .map(move |slice| {
                    NttGgswCiphertext::from_container(
                        slice,
                        self.glwe_size,
                        self.polynomial_size,
                        self.decomp_base_log,
                        self.decomp_level_count,
                    )
                }),
            mod_p8
                .split_into(ggsw_ciphertext_count.0)
                .map(move |slice| {
                    NttGgswCiphertext::from_container(
                        slice,
                        self.glwe_size,
                        self.polynomial_size,
                        self.decomp_base_log,
                        self.decomp_level_count,
                    )
                }),
            mod_p9
                .split_into(ggsw_ciphertext_count.0)
                .map(move |slice| {
                    NttGgswCiphertext::from_container(
                        slice,
                        self.glwe_size,
                        self.polynomial_size,
                        self.decomp_base_log,
                        self.decomp_level_count,
                    )
                }),
        )
    }
}

impl<C: ContainerMut<Element = u32>> CrtNtt128LweBsk<C> {
    pub fn as_mut(
        &mut self,
    ) -> (
        &mut [u32],
        &mut [u32],
        &mut [u32],
        &mut [u32],
        &mut [u32],
        &mut [u32],
        &mut [u32],
        &mut [u32],
        &mut [u32],
        &mut [u32],
    ) {
        let Self {
            mod_p0,
            mod_p1,
            mod_p2,
            mod_p3,
            mod_p4,
            mod_p5,
            mod_p6,
            mod_p7,
            mod_p8,
            mod_p9,
            glwe_size: _,
            polynomial_size: _,
            decomp_base_log: _,
            decomp_level_count: _,
            ciphertext_modulus: _,
        } = self;

        (
            mod_p0.as_mut(),
            mod_p1.as_mut(),
            mod_p2.as_mut(),
            mod_p3.as_mut(),
            mod_p4.as_mut(),
            mod_p5.as_mut(),
            mod_p6.as_mut(),
            mod_p7.as_mut(),
            mod_p8.as_mut(),
            mod_p9.as_mut(),
        )
    }
}

pub fn convert_standard_lwe_bootstrap_key_to_crt_ntt_128<InputCont, OutputCont>(
    input_bsk: &LweBootstrapKey<InputCont>,
    output_bsk: &mut CrtNtt128LweBsk<OutputCont>,
) where
    InputCont: Container<Element = u128>,
    OutputCont: ContainerMut<Element = u32>,
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
        "Mismatched GlweSize"
    );

    assert_eq!(
        input_bsk.decomposition_base_log(),
        output_bsk.decomposition_base_log(),
        "Mismatched DecompositionBaseLog between input_bsk {:?} and output_bsk {:?}",
        input_bsk.glwe_size(),
        output_bsk.glwe_size(),
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

    let polynomial_size = input_bsk.polynomial_size().0;

    let ntt = Plan32::try_new(polynomial_size).unwrap();

    let (mod_p0, mod_p1, mod_p2, mod_p3, mod_p4, mod_p5, mod_p6, mod_p7, mod_p8, mod_p9) =
        output_bsk.as_mut();

    for (
        input_poly,
        mod_p0,
        mod_p1,
        mod_p2,
        mod_p3,
        mod_p4,
        mod_p5,
        mod_p6,
        mod_p7,
        mod_p8,
        mod_p9,
    ) in izip!(
        input_bsk.as_polynomial_list().iter(),
        mod_p0.chunks_exact_mut(polynomial_size),
        mod_p1.chunks_exact_mut(polynomial_size),
        mod_p2.chunks_exact_mut(polynomial_size),
        mod_p3.chunks_exact_mut(polynomial_size),
        mod_p4.chunks_exact_mut(polynomial_size),
        mod_p5.chunks_exact_mut(polynomial_size),
        mod_p6.chunks_exact_mut(polynomial_size),
        mod_p7.chunks_exact_mut(polynomial_size),
        mod_p8.chunks_exact_mut(polynomial_size),
        mod_p9.chunks_exact_mut(polynomial_size)
    ) {
        ntt.forward_normalized(
            input_poly.as_ref(),
            mod_p0,
            mod_p1,
            mod_p2,
            mod_p3,
            mod_p4,
            mod_p5,
            mod_p6,
            mod_p7,
            mod_p8,
            mod_p9,
        );
    }
}

pub fn pbs_ntt_128<InputCont, OutputCont, AccCont, BskCont>(
    lwe_in: &LweCiphertext<InputCont>,
    lwe_out: &mut LweCiphertext<OutputCont>,
    accumulator: &GlweCiphertext<AccCont>,
    bsk: &CrtNtt128LweBsk<BskCont>,
) where
    InputCont: Container<Element = u128>,
    OutputCont: ContainerMut<Element = u128>,
    AccCont: Container<Element = u128>,
    BskCont: Container<Element = u32>,
{
    debug_assert_eq!(lwe_out.ciphertext_modulus(), lwe_in.ciphertext_modulus());
    debug_assert_eq!(
        lwe_in.ciphertext_modulus(),
        accumulator.ciphertext_modulus()
    );

    let ntt = Plan32::try_new(accumulator.polynomial_size().0).unwrap();
    let mut buffers = ComputationBuffers::new();
    buffers.resize(1 << 24);
    let stack = buffers.stack();

    let (local_accumulator_data, stack) =
        stack.collect_aligned(CACHELINE_ALIGN, accumulator.as_ref().iter().copied());
    let mut local_accumulator = GlweCiphertextMutView::from_container(
        local_accumulator_data,
        accumulator.polynomial_size(),
        accumulator.ciphertext_modulus(),
    );

    blind_rotate_assign_ntt_128(lwe_in, &mut local_accumulator, bsk, &ntt, stack);

    extract_lwe_sample_from_glwe_ciphertext(&local_accumulator, lwe_out, MonomialDegree(0));
}

fn blind_rotate_assign_ntt_128<InputCont, AccCont, BskCont>(
    lwe_in: &LweCiphertext<InputCont>,
    lut: &mut GlweCiphertext<AccCont>,
    bsk: &CrtNtt128LweBsk<BskCont>,
    ntt: &Plan32,
    mut stack: PodStack<'_>,
) where
    InputCont: Container<Element = u128>,
    AccCont: ContainerMut<Element = u128>,
    BskCont: Container<Element = u32>,
{
    let (lwe_mask, lwe_body) = lwe_in.get_mask_and_body();

    let lut_poly_size = lut.polynomial_size();
    let ciphertext_modulus = lut.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());
    let monomial_degree = pbs_modulus_switch(*lwe_body.data, lut_poly_size);

    lut.as_mut_polynomial_list()
        .iter_mut()
        .for_each(|mut poly| {
            polynomial_wrapping_monic_monomial_div_assign(
                &mut poly,
                MonomialDegree(monomial_degree),
            );
        });

    // We initialize the ct_0 used for the successive cmuxes
    let ct0 = lut;

    let (mod_p0, mod_p1, mod_p2, mod_p3, mod_p4, mod_p5, mod_p6, mod_p7, mod_p8, mod_p9) =
        bsk.into_ggsw_iter();

    for (
        lwe_mask_element,
        mod_p0,
        mod_p1,
        mod_p2,
        mod_p3,
        mod_p4,
        mod_p5,
        mod_p6,
        mod_p7,
        mod_p8,
        mod_p9,
    ) in izip!(
        lwe_mask.as_ref().iter(),
        mod_p0,
        mod_p1,
        mod_p2,
        mod_p3,
        mod_p4,
        mod_p5,
        mod_p6,
        mod_p7,
        mod_p8,
        mod_p9
    ) {
        if *lwe_mask_element != 0u128 {
            let stack = stack.rb_mut();
            // We copy ct_0 to ct_1
            let (ct1, stack) = stack.collect_aligned(CACHELINE_ALIGN, ct0.as_ref().iter().copied());
            let mut ct1 = GlweCiphertextMutView::from_container(
                ct1,
                ct0.polynomial_size(),
                ct0.ciphertext_modulus(),
            );

            // We rotate ct_1 by performing ct_1 <- ct_1 * X^{a_hat}
            for mut poly in ct1.as_mut_polynomial_list().iter_mut() {
                polynomial_wrapping_monic_monomial_mul_assign(
                    &mut poly,
                    MonomialDegree(pbs_modulus_switch(*lwe_mask_element, lut_poly_size)),
                );
            }

            // ct1 is re-created each loop it can be moved, ct0 is already a view, but
            // as_mut_view is required to keep borrow rules consistent

            for (c1, c0) in izip!(ct1.as_mut(), ct0.as_ref()) {
                *c1 = c1.wrapping_sub(*c0);
            }

            add_assign_ext_prod(
                ct0.as_mut_view(),
                mod_p0,
                mod_p1,
                mod_p2,
                mod_p3,
                mod_p4,
                mod_p5,
                mod_p6,
                mod_p7,
                mod_p8,
                mod_p9,
                ct1.as_view(),
                &ntt,
                stack,
            );
        }
    }

    if !ciphertext_modulus.is_native_modulus() {
        // When we convert back from the fourier domain, integer values will contain up to
        // about 100 MSBs with information. In our representation of power of 2
        // moduli < native modulus we fill the MSBs and leave the LSBs
        // empty, this usage of the signed decomposer allows to round while
        // keeping the data in the MSBs
        let signed_decomposer = SignedDecomposer::new(
            DecompositionBaseLog(ciphertext_modulus.get_custom_modulus().ilog2() as usize),
            DecompositionLevelCount(1),
        );
        ct0.as_mut()
            .iter_mut()
            .for_each(|x| *x = signed_decomposer.closest_representable(*x));
    }
}

fn add_assign_ext_prod(
    mut out: GlweCiphertext<&mut [u128]>,
    mod_p0: NttGgswCiphertext<&[u32]>,
    mod_p1: NttGgswCiphertext<&[u32]>,
    mod_p2: NttGgswCiphertext<&[u32]>,
    mod_p3: NttGgswCiphertext<&[u32]>,
    mod_p4: NttGgswCiphertext<&[u32]>,
    mod_p5: NttGgswCiphertext<&[u32]>,
    mod_p6: NttGgswCiphertext<&[u32]>,
    mod_p7: NttGgswCiphertext<&[u32]>,
    mod_p8: NttGgswCiphertext<&[u32]>,
    mod_p9: NttGgswCiphertext<&[u32]>,
    glwe: GlweCiphertext<&[u128]>,
    ntt: &Plan32,
    stack: PodStack<'_>,
) {
    let align = CACHELINE_ALIGN;
    let ciphertext_modulus = glwe.ciphertext_modulus();
    let decomposition_base_log = mod_p0.decomposition_base_log();
    let decomposition_level_count = mod_p0.decomposition_level_count();

    // we round the input mask and body
    let decomposer =
        SignedDecomposer::<u128>::new(decomposition_base_log, decomposition_level_count);

    let glwe_size = mod_p0.glwe_size();
    let polynomial_size = mod_p0.polynomial_size();

    let (output_ntt_buffer_mod_p0, stack) =
        stack.make_aligned_with(polynomial_size.0 * glwe_size.0, align, |_| 0u32);
    let (output_ntt_buffer_mod_p1, stack) =
        stack.make_aligned_with(polynomial_size.0 * glwe_size.0, align, |_| 0u32);
    let (output_ntt_buffer_mod_p2, stack) =
        stack.make_aligned_with(polynomial_size.0 * glwe_size.0, align, |_| 0u32);
    let (output_ntt_buffer_mod_p3, stack) =
        stack.make_aligned_with(polynomial_size.0 * glwe_size.0, align, |_| 0u32);
    let (output_ntt_buffer_mod_p4, stack) =
        stack.make_aligned_with(polynomial_size.0 * glwe_size.0, align, |_| 0u32);
    let (output_ntt_buffer_mod_p5, stack) =
        stack.make_aligned_with(polynomial_size.0 * glwe_size.0, align, |_| 0u32);
    let (output_ntt_buffer_mod_p6, stack) =
        stack.make_aligned_with(polynomial_size.0 * glwe_size.0, align, |_| 0u32);
    let (output_ntt_buffer_mod_p7, stack) =
        stack.make_aligned_with(polynomial_size.0 * glwe_size.0, align, |_| 0u32);
    let (output_ntt_buffer_mod_p8, stack) =
        stack.make_aligned_with(polynomial_size.0 * glwe_size.0, align, |_| 0u32);
    let (output_ntt_buffer_mod_p9, mut substack0) =
        stack.make_aligned_with(polynomial_size.0 * glwe_size.0, align, |_| 0u32);

    // output_fft_buffer is initially uninitialized, considered to be implicitly zero,
    // to avoid the cost of filling it up with zeros. `is_output_uninit`
    // is set to `false` once it has been fully initialized for the
    // first time.
    // let mut is_output_uninit = true;

    {
        // ------------------------------------------------------ EXTERNAL PRODUCT IN
        // FOURIER DOMAIN In this section, we perform the external
        // product in the fourier domain, and accumulate the result
        // in the output_fft_buffer variable.
        let (mut decomposition, mut substack1) = TensorSignedDecompositionLendingIter::new(
            glwe.as_ref()
                .iter()
                .map(|s| decomposer.init_decomposer_state(*s)),
            DecompositionBaseLog(decomposer.base_log),
            DecompositionLevelCount(decomposer.level_count),
            substack0.rb_mut(),
        );

        let mut decomp_levels = Vec::with_capacity(decomposition_level_count.0);

        let mut substack2 = {
            let mut tmp_substack = substack1;
            for _ in 0..decomposition_level_count.0 {
                // We retrieve the decomposition of this level.
                let (_, glwe_decomp_term, substack2) =
                    collect_take_next_term(&mut decomposition, tmp_substack, align);
                let (ntt_mod_p0, stack) =
                    substack2.make_aligned_raw::<u32>(polynomial_size.0 * glwe_size.0, align);
                let (ntt_mod_p1, stack) =
                    stack.make_aligned_raw::<u32>(polynomial_size.0 * glwe_size.0, align);
                let (ntt_mod_p2, stack) =
                    stack.make_aligned_raw::<u32>(polynomial_size.0 * glwe_size.0, align);
                let (ntt_mod_p3, stack) =
                    stack.make_aligned_raw::<u32>(polynomial_size.0 * glwe_size.0, align);
                let (ntt_mod_p4, stack) =
                    stack.make_aligned_raw::<u32>(polynomial_size.0 * glwe_size.0, align);
                let (ntt_mod_p5, stack) =
                    stack.make_aligned_raw::<u32>(polynomial_size.0 * glwe_size.0, align);
                let (ntt_mod_p6, stack) =
                    stack.make_aligned_raw::<u32>(polynomial_size.0 * glwe_size.0, align);
                let (ntt_mod_p7, stack) =
                    stack.make_aligned_raw::<u32>(polynomial_size.0 * glwe_size.0, align);
                let (ntt_mod_p8, stack) =
                    stack.make_aligned_raw::<u32>(polynomial_size.0 * glwe_size.0, align);
                let (ntt_mod_p9, stack) =
                    stack.make_aligned_raw::<u32>(polynomial_size.0 * glwe_size.0, align);
                decomp_levels.push((
                    glwe_decomp_term,
                    (
                        ntt_mod_p0, ntt_mod_p1, ntt_mod_p2, ntt_mod_p3, ntt_mod_p4, ntt_mod_p5,
                        ntt_mod_p6, ntt_mod_p7, ntt_mod_p8, ntt_mod_p9,
                    ),
                ));
                tmp_substack = stack;
            }
            tmp_substack
        };

        // let stack = substack2.rb_mut();
        // let (ntt_mod_p0, stack) = stack.make_aligned_raw::<u32>(len, align);
        // let (ntt_mod_p1, stack) = stack.make_aligned_raw::<u32>(len, align);
        // let (ntt_mod_p2, stack) = stack.make_aligned_raw::<u32>(len, align);
        // let (ntt_mod_p3, stack) = stack.make_aligned_raw::<u32>(len, align);
        // let (ntt_mod_p4, stack) = stack.make_aligned_raw::<u32>(len, align);
        // let (ntt_mod_p5, stack) = stack.make_aligned_raw::<u32>(len, align);
        // let (ntt_mod_p6, stack) = stack.make_aligned_raw::<u32>(len, align);
        // let (ntt_mod_p7, stack) = stack.make_aligned_raw::<u32>(len, align);
        // let (ntt_mod_p8, stack) = stack.make_aligned_raw::<u32>(len, align);
        // let (ntt_mod_p9, _stack) = stack.make_aligned_raw::<u32>(len, align);

        decomp_levels
            .par_iter_mut()
            .enumerate()
            .for_each(|(index, (level_slice, out_buffers))| {
                let ggws_decomp_matrix_mod_p0 = mod_p0.get_level(index);
                let ggws_decomp_matrix_mod_p1 = mod_p1.get_level(index);
                let ggws_decomp_matrix_mod_p2 = mod_p2.get_level(index);
                let ggws_decomp_matrix_mod_p3 = mod_p3.get_level(index);
                let ggws_decomp_matrix_mod_p4 = mod_p4.get_level(index);
                let ggws_decomp_matrix_mod_p5 = mod_p5.get_level(index);
                let ggws_decomp_matrix_mod_p6 = mod_p6.get_level(index);
                let ggws_decomp_matrix_mod_p7 = mod_p7.get_level(index);
                let ggws_decomp_matrix_mod_p8 = mod_p8.get_level(index);
                let ggws_decomp_matrix_mod_p9 = mod_p9.get_level(index);

                let mut buffer = ComputationBuffers::new();
                buffer.resize(1 << 20);

                let stack = buffer.stack();

                let mut glwe_decomp_term = GlweCiphertextMutView::from_container(
                    level_slice,
                    polynomial_size,
                    ciphertext_modulus,
                );

                let (
                    output_ntt_buffer_mod_p0,
                    output_ntt_buffer_mod_p1,
                    output_ntt_buffer_mod_p2,
                    output_ntt_buffer_mod_p3,
                    output_ntt_buffer_mod_p4,
                    output_ntt_buffer_mod_p5,
                    output_ntt_buffer_mod_p6,
                    output_ntt_buffer_mod_p7,
                    output_ntt_buffer_mod_p8,
                    output_ntt_buffer_mod_p9,
                ) = out_buffers;

                let len = polynomial_size.0;

                let (ntt_mod_p0, stack) = stack.make_aligned_raw::<u32>(len, align);
                let (ntt_mod_p1, stack) = stack.make_aligned_raw::<u32>(len, align);
                let (ntt_mod_p2, stack) = stack.make_aligned_raw::<u32>(len, align);
                let (ntt_mod_p3, stack) = stack.make_aligned_raw::<u32>(len, align);
                let (ntt_mod_p4, stack) = stack.make_aligned_raw::<u32>(len, align);
                let (ntt_mod_p5, stack) = stack.make_aligned_raw::<u32>(len, align);
                let (ntt_mod_p6, stack) = stack.make_aligned_raw::<u32>(len, align);
                let (ntt_mod_p7, stack) = stack.make_aligned_raw::<u32>(len, align);
                let (ntt_mod_p8, stack) = stack.make_aligned_raw::<u32>(len, align);
                let (ntt_mod_p9, _stack) = stack.make_aligned_raw::<u32>(len, align);

                // For each level we have to add the result of the vector-matrix product
                // between the decomposition of the glwe, and the
                // ggsw level matrix to the output. To do so, we
                // iteratively add to the output, the product between every line of the
                // matrix, and the corresponding (scalar) polynomial
                // in the glwe decomposition:
                //
                //                ggsw_mat                        ggsw_mat
                //   glwe_dec   | - - - - | <        glwe_dec   | - - - - |
                //  | - - - | x | - - - - |         | - - - | x | - - - - | <
                //    ^         | - - - - |             ^       | - - - - |
                //
                //        t = 1                           t = 2                     ...

                for (
                    ggws_row_mod_p0,
                    ggws_row_mod_p1,
                    ggws_row_mod_p2,
                    ggws_row_mod_p3,
                    ggws_row_mod_p4,
                    ggws_row_mod_p5,
                    ggws_row_mod_p6,
                    ggws_row_mod_p7,
                    ggws_row_mod_p8,
                    ggws_row_mod_p9,
                    mut glwe_poly,
                ) in izip!(
                    ggws_decomp_matrix_mod_p0.into_rows(),
                    ggws_decomp_matrix_mod_p1.into_rows(),
                    ggws_decomp_matrix_mod_p2.into_rows(),
                    ggws_decomp_matrix_mod_p3.into_rows(),
                    ggws_decomp_matrix_mod_p4.into_rows(),
                    ggws_decomp_matrix_mod_p5.into_rows(),
                    ggws_decomp_matrix_mod_p6.into_rows(),
                    ggws_decomp_matrix_mod_p7.into_rows(),
                    ggws_decomp_matrix_mod_p8.into_rows(),
                    ggws_decomp_matrix_mod_p9.into_rows(),
                    glwe_decomp_term.as_mut_polynomial_list().iter_mut()
                ) {
                    let len = polynomial_size.0;

                    // We perform the forward ntt transform for the glwe polynomial
                    ntt.fwd(
                        glwe_poly.as_ref(),
                        ntt_mod_p0,
                        ntt_mod_p1,
                        ntt_mod_p2,
                        ntt_mod_p3,
                        ntt_mod_p4,
                        ntt_mod_p5,
                        ntt_mod_p6,
                        ntt_mod_p7,
                        ntt_mod_p8,
                        ntt_mod_p9,
                    );
                    // Now we loop through the polynomials of the output, and add the
                    // corresponding product of polynomials.

                    for (
                        (
                            out_poly_p0,
                            out_poly_p1,
                            out_poly_p2,
                            out_poly_p3,
                            out_poly_p4,
                            out_poly_p5,
                            out_poly_p6,
                            out_poly_p7,
                            out_poly_p8,
                            out_poly_p9,
                        ),
                        (
                            ggsw_poly_p0,
                            ggsw_poly_p1,
                            ggsw_poly_p2,
                            ggsw_poly_p3,
                            ggsw_poly_p4,
                            ggsw_poly_p5,
                            ggsw_poly_p6,
                            ggsw_poly_p7,
                            ggsw_poly_p8,
                            ggsw_poly_p9,
                        ),
                    ) in izip!(
                        output_ntt_buffer_mod_p0.chunks_exact_mut(polynomial_size.0),
                        output_ntt_buffer_mod_p1.chunks_exact_mut(polynomial_size.0),
                        output_ntt_buffer_mod_p2.chunks_exact_mut(polynomial_size.0),
                        output_ntt_buffer_mod_p3.chunks_exact_mut(polynomial_size.0),
                        output_ntt_buffer_mod_p4.chunks_exact_mut(polynomial_size.0),
                        output_ntt_buffer_mod_p5.chunks_exact_mut(polynomial_size.0),
                        output_ntt_buffer_mod_p6.chunks_exact_mut(polynomial_size.0),
                        output_ntt_buffer_mod_p7.chunks_exact_mut(polynomial_size.0),
                        output_ntt_buffer_mod_p8.chunks_exact_mut(polynomial_size.0),
                        output_ntt_buffer_mod_p9.chunks_exact_mut(polynomial_size.0),
                    )
                    .zip(izip!(
                        ggws_row_mod_p0.as_ref().chunks_exact(polynomial_size.0),
                        ggws_row_mod_p1.as_ref().chunks_exact(polynomial_size.0),
                        ggws_row_mod_p2.as_ref().chunks_exact(polynomial_size.0),
                        ggws_row_mod_p3.as_ref().chunks_exact(polynomial_size.0),
                        ggws_row_mod_p4.as_ref().chunks_exact(polynomial_size.0),
                        ggws_row_mod_p5.as_ref().chunks_exact(polynomial_size.0),
                        ggws_row_mod_p6.as_ref().chunks_exact(polynomial_size.0),
                        ggws_row_mod_p7.as_ref().chunks_exact(polynomial_size.0),
                        ggws_row_mod_p8.as_ref().chunks_exact(polynomial_size.0),
                        ggws_row_mod_p9.as_ref().chunks_exact(polynomial_size.0),
                    )) {
                        ntt.mul_accumulate(
                            out_poly_p0,
                            out_poly_p1,
                            out_poly_p2,
                            out_poly_p3,
                            out_poly_p4,
                            out_poly_p5,
                            out_poly_p6,
                            out_poly_p7,
                            out_poly_p8,
                            out_poly_p9,
                            ntt_mod_p0,
                            ntt_mod_p1,
                            ntt_mod_p2,
                            ntt_mod_p3,
                            ntt_mod_p4,
                            ntt_mod_p5,
                            ntt_mod_p6,
                            ntt_mod_p7,
                            ntt_mod_p8,
                            ntt_mod_p9,
                            ggsw_poly_p0,
                            ggsw_poly_p1,
                            ggsw_poly_p2,
                            ggsw_poly_p3,
                            ggsw_poly_p4,
                            ggsw_poly_p5,
                            ggsw_poly_p6,
                            ggsw_poly_p7,
                            ggsw_poly_p8,
                            ggsw_poly_p9,
                        );

                        ntt.inv(
                            glwe_poly.as_mut(),
                            out_poly_p0,
                            out_poly_p1,
                            out_poly_p2,
                            out_poly_p3,
                            out_poly_p4,
                            out_poly_p5,
                            out_poly_p6,
                            out_poly_p7,
                            out_poly_p8,
                            out_poly_p9,
                        );
                    }

                    // // we initialized `output_fft_buffer, so we can set this to false
                    // is_output_uninit = false;
                }
            });

        // // We loop through the levels (we reverse to match the order of the
        // // decomposition iterator.)
        // for (
        //     ggws_decomp_matrix_mod_p0,
        //     ggws_decomp_matrix_mod_p1,
        //     ggws_decomp_matrix_mod_p2,
        //     ggws_decomp_matrix_mod_p3,
        //     ggws_decomp_matrix_mod_p4,
        //     ggws_decomp_matrix_mod_p5,
        //     ggws_decomp_matrix_mod_p6,
        //     ggws_decomp_matrix_mod_p7,
        //     ggws_decomp_matrix_mod_p8,
        //     ggws_decomp_matrix_mod_p9,
        // ) in izip!(
        //     mod_p0.into_levels(),
        //     mod_p1.into_levels(),
        //     mod_p2.into_levels(),
        //     mod_p3.into_levels(),
        //     mod_p4.into_levels(),
        //     mod_p5.into_levels(),
        //     mod_p6.into_levels(),
        //     mod_p7.into_levels(),
        //     mod_p8.into_levels(),
        //     mod_p9.into_levels(),
        // ) {
        //     let glwe_decomp_term = GlweCiphertextView::from_container(
        //         &*glwe_decomp_term,
        //         polynomial_size,
        //         ciphertext_modulus,
        //     );

        //     // For each level we have to add the result of the vector-matrix product
        //     // between the decomposition of the glwe, and the
        //     // ggsw level matrix to the output. To do so, we
        //     // iteratively add to the output, the product between every line of the
        //     // matrix, and the corresponding (scalar) polynomial
        //     // in the glwe decomposition:
        //     //
        //     //                ggsw_mat                        ggsw_mat
        //     //   glwe_dec   | - - - - | <        glwe_dec   | - - - - |
        //     //  | - - - | x | - - - - |         | - - - | x | - - - - | <
        //     //    ^         | - - - - |             ^       | - - - - |
        //     //
        //     //        t = 1                           t = 2                     ...

        //     for (
        //         ggws_row_mod_p0,
        //         ggws_row_mod_p1,
        //         ggws_row_mod_p2,
        //         ggws_row_mod_p3,
        //         ggws_row_mod_p4,
        //         ggws_row_mod_p5,
        //         ggws_row_mod_p6,
        //         ggws_row_mod_p7,
        //         ggws_row_mod_p8,
        //         ggws_row_mod_p9,
        //         glwe_poly,
        //     ) in izip!(
        //         ggws_decomp_matrix_mod_p0.into_rows(),
        //         ggws_decomp_matrix_mod_p1.into_rows(),
        //         ggws_decomp_matrix_mod_p2.into_rows(),
        //         ggws_decomp_matrix_mod_p3.into_rows(),
        //         ggws_decomp_matrix_mod_p4.into_rows(),
        //         ggws_decomp_matrix_mod_p5.into_rows(),
        //         ggws_decomp_matrix_mod_p6.into_rows(),
        //         ggws_decomp_matrix_mod_p7.into_rows(),
        //         ggws_decomp_matrix_mod_p8.into_rows(),
        //         ggws_decomp_matrix_mod_p9.into_rows(),
        //         glwe_decomp_term.as_polynomial_list().iter()
        //     ) {
        //         let len = polynomial_size.0;

        //         // We perform the forward ntt transform for the glwe polynomial
        //         ntt.fwd(
        //             glwe_poly.as_ref(),
        //             ntt_mod_p0,
        //             ntt_mod_p1,
        //             ntt_mod_p2,
        //             ntt_mod_p3,
        //             ntt_mod_p4,
        //             ntt_mod_p5,
        //             ntt_mod_p6,
        //             ntt_mod_p7,
        //             ntt_mod_p8,
        //             ntt_mod_p9,
        //         );
        //         // Now we loop through the polynomials of the output, and add the
        //         // corresponding product of polynomials.

        //         for (
        //             (
        //                 out_poly_p0,
        //                 out_poly_p1,
        //                 out_poly_p2,
        //                 out_poly_p3,
        //                 out_poly_p4,
        //                 out_poly_p5,
        //                 out_poly_p6,
        //                 out_poly_p7,
        //                 out_poly_p8,
        //                 out_poly_p9,
        //             ),
        //             (
        //                 ggsw_poly_p0,
        //                 ggsw_poly_p1,
        //                 ggsw_poly_p2,
        //                 ggsw_poly_p3,
        //                 ggsw_poly_p4,
        //                 ggsw_poly_p5,
        //                 ggsw_poly_p6,
        //                 ggsw_poly_p7,
        //                 ggsw_poly_p8,
        //                 ggsw_poly_p9,
        //             ),
        //         ) in izip!(
        //             output_ntt_buffer_mod_p0.chunks_exact_mut(polynomial_size.0),
        //             output_ntt_buffer_mod_p1.chunks_exact_mut(polynomial_size.0),
        //             output_ntt_buffer_mod_p2.chunks_exact_mut(polynomial_size.0),
        //             output_ntt_buffer_mod_p3.chunks_exact_mut(polynomial_size.0),
        //             output_ntt_buffer_mod_p4.chunks_exact_mut(polynomial_size.0),
        //             output_ntt_buffer_mod_p5.chunks_exact_mut(polynomial_size.0),
        //             output_ntt_buffer_mod_p6.chunks_exact_mut(polynomial_size.0),
        //             output_ntt_buffer_mod_p7.chunks_exact_mut(polynomial_size.0),
        //             output_ntt_buffer_mod_p8.chunks_exact_mut(polynomial_size.0),
        //             output_ntt_buffer_mod_p9.chunks_exact_mut(polynomial_size.0),
        //         )
        //         .zip(izip!(
        //             ggws_row_mod_p0.as_ref().chunks_exact(polynomial_size.0),
        //             ggws_row_mod_p1.as_ref().chunks_exact(polynomial_size.0),
        //             ggws_row_mod_p2.as_ref().chunks_exact(polynomial_size.0),
        //             ggws_row_mod_p3.as_ref().chunks_exact(polynomial_size.0),
        //             ggws_row_mod_p4.as_ref().chunks_exact(polynomial_size.0),
        //             ggws_row_mod_p5.as_ref().chunks_exact(polynomial_size.0),
        //             ggws_row_mod_p6.as_ref().chunks_exact(polynomial_size.0),
        //             ggws_row_mod_p7.as_ref().chunks_exact(polynomial_size.0),
        //             ggws_row_mod_p8.as_ref().chunks_exact(polynomial_size.0),
        //             ggws_row_mod_p9.as_ref().chunks_exact(polynomial_size.0),
        //         )) {
        //             ntt.mul_accumulate(
        //                 out_poly_p0,
        //                 out_poly_p1,
        //                 out_poly_p2,
        //                 out_poly_p3,
        //                 out_poly_p4,
        //                 out_poly_p5,
        //                 out_poly_p6,
        //                 out_poly_p7,
        //                 out_poly_p8,
        //                 out_poly_p9,
        //                 ntt_mod_p0,
        //                 ntt_mod_p1,
        //                 ntt_mod_p2,
        //                 ntt_mod_p3,
        //                 ntt_mod_p4,
        //                 ntt_mod_p5,
        //                 ntt_mod_p6,
        //                 ntt_mod_p7,
        //                 ntt_mod_p8,
        //                 ntt_mod_p9,
        //                 ggsw_poly_p0,
        //                 ggsw_poly_p1,
        //                 ggsw_poly_p2,
        //                 ggsw_poly_p3,
        //                 ggsw_poly_p4,
        //                 ggsw_poly_p5,
        //                 ggsw_poly_p6,
        //                 ggsw_poly_p7,
        //                 ggsw_poly_p8,
        //                 ggsw_poly_p9,
        //             );
        //         }

        //         // // we initialized `output_fft_buffer, so we can set this to false
        //         // is_output_uninit = false;
        //     }
        // }

        // --------------------------------------------  TRANSFORMATION OF RESULT TO
        // STANDARD DOMAIN In this section, we bring the result from the
        // fourier domain, back to the standard domain, and add it to the
        // output.
        //
        // We iterate over the polynomials in the output.

        // let (tmp_inv_buff, _stack) =
        //     substack0.make_aligned_raw(polynomial_size.0 * glwe_size.0, align);

        for level_data in decomp_levels.iter() {
            let level_slice = &level_data.0;
            for (mut out, inp) in out
                .as_mut_polynomial_list()
                .iter_mut()
                .zip(level_slice.chunks_exact(polynomial_size.0))
            {
                out.as_mut()
                    .iter_mut()
                    .zip(inp.iter())
                    .for_each(|(dst, src)| *dst = (*dst).wrapping_add(*src));
            }
        }
    }
}
