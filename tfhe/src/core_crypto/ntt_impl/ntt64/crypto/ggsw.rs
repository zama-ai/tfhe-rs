use super::super::math::ntt::NttView;
use crate::core_crypto::commons::math::decomposition::{
    decompose_one_level_non_native, DecompositionLevel, SignedDecomposerNonNative,
};
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
};
use crate::core_crypto::commons::traits::{
    Container, ContiguousEntityContainer, ContiguousEntityContainerMut, Split,
};
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::UnsignedInteger;
use aligned_vec::{avec, ABox, CACHELINE_ALIGN};
use dyn_stack::{DynArray, PodStack, ReborrowMut, SizeOverflow, StackReq};
use std::iter::Map;
use std::slice::IterMut;

/// A GGSW ciphertext in the Ntt domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NttGgswCiphertext<C: Container<Element = u64>> {
    data: C,
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
}

/// A matrix containing a single level of gadget decomposition, in the Ntt domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NttGgswLevelMatrix<C: Container<Element = u64>> {
    data: C,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    row_count: usize,
    decomposition_level: DecompositionLevel,
}

/// A row of a GGSW level matrix, in the Ntt domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NttGgswLevelRow<C: Container<Element = u64>> {
    data: C,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomposition_level: DecompositionLevel,
}

pub type NttGgswCiphertextView<'a> = NttGgswCiphertext<&'a [u64]>;
pub type NttGgswCiphertextMutView<'a> = NttGgswCiphertext<&'a mut [u64]>;
pub type NttGgswLevelMatrixView<'a> = NttGgswLevelMatrix<&'a [u64]>;
pub type NttGgswLevelMatrixMutView<'a> = NttGgswLevelMatrix<&'a mut [u64]>;
pub type NttGgswLevelRowView<'a> = NttGgswLevelRow<&'a [u64]>;
pub type NttGgswLevelRowMutView<'a> = NttGgswLevelRow<&'a mut [u64]>;

impl<C: Container<Element = u64>> NttGgswCiphertext<C> {
    pub fn from_container(
        data: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        assert_eq!(
            data.container_len(),
            polynomial_size.0 * glwe_size.0 * glwe_size.0 * decomposition_level_count.0
        );

        Self {
            data,
            polynomial_size,
            glwe_size,
            decomposition_base_log,
            decomposition_level_count,
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomposition_base_log
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomposition_level_count
    }

    pub fn data(self) -> C {
        self.data
    }

    pub fn as_view(&self) -> NttGgswCiphertextView<'_>
    where
        C: AsRef<[u64]>,
    {
        NttGgswCiphertextView {
            data: self.data.as_ref(),
            polynomial_size: self.polynomial_size,
            glwe_size: self.glwe_size,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }

    pub fn as_mut_view(&mut self) -> NttGgswCiphertextMutView<'_>
    where
        C: AsMut<[u64]>,
    {
        NttGgswCiphertextMutView {
            data: self.data.as_mut(),
            polynomial_size: self.polynomial_size,
            glwe_size: self.glwe_size,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }
}

impl<C: Container<Element = u64>> NttGgswLevelMatrix<C> {
    pub fn new(
        data: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        row_count: usize,
        decomposition_level: DecompositionLevel,
    ) -> Self {
        assert_eq!(
            data.container_len(),
            polynomial_size.0 * glwe_size.0 * row_count
        );
        Self {
            data,
            polynomial_size,
            glwe_size,
            row_count,
            decomposition_level,
        }
    }

    /// Return an iterator over the rows of the level matrices.
    pub fn into_rows(self) -> impl DoubleEndedIterator<Item = NttGgswLevelRow<C>>
    where
        C: Split,
    {
        self.data
            .split_into(self.row_count)
            .map(move |slice| NttGgswLevelRow {
                data: slice,
                polynomial_size: self.polynomial_size,
                glwe_size: self.glwe_size,
                decomposition_level: self.decomposition_level,
            })
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    pub fn row_count(&self) -> usize {
        self.row_count
    }

    pub fn decomposition_level(&self) -> DecompositionLevel {
        self.decomposition_level
    }

    pub fn data(self) -> C {
        self.data
    }
}

impl<C: Container<Element = u64>> NttGgswLevelRow<C> {
    pub fn new(
        data: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_level: DecompositionLevel,
    ) -> Self {
        assert_eq!(data.container_len(), polynomial_size.0 * glwe_size.0);
        Self {
            data,
            polynomial_size,
            glwe_size,
            decomposition_level,
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    pub fn decomposition_level(&self) -> DecompositionLevel {
        self.decomposition_level
    }

    pub fn data(self) -> C {
        self.data
    }
}

impl<'a> NttGgswCiphertextView<'a> {
    /// Return an iterator over the level matrices.
    pub fn into_levels(self) -> impl DoubleEndedIterator<Item = NttGgswLevelMatrixView<'a>> {
        self.data
            .split_into(self.decomposition_level_count.0)
            .enumerate()
            .map(move |(i, slice)| {
                NttGgswLevelMatrixView::new(
                    slice,
                    self.glwe_size,
                    self.polynomial_size,
                    self.glwe_size.0,
                    DecompositionLevel(i + 1),
                )
            })
    }
}

impl<'a> NttGgswCiphertextMutView<'a> {
    /// Fill a GGSW ciphertext with the Ntt transform of a GGSW ciphertext in the standard
    /// domain.
    pub fn fill_with_forward_ntt(self, coef_ggsw: GgswCiphertextView<'_, u64>, ntt: NttView<'_>) {
        debug_assert_eq!(coef_ggsw.polynomial_size(), self.polynomial_size());
        let poly_size = coef_ggsw.polynomial_size().0;

        for (ntt_poly, coef_poly) in izip!(
            self.data().into_chunks(poly_size),
            coef_ggsw.as_polynomial_list().iter()
        ) {
            ntt.forward_normalized(PolynomialMutView::from_container(ntt_poly), coef_poly);
        }
    }
}

#[allow(unused)]
type NttGgswCiphertextOwned = NttGgswCiphertext<ABox<[u64]>>;

impl NttGgswCiphertext<ABox<[u64]>> {
    pub fn new(
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        let boxed = avec![
            u64::default();
            polynomial_size.0
                * glwe_size.0
                * glwe_size.0
                * decomposition_level_count.0
        ]
        .into_boxed_slice();

        NttGgswCiphertext::from_container(
            boxed,
            glwe_size,
            polynomial_size,
            decomposition_base_log,
            decomposition_level_count,
        )
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct NttGgswCiphertextList<C: Container<Element = u64>> {
    data: C,
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    decomposition_level_count: DecompositionLevelCount,
    decomposition_base_log: DecompositionBaseLog,
    count: usize,
}

pub type NttGgswCiphertextListView<'a> = NttGgswCiphertextList<&'a [u64]>;
pub type NttGgswCiphertextListMutView<'a> = NttGgswCiphertextList<&'a mut [u64]>;

impl<C: Container<Element = u64>> NttGgswCiphertextList<C> {
    pub fn new(
        data: C,
        count: usize,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        assert_eq!(
            data.container_len(),
            count * polynomial_size.0 * glwe_size.0 * glwe_size.0 * decomposition_level_count.0
        );

        Self {
            data,
            polynomial_size,
            count,
            glwe_size,
            decomposition_level_count,
            decomposition_base_log,
        }
    }

    pub fn data(self) -> C {
        self.data
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomposition_level_count
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomposition_base_log
    }

    pub fn as_view(&self) -> NttGgswCiphertextListView<'_> {
        NttGgswCiphertextListView {
            data: self.data.as_ref(),
            polynomial_size: self.polynomial_size,
            count: self.count,
            glwe_size: self.glwe_size,
            decomposition_level_count: self.decomposition_level_count,
            decomposition_base_log: self.decomposition_base_log,
        }
    }

    pub fn as_mut_view(&mut self) -> NttGgswCiphertextListMutView<'_>
    where
        C: AsMut<[u64]>,
    {
        NttGgswCiphertextListMutView {
            data: self.data.as_mut(),
            polynomial_size: self.polynomial_size,
            count: self.count,
            glwe_size: self.glwe_size,
            decomposition_level_count: self.decomposition_level_count,
            decomposition_base_log: self.decomposition_base_log,
        }
    }

    pub fn into_ggsw_iter(self) -> impl DoubleEndedIterator<Item = NttGgswCiphertext<C>>
    where
        C: Split,
    {
        self.data.split_into(self.count).map(move |slice| {
            NttGgswCiphertext::from_container(
                slice,
                self.glwe_size,
                self.polynomial_size,
                self.decomposition_base_log,
                self.decomposition_level_count,
            )
        })
    }

    pub fn split_at(self, mid: usize) -> (Self, Self)
    where
        C: Split,
    {
        let polynomial_size = self.polynomial_size;
        let glwe_size = self.glwe_size;
        let decomposition_level_count = self.decomposition_level_count;
        let decomposition_base_log = self.decomposition_base_log;

        let (left, right) = self.data.split_at(
            mid * polynomial_size.0 * glwe_size.0 * glwe_size.0 * decomposition_level_count.0,
        );
        (
            Self::new(
                left,
                mid,
                glwe_size,
                polynomial_size,
                decomposition_base_log,
                decomposition_level_count,
            ),
            Self::new(
                right,
                self.count - mid,
                glwe_size,
                polynomial_size,
                decomposition_base_log,
                decomposition_level_count,
            ),
        )
    }
}

/// Return the required memory for [`add_external_product_assign`].
pub fn add_external_product_assign_scratch(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    ntt: NttView<'_>,
) -> Result<StackReq, SizeOverflow> {
    let align = CACHELINE_ALIGN;
    let standard_scratch =
        StackReq::try_new_aligned::<u64>(glwe_size.0 * polynomial_size.0, align)?;
    let ntt_scratch = StackReq::try_new_aligned::<u64>(glwe_size.0 * polynomial_size.0, align)?;
    let ntt_scratch_single = StackReq::try_new_aligned::<u64>(polynomial_size.0, align)?;
    let _ = &ntt;

    let substack2 = ntt_scratch_single;
    let substack1 = substack2.try_and(standard_scratch)?;
    let substack0 = substack1.try_and(standard_scratch)?;
    substack0.try_and(ntt_scratch)
}

/// Perform the external product of `ggsw` and `glwe`, and adds the result to `out`.
#[cfg_attr(__profiling, inline(never))]
pub fn add_external_product_assign<InputGlweCont>(
    mut out: GlweCiphertextMutView<'_, u64>,
    ggsw: NttGgswCiphertextView<'_>,
    glwe: GlweCiphertext<InputGlweCont>,
    ntt: NttView<'_>,
    stack: PodStack<'_>,
) where
    InputGlweCont: Container<Element = u64>,
{
    // we check that the polynomial sizes match
    debug_assert_eq!(ggsw.polynomial_size(), glwe.polynomial_size());
    debug_assert_eq!(ggsw.polynomial_size(), out.polynomial_size());
    // we check that the glwe sizes match
    debug_assert_eq!(ggsw.glwe_size(), glwe.glwe_size());
    debug_assert_eq!(ggsw.glwe_size(), out.glwe_size());

    let align = CACHELINE_ALIGN;
    let poly_size = ggsw.polynomial_size().0;

    // we round the input mask and body
    let decomposer = SignedDecomposerNonNative::<u64>::new(
        ggsw.decomposition_base_log(),
        ggsw.decomposition_level_count(),
        out.ciphertext_modulus(),
    );

    let (mut output_fft_buffer, mut substack0) =
        stack.make_aligned_raw::<u64>(poly_size * ggsw.glwe_size().0, align);
    // output_fft_buffer is initially uninitialized, considered to be implicitly zero, to avoid
    // the cost of filling it up with zeros. `is_output_uninit` is set to `false` once
    // it has been fully initialized for the first time.
    let output_fft_buffer = &mut *output_fft_buffer;
    let mut is_output_uninit = true;

    {
        // ------------------------------------------------------ EXTERNAL PRODUCT IN FOURIER DOMAIN
        // In this section, we perform the external product in the ntt domain, and accumulate
        // the result in the output_fft_buffer variable.
        let (mut decomposition, mut substack1) = TensorSignedDecompositionLendingIterNonNative::new(
            &decomposer,
            glwe.as_ref().iter().copied(),
            ntt.custom_modulus(),
            substack0.rb_mut(),
        );

        // We loop through the levels (we reverse to match the order of the decomposition iterator.)
        ggsw.into_levels().rev().for_each(|ggsw_decomp_matrix| {
            // We retrieve the decomposition of this level.
            let (glwe_level, glwe_decomp_term, mut substack2) =
                collect_next_term(&mut decomposition, &mut substack1, align);
            let glwe_decomp_term = GlweCiphertextView::from_container(
                &*glwe_decomp_term,
                ggsw.polynomial_size(),
                out.ciphertext_modulus(),
            );
            debug_assert_eq!(ggsw_decomp_matrix.decomposition_level(), glwe_level);

            // For each level we have to add the result of the vector-matrix product between the
            // decomposition of the glwe, and the ggsw level matrix to the output. To do so, we
            // iteratively add to the output, the product between every line of the matrix, and
            // the corresponding (scalar) polynomial in the glwe decomposition:
            //
            //                ggsw_mat                        ggsw_mat
            //   glwe_dec   | - - - - | <        glwe_dec   | - - - - |
            //  | - - - | x | - - - - |         | - - - | x | - - - - | <
            //    ^         | - - - - |             ^       | - - - - |
            //
            //        t = 1                           t = 2                     ...

            izip!(
                ggsw_decomp_matrix.into_rows(),
                glwe_decomp_term.as_polynomial_list().iter()
            )
            .for_each(|(ggsw_row, glwe_poly)| {
                let (mut ntt_poly, _) =
                    substack2.rb_mut().make_aligned_raw::<u64>(poly_size, align);
                // We perform the forward ntt transform for the glwe polynomial
                ntt.forward(PolynomialMutView::from_container(&mut ntt_poly), glwe_poly);
                // Now we loop through the polynomials of the output, and add the
                // corresponding product of polynomials.

                update_with_fmadd(
                    output_fft_buffer,
                    ggsw_row.data(),
                    &ntt_poly,
                    is_output_uninit,
                    poly_size,
                    ntt,
                );

                // we initialized `output_fft_buffer, so we can set this to false
                is_output_uninit = false;
            });
        });
    }

    // --------------------------------------------  TRANSFORMATION OF RESULT TO STANDARD DOMAIN
    // In this section, we bring the result from the ntt domain, back to the standard
    // domain, and add it to the output.
    //
    // We iterate over the polynomials in the output.
    if !is_output_uninit {
        izip!(
            out.as_mut_polynomial_list().iter_mut(),
            output_fft_buffer
                .into_chunks(poly_size)
                .map(PolynomialMutView::from_container),
        )
        .for_each(|(out, ntt_poly)| {
            ntt.add_backward(out, ntt_poly);
        });
    }
}

#[cfg_attr(__profiling, inline(never))]
pub(crate) fn update_with_fmadd(
    output_fft_buffer: &mut [u64],
    lhs_polynomial_list: &[u64],
    ntt_poly: &[u64],
    is_output_uninit: bool,
    poly_size: usize,
    ntt: NttView<'_>,
) {
    if is_output_uninit {
        output_fft_buffer.fill(0);
    }

    izip!(
        output_fft_buffer.into_chunks(poly_size),
        lhs_polynomial_list.into_chunks(poly_size)
    )
    .for_each(|(output_ntt, ggsw_poly)| {
        ntt.plan.mul_accumulate(output_ntt, ggsw_poly, ntt_poly);
    });
}

struct TensorSignedDecompositionLendingIterNonNative<'buffers> {
    // The base log of the decomposition
    base_log: usize,
    // The current level
    current_level: usize,
    // A mask which allows to compute the mod B of a value. For B=2^4, this guy is of the form:
    // ...0001111
    mod_b_mask: u64,
    // The internal states of each decomposition
    states: DynArray<'buffers, u64>,

    shift: u64,
    // A flag which stores whether the iterator is a fresh one (for the recompose method).
    fresh: bool,

    ciphertext_modulus: u64,
}

impl<'buffers> TensorSignedDecompositionLendingIterNonNative<'buffers> {
    #[inline]
    pub(crate) fn new(
        decomposer: &SignedDecomposerNonNative<u64>,
        input: impl Iterator<Item = u64>,
        modulus: u64,
        stack: PodStack<'buffers>,
    ) -> (Self, PodStack<'buffers>) {
        let (states, stack) = stack.collect_aligned(
            aligned_vec::CACHELINE_ALIGN,
            input.map(|i| {
                let (state_i, _) = decomposer.init_decomposition_state(i);
                state_i
            }),
        );
        let base_log = decomposer.base_log();
        let level_count = decomposer.level_count();
        (
            TensorSignedDecompositionLendingIterNonNative {
                base_log: base_log.0,
                current_level: level_count.0,
                mod_b_mask: (1u64 << base_log.0) - 1u64,
                states,
                shift: decomposer.shift,
                fresh: true,
                ciphertext_modulus: modulus,
            },
            stack,
        )
    }

    // inlining this improves perf of external product by about 25%, even in LTO builds
    #[inline]
    pub fn next_term<'short>(
        &'short mut self,
    ) -> Option<(
        DecompositionLevel,
        DecompositionBaseLog,
        Map<IterMut<'short, u64>, impl FnMut(&'short mut u64) -> u64>,
    )> {
        // The iterator is not fresh anymore.
        self.fresh = false;
        // We check if the decomposition is over
        if self.current_level == 0 {
            return None;
        }
        let current_level = self.current_level;
        let base_log = self.base_log;
        let mod_b_mask = self.mod_b_mask;
        let modulus = self.ciphertext_modulus;
        let shift = self.shift;
        self.current_level -= 1;

        Some((
            DecompositionLevel(current_level),
            DecompositionBaseLog(self.base_log),
            self.states.iter_mut().map(move |state| {
                decompose_one_level_non_native(base_log, state, mod_b_mask, modulus, shift)
            }),
        ))
    }
}

#[cfg_attr(__profiling, inline(never))]
fn collect_next_term<'a>(
    decomposition: &mut TensorSignedDecompositionLendingIterNonNative<'_>,
    substack1: &'a mut PodStack,
    align: usize,
) -> (
    DecompositionLevel,
    dyn_stack::DynArray<'a, u64>,
    PodStack<'a>,
) {
    let (glwe_level, _, glwe_decomp_term) = decomposition.next_term().unwrap();
    let (glwe_decomp_term, substack2) = substack1.rb_mut().collect_aligned(align, glwe_decomp_term);
    (glwe_level, glwe_decomp_term, substack2)
}

/// Return the required memory for [`cmux`].
pub fn cmux_scratch(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    ntt: NttView<'_>,
) -> Result<StackReq, SizeOverflow> {
    add_external_product_assign_scratch(glwe_size, polynomial_size, ntt)
}

/// This cmux mutates both ct1 and ct0. The result is in ct0 after the method was called.
pub fn cmux(
    ct0: GlweCiphertextMutView<'_, u64>,
    mut ct1: GlweCiphertextMutView<'_, u64>,
    ggsw: NttGgswCiphertextView<'_>,
    ntt: NttView<'_>,
    stack: PodStack<'_>,
) {
    izip!(ct1.as_mut(), ct0.as_ref(),).for_each(|(c1, c0)| {
        *c1 = c1.wrapping_sub_custom_mod(*c0, ntt.custom_modulus());
    });
    add_external_product_assign(ct0, ggsw, ct1, ntt, stack);
}
