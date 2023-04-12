use crate::core_crypto::commons::math::decomposition::{DecompositionLevel, SignedDecomposer};
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
};
use crate::core_crypto::commons::traits::contiguous_entity_container::ContiguousEntityContainerMut;
use crate::core_crypto::commons::traits::{Container, ContiguousEntityContainer, Split};
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::common::{
    as_mut_array, as_ref_array, chain_array_with_context, iter_array,
};
use crate::core_crypto::fft_impl::crt_ntt::math::ntt::CrtNtt;
use crate::core_crypto::fft_impl::fft64::math::decomposition::TensorSignedDecompositionLendingIter;
use crate::core_crypto::prelude::{CiphertextModulus, ContainerMut, UnsignedInteger};
use aligned_vec::CACHELINE_ALIGN;
use dyn_stack::{PodStack, ReborrowMut, SizeOverflow, StackReq};

/// A GGSW ciphertext in the NTT domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrtNttGgswCiphertext<
    CrtScalar,
    const N_COMPONENTS: usize,
    C: Container<Element = CrtScalar>,
> {
    data: [C; N_COMPONENTS],

    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
}

/// A matrix containing a single level of gadget decomposition, in the NTT domain.
pub struct CrtNttGgswLevelMatrix<
    CrtScalar,
    const N_COMPONENTS: usize,
    C: Container<Element = CrtScalar>,
> {
    data: [C; N_COMPONENTS],

    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    row_count: usize,
    decomposition_level: DecompositionLevel,
}

/// A row of a GGSW level matrix, in the NTT domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrtNttGgswLevelRow<
    CrtScalar,
    const N_COMPONENTS: usize,
    C: Container<Element = CrtScalar>,
> {
    data: [C; N_COMPONENTS],

    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    decomposition_level: DecompositionLevel,
}

impl<CrtScalar: UnsignedInteger, const N_COMPONENTS: usize, C: Container<Element = CrtScalar>>
    CrtNttGgswCiphertext<CrtScalar, N_COMPONENTS, C>
{
    pub fn from_container(
        data: [C; N_COMPONENTS],
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        let container_len =
            polynomial_size.0 * glwe_size.0 * glwe_size.0 * decomposition_level_count.0;

        data.iter()
            .for_each(|data| assert_eq!(data.container_len(), container_len));

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

    pub fn data(self) -> [C; N_COMPONENTS] {
        self.data
    }

    pub fn as_view(&self) -> CrtNttGgswCiphertext<CrtScalar, N_COMPONENTS, &[C::Element]> {
        CrtNttGgswCiphertext {
            data: as_ref_array(&self.data).map(|data| data.as_ref()),
            polynomial_size: self.polynomial_size,
            glwe_size: self.glwe_size,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }

    pub fn as_mut_view(
        &mut self,
    ) -> CrtNttGgswCiphertext<CrtScalar, N_COMPONENTS, &mut [C::Element]>
    where
        C: AsMut<[C::Element]>,
    {
        CrtNttGgswCiphertext {
            data: as_mut_array(&mut self.data).map(|data| data.as_mut()),
            polynomial_size: self.polynomial_size,
            glwe_size: self.glwe_size,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }

    /// Return an iterator over the level matrices.
    pub fn into_levels(
        self,
    ) -> impl DoubleEndedIterator<Item = CrtNttGgswLevelMatrix<CrtScalar, N_COMPONENTS, C>>
    where
        C: Split,
    {
        iter_array(
            self.data
                .map(|data| data.split_into(self.decomposition_level_count.0)),
        )
        .enumerate()
        .map(move |(i, data)| {
            CrtNttGgswLevelMatrix::from_container(
                data,
                self.polynomial_size,
                self.glwe_size,
                self.glwe_size.0,
                DecompositionLevel(i + 1),
            )
        })
    }
}

impl<CrtScalar: UnsignedInteger, const N_COMPONENTS: usize, C: Container<Element = CrtScalar>>
    CrtNttGgswLevelMatrix<CrtScalar, N_COMPONENTS, C>
{
    pub fn from_container(
        data: [C; N_COMPONENTS],
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
        row_count: usize,
        decomposition_level: DecompositionLevel,
    ) -> Self {
        let container_len = polynomial_size.0 * glwe_size.0 * row_count;

        data.iter()
            .for_each(|data| assert_eq!(data.container_len(), container_len));

        Self {
            data,
            polynomial_size,
            glwe_size,
            row_count,
            decomposition_level,
        }
    }

    pub fn into_rows(
        self,
    ) -> impl DoubleEndedIterator<Item = CrtNttGgswLevelRow<CrtScalar, N_COMPONENTS, C>>
    where
        C: Split,
    {
        iter_array(self.data.map(|data| data.split_into(self.row_count))).map(move |data| {
            CrtNttGgswLevelRow::from_container(
                data,
                self.polynomial_size,
                self.glwe_size,
                self.decomposition_level,
            )
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

    pub fn data(self) -> [C; N_COMPONENTS] {
        self.data
    }
}

impl<CrtScalar: UnsignedInteger, const N_COMPONENTS: usize, C: Container<Element = CrtScalar>>
    CrtNttGgswLevelRow<CrtScalar, N_COMPONENTS, C>
{
    pub fn from_container(
        data: [C; N_COMPONENTS],
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
        decomposition_level: DecompositionLevel,
    ) -> Self {
        let container_len = polynomial_size.0 * glwe_size.0;

        data.iter()
            .for_each(|data| assert_eq!(data.container_len(), container_len));

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

    pub fn data(self) -> [C; N_COMPONENTS] {
        self.data
    }
}

impl<CrtScalar: UnsignedInteger, const N_COMPONENTS: usize, Cont>
    CrtNttGgswCiphertext<CrtScalar, N_COMPONENTS, Cont>
where
    Cont: ContainerMut<Element = CrtScalar>,
{
    /// Fill a GGSW ciphertext with the NTT of a GGSW ciphertext in the standard domain.

    pub fn fill_with_forward_ntt<Scalar, ContGgsw>(
        &mut self,
        coef_ggsw: &GgswCiphertext<ContGgsw>,
        ntt_plan: Scalar::PlanView<'_>,
    ) where
        Scalar: CrtNtt<CrtScalar, N_COMPONENTS>,
        ContGgsw: Container<Element = Scalar>,
    {
        fn implementation<
            CrtScalar: UnsignedInteger,
            const N_COMPONENTS: usize,
            Scalar: CrtNtt<CrtScalar, N_COMPONENTS>,
        >(
            this: CrtNttGgswCiphertext<CrtScalar, N_COMPONENTS, &mut [CrtScalar]>,
            coef_ggsw: GgswCiphertext<&[Scalar]>,
            ntt_plan: Scalar::PlanView<'_>,
        ) {
            assert_eq!(coef_ggsw.polynomial_size(), this.polynomial_size());
            let poly_size = this.polynomial_size().0;
            let data = this.data();

            for (ntt, coef_poly) in izip!(
                iter_array(data.map(|data| data.into_chunks(poly_size))),
                coef_ggsw.as_polynomial_list().iter(),
            ) {
                Scalar::forward_normalized(ntt_plan, ntt, coef_poly.as_ref());
            }
        }

        implementation(self.as_mut_view(), coef_ggsw.as_view(), ntt_plan)
    }
}

pub fn add_external_product_assign_scratch<
    CrtScalar: UnsignedInteger,
    const N_COMPONENTS: usize,
    Scalar: CrtNtt<CrtScalar, N_COMPONENTS>,
>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
) -> Result<StackReq, SizeOverflow> {
    let align = CACHELINE_ALIGN;
    let standard_scratch =
        StackReq::try_new_aligned::<Scalar>(glwe_size.0 * polynomial_size.0, align)?;
    let ntt_scratch =
        StackReq::try_new_aligned::<CrtScalar>(glwe_size.0 * polynomial_size.0, align)?;
    let ntt_scratch_single = StackReq::try_new_aligned::<CrtScalar>(polynomial_size.0, align)?;

    let substack2 = StackReq::try_all_of([ntt_scratch_single; N_COMPONENTS])?;
    let substack1 = substack2.try_and(standard_scratch)?;
    let substack0 = StackReq::try_any_of([
        substack1.try_and(standard_scratch)?,
        Scalar::add_backward_scratch(polynomial_size)?,
    ])?;
    substack0.try_and(StackReq::try_all_of([ntt_scratch; N_COMPONENTS])?)
}

#[cfg_attr(__profiling, inline(never))]
pub fn add_external_product_assign<
    CrtScalar,
    const N_COMPONENTS: usize,
    Scalar,
    ContOut,
    ContGgsw,
    ContGlwe,
>(
    out: &mut GlweCiphertext<ContOut>,
    ggsw: &CrtNttGgswCiphertext<CrtScalar, N_COMPONENTS, ContGgsw>,
    glwe: &GlweCiphertext<ContGlwe>,
    ntt_plan: Scalar::PlanView<'_>,
    stack: PodStack<'_>,
) where
    CrtScalar: UnsignedInteger,
    Scalar: CrtNtt<CrtScalar, N_COMPONENTS>,
    ContOut: ContainerMut<Element = Scalar>,
    ContGgsw: Container<Element = CrtScalar>,
    ContGlwe: Container<Element = Scalar>,
{
    fn implementation<
        CrtScalar: UnsignedInteger,
        const N_COMPONENTS: usize,
        Scalar: CrtNtt<CrtScalar, N_COMPONENTS>,
    >(
        mut out: GlweCiphertext<&mut [Scalar]>,
        ggsw: CrtNttGgswCiphertext<CrtScalar, N_COMPONENTS, &[CrtScalar]>,
        glwe: GlweCiphertext<&[Scalar]>,
        ntt_plan: Scalar::PlanView<'_>,
        stack: PodStack<'_>,
    ) {
        // we check that the polynomial sizes match
        assert_eq!(ggsw.polynomial_size(), glwe.polynomial_size());
        assert_eq!(ggsw.polynomial_size(), out.polynomial_size());
        // we check that the glwe sizes match
        assert_eq!(ggsw.glwe_size(), glwe.glwe_size());
        assert_eq!(ggsw.glwe_size(), out.glwe_size());

        let align = CACHELINE_ALIGN;
        let poly_size = ggsw.polynomial_size().0;

        // we round the input mask and body
        let decomposer = SignedDecomposer::<Scalar>::new(
            ggsw.decomposition_base_log(),
            ggsw.decomposition_level_count(),
        );

        let (mut output_ntt_buffer, mut substack0) =
            chain_array_with_context::<_, _, N_COMPONENTS>(stack, |stack| {
                stack.make_aligned_with(poly_size * ggsw.glwe_size().0, align, |_| CrtScalar::ZERO)
            });

        let mut output_ntt_buffer =
            as_mut_array(&mut output_ntt_buffer).map(|buffer| &mut **buffer);
        {
            // ------------------------------------------------------ EXTERNAL PRODUCT IN FOURIER
            // DOMAIN In this section, we perform the external product in the NTT
            // domain, and accumulate the result in the output_ntt_buffer variable.
            let (mut decomposition, mut substack1) = TensorSignedDecompositionLendingIter::new(
                glwe.as_ref()
                    .iter()
                    .map(|s| decomposer.closest_representable(*s)),
                DecompositionBaseLog(decomposer.base_log),
                DecompositionLevelCount(decomposer.level_count),
                substack0.rb_mut(),
            );

            // We loop through the levels (we reverse to match the order of the decomposition
            // iterator.)
            for ggsw_decomp_matrix in ggsw.into_levels().rev() {
                // We retrieve the decomposition of this level.
                let (glwe_level, glwe_decomp_term, mut substack2) =
                    collect_next_term(&mut decomposition, &mut substack1, align);
                let glwe_decomp_term = GlweCiphertextView::from_container(
                    &*glwe_decomp_term,
                    ggsw.polynomial_size(),
                    CiphertextModulus::new_native(),
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

                for (ggsw_row, glwe_poly) in izip!(
                    ggsw_decomp_matrix.into_rows(),
                    glwe_decomp_term.as_polynomial_list().iter()
                ) {
                    let len = poly_size;
                    let stack = substack2.rb_mut();
                    let (mut ntt, _) =
                        chain_array_with_context::<_, _, N_COMPONENTS>(stack, |stack| {
                            stack.make_aligned_raw::<CrtScalar>(len, align)
                        });
                    let mut ntt = as_mut_array(&mut ntt).map(|ntt| &mut **ntt);

                    // We perform the forward NTT for the glwe polynomial
                    Scalar::forward(
                        ntt_plan,
                        as_mut_array(&mut ntt).map(|buf| &mut **buf),
                        glwe_poly.as_ref(),
                    );
                    // Now we loop through the polynomials of the output, and add the
                    // corresponding product of polynomials.
                    for (output_ntt, ggsw_poly) in izip!(
                        iter_array(
                            as_mut_array(&mut output_ntt_buffer)
                                .map(|buf| (&mut **buf).into_chunks(poly_size))
                        ),
                        iter_array(
                            as_ref_array(&ggsw_row.data).map(|buf| (&**buf).into_chunks(poly_size))
                        ),
                    ) {
                        Scalar::mul_accumulate(
                            ntt_plan,
                            output_ntt,
                            ggsw_poly,
                            as_ref_array(&ntt).map(|buf| &**buf),
                        );
                    }
                }
            }
        }

        // --------------------------------------------  TRANSFORMATION OF RESULT TO STANDARD DOMAIN
        // In this section, we bring the result from the fourier domain, back to the standard
        // domain, and add it to the output.
        //
        // We iterate over the polynomials in the output.
        for (mut out, ntt) in izip!(
            out.as_mut_polynomial_list().iter_mut(),
            iter_array(output_ntt_buffer.map(|buf| buf.into_chunks(poly_size))),
        ) {
            Scalar::add_backward(ntt_plan, out.as_mut(), ntt, substack0.rb_mut());
        }
    }

    implementation(
        out.as_mut_view(),
        ggsw.as_view(),
        glwe.as_view(),
        ntt_plan,
        stack,
    )
}

fn collect_next_term<'a, Scalar: UnsignedInteger>(
    decomposition: &mut TensorSignedDecompositionLendingIter<'_, Scalar>,
    substack1: &'a mut PodStack,
    align: usize,
) -> (
    DecompositionLevel,
    dyn_stack::DynArray<'a, Scalar>,
    PodStack<'a>,
) {
    let (glwe_level, _, glwe_decomp_term) = decomposition.next_term().unwrap();
    let (glwe_decomp_term, substack2) = substack1.rb_mut().collect_aligned(align, glwe_decomp_term);
    (glwe_level, glwe_decomp_term, substack2)
}

/// Return the required memory for [`cmux`].
pub fn cmux_scratch<CrtScalar: UnsignedInteger, const N_COMPONENTS: usize, Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
) -> Result<StackReq, SizeOverflow>
where
    Scalar: CrtNtt<CrtScalar, N_COMPONENTS>,
{
    add_external_product_assign_scratch::<CrtScalar, N_COMPONENTS, Scalar>(
        glwe_size,
        polynomial_size,
    )
}

/// This cmux mutates both ct1 and ct0. The result is in ct0 after the method was called.
pub fn cmux<CrtScalar, const N_COMPONENTS: usize, Scalar, ContCt0, ContCt1, ContGgsw>(
    ct0: &mut GlweCiphertext<ContCt0>,
    ct1: &mut GlweCiphertext<ContCt1>,
    ggsw: &CrtNttGgswCiphertext<CrtScalar, N_COMPONENTS, ContGgsw>,
    ntt_plan: Scalar::PlanView<'_>,
    stack: PodStack<'_>,
) where
    CrtScalar: UnsignedInteger,
    Scalar: CrtNtt<CrtScalar, N_COMPONENTS>,
    ContCt0: ContainerMut<Element = Scalar>,
    ContCt1: ContainerMut<Element = Scalar>,
    ContGgsw: Container<Element = CrtScalar>,
{
    fn implementation<
        CrtScalar: UnsignedInteger,
        const N_COMPONENTS: usize,
        Scalar: CrtNtt<CrtScalar, N_COMPONENTS>,
    >(
        mut ct0: GlweCiphertext<&mut [Scalar]>,
        mut ct1: GlweCiphertext<&mut [Scalar]>,
        ggsw: CrtNttGgswCiphertext<CrtScalar, N_COMPONENTS, &[CrtScalar]>,
        ntt_plan: Scalar::PlanView<'_>,
        stack: PodStack<'_>,
    ) {
        for (c1, c0) in izip!(ct1.as_mut(), ct0.as_ref(),) {
            *c1 = c1.wrapping_sub(*c0);
        }
        add_external_product_assign(&mut ct0, &ggsw, &ct1, ntt_plan, stack);
    }

    implementation(
        ct0.as_mut_view(),
        ct1.as_mut_view(),
        ggsw.as_view(),
        ntt_plan,
        stack,
    )
}
