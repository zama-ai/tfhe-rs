//! Module containing primitives pertaining to the Wopbs (WithOut padding PBS).

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::fft64::FftView;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use concrete_fft::c64;
use dyn_stack::{PodStack, SizeOverflow, StackReq};
use rayon::prelude::*;

mod implementation {
    #![allow(clippy::too_many_arguments)]

    use crate::core_crypto::algorithms::polynomial_algorithms::*;
    use crate::core_crypto::algorithms::*;
    use crate::core_crypto::commons::math::decomposition::DecompositionLevel;
    use crate::core_crypto::commons::math::fft64::FftView;
    use crate::core_crypto::commons::numeric::CastInto;
    use crate::core_crypto::commons::parameters::*;
    use crate::core_crypto::commons::traits::*;
    use crate::core_crypto::commons::utils::izip;
    use crate::core_crypto::entities::*;
    use aligned_vec::CACHELINE_ALIGN;
    use concrete_fft::c64;
    use dyn_stack::{PodStack, ReborrowMut, SizeOverflow, StackReq};

    pub fn extract_bits_scratch<Scalar>(
        input_lwe_dimension: LweDimension,
        ksk_after_key_size: LweDimension,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        fft: FftView<'_>,
    ) -> Result<StackReq, SizeOverflow> {
        let align = CACHELINE_ALIGN;

        let lwe_in_buffer =
            StackReq::try_new_aligned::<Scalar>(input_lwe_dimension.to_lwe_size().0, align)?;
        let lwe_out_ks_buffer =
            StackReq::try_new_aligned::<Scalar>(ksk_after_key_size.to_lwe_size().0, align)?;
        let pbs_accumulator =
            StackReq::try_new_aligned::<Scalar>(glwe_size.0 * polynomial_size.0, align)?;
        let lwe_out_pbs_buffer = StackReq::try_new_aligned::<Scalar>(
            glwe_size
                .to_glwe_dimension()
                .to_equivalent_lwe_dimension(polynomial_size)
                .to_lwe_size()
                .0,
            align,
        )?;
        let lwe_bit_left_shift_buffer = lwe_in_buffer;
        let bootstrap_scratch = programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<
            Scalar,
        >(glwe_size, polynomial_size, fft)?;

        lwe_in_buffer
            .try_and(lwe_out_ks_buffer)?
            .try_and(pbs_accumulator)?
            .try_and(lwe_out_pbs_buffer)?
            .try_and(StackReq::try_any_of([
                lwe_bit_left_shift_buffer,
                bootstrap_scratch,
            ])?)
    }

    /// Function to extract `number_of_bits_to_extract` from an [`LweCiphertext`] starting at the
    /// bit number `delta_log` (0-indexed) included.
    ///
    /// Output bits are ordered from the MSB to the LSB. Each one of them is output in a distinct
    /// LWE ciphertext, containing the encryption of the bit scaled by q/2 (i.e., the most
    /// significant bit in the plaintext representation).
    pub fn extract_bits<Scalar: UnsignedTorus + CastInto<usize>>(
        mut lwe_list_out: LweCiphertextList<&'_ mut [Scalar]>,
        lwe_in: LweCiphertext<&'_ [Scalar]>,
        ksk: LweKeyswitchKey<&'_ [Scalar]>,
        fourier_bsk: FourierLweBootstrapKeyView<'_>,
        delta_log: DeltaLog,
        number_of_bits_to_extract: ExtractedBitsCount,
        fft: FftView<'_>,
        stack: PodStack<'_>,
    ) {
        debug_assert!(lwe_list_out.ciphertext_modulus() == lwe_in.ciphertext_modulus());
        debug_assert!(lwe_in.ciphertext_modulus() == ksk.ciphertext_modulus());
        debug_assert!(
            ksk.ciphertext_modulus().is_native_modulus(),
            "This operation only supports native moduli"
        );

        let ciphertext_n_bits = Scalar::BITS;
        let number_of_bits_to_extract = number_of_bits_to_extract.0;

        debug_assert!(
            ciphertext_n_bits >= number_of_bits_to_extract + delta_log.0,
            "Tried to extract {} bits, while the maximum number of extractable bits for {} bits
        ciphertexts and a scaling factor of 2^{} is {}",
            number_of_bits_to_extract,
            ciphertext_n_bits,
            delta_log.0,
            ciphertext_n_bits - delta_log.0,
        );
        debug_assert!(
            lwe_list_out.lwe_size().to_lwe_dimension() == ksk.output_key_lwe_dimension(),
            "lwe_list_out needs to have an lwe_size of {}, got {}",
            ksk.output_key_lwe_dimension().0,
            lwe_list_out.lwe_size().to_lwe_dimension().0,
        );
        debug_assert!(
            lwe_list_out.lwe_ciphertext_count().0 == number_of_bits_to_extract,
            "lwe_list_out needs to have a ciphertext count of {}, got {}",
            number_of_bits_to_extract,
            lwe_list_out.lwe_ciphertext_count().0,
        );
        debug_assert!(
            lwe_in.lwe_size() == fourier_bsk.output_lwe_dimension().to_lwe_size(),
            "lwe_in needs to have an LWE dimension of {}, got {}",
            fourier_bsk.output_lwe_dimension().to_lwe_size().0,
            lwe_in.lwe_size().0,
        );
        debug_assert!(
            ksk.output_key_lwe_dimension() == fourier_bsk.input_lwe_dimension(),
            "ksk needs to have an output LWE dimension of {}, got {}",
            fourier_bsk.input_lwe_dimension().0,
            ksk.output_key_lwe_dimension().0,
        );
        debug_assert!(lwe_list_out.ciphertext_modulus() == lwe_in.ciphertext_modulus());
        debug_assert!(lwe_in.ciphertext_modulus() == ksk.ciphertext_modulus());

        let polynomial_size = fourier_bsk.polynomial_size();
        let glwe_size = fourier_bsk.glwe_size();
        let glwe_dimension = glwe_size.to_glwe_dimension();
        let ciphertext_modulus = lwe_in.ciphertext_modulus();

        let align = CACHELINE_ALIGN;

        let (mut lwe_in_buffer_data, stack) =
            stack.collect_aligned(align, lwe_in.as_ref().iter().copied());
        let mut lwe_in_buffer =
            LweCiphertext::from_container(&mut *lwe_in_buffer_data, lwe_in.ciphertext_modulus());

        let (mut lwe_out_ks_buffer_data, stack) =
            stack.make_aligned_with(ksk.output_lwe_size().0, align, |_| Scalar::ZERO);
        let mut lwe_out_ks_buffer =
            LweCiphertext::from_container(&mut *lwe_out_ks_buffer_data, ksk.ciphertext_modulus());

        let (mut pbs_accumulator_data, stack) =
            stack.make_aligned_with(glwe_size.0 * polynomial_size.0, align, |_| Scalar::ZERO);
        let mut pbs_accumulator = GlweCiphertextMutView::from_container(
            &mut *pbs_accumulator_data,
            polynomial_size,
            ciphertext_modulus,
        );

        let lwe_size = glwe_dimension
            .to_equivalent_lwe_dimension(polynomial_size)
            .to_lwe_size();
        let (mut lwe_out_pbs_buffer_data, mut stack) =
            stack.make_aligned_with(lwe_size.0, align, |_| Scalar::ZERO);
        let mut lwe_out_pbs_buffer = LweCiphertext::from_container(
            &mut *lwe_out_pbs_buffer_data,
            lwe_list_out.ciphertext_modulus(),
        );

        // We iterate on the list in reverse as we want to store the extracted MSB at index 0
        for (bit_idx, mut output_ct) in lwe_list_out.iter_mut().rev().enumerate() {
            // Shift on padding bit
            let (lwe_bit_left_shift_buffer_data, _) = stack.rb_mut().collect_aligned(
                align,
                lwe_in_buffer
                    .as_ref()
                    .iter()
                    .map(|s| *s << (ciphertext_n_bits - delta_log.0 - bit_idx - 1)),
            );

            // Key switch to input PBS key
            keyswitch_lwe_ciphertext(
                &ksk,
                &LweCiphertext::from_container(
                    &*lwe_bit_left_shift_buffer_data,
                    lwe_in.ciphertext_modulus(),
                ),
                &mut lwe_out_ks_buffer,
            );

            drop(lwe_bit_left_shift_buffer_data);

            // Store the keyswitch output unmodified to the output list (as we need to to do other
            // computations on the output of the keyswitch)
            output_ct
                .as_mut()
                .copy_from_slice(lwe_out_ks_buffer.as_ref());

            // If this was the last extracted bit, break
            // we subtract 1 because if the number_of_bits_to_extract is 1 we want to stop right
            // away
            if bit_idx == number_of_bits_to_extract - 1 {
                break;
            }

            // Add q/4 to center the error while computing a negacyclic LUT
            let out_ks_body = lwe_out_ks_buffer.get_mut_body().data;
            *out_ks_body = (*out_ks_body).wrapping_add(Scalar::ONE << (ciphertext_n_bits - 2));

            // Fill lut for the current bit (equivalent to trivial encryption as mask is 0s)
            // The LUT is filled with -alpha in each coefficient where alpha = delta*2^{bit_idx-1}
            for poly_coeff in &mut pbs_accumulator
                .as_mut_view()
                .get_mut_body()
                .as_mut_polynomial()
                .iter_mut()
            {
                *poly_coeff = Scalar::ZERO.wrapping_sub(Scalar::ONE << (delta_log.0 - 1 + bit_idx));
            }

            fourier_bsk.bootstrap(
                lwe_out_pbs_buffer.as_mut_view(),
                lwe_out_ks_buffer.as_view(),
                pbs_accumulator.as_view(),
                fft,
                stack.rb_mut(),
            );

            // Add alpha where alpha = delta*2^{bit_idx-1} to end up with an encryption of 0 if the
            // extracted bit was 0 and 1 in the other case
            let out_pbs_body = lwe_out_pbs_buffer.get_mut_body().data;

            *out_pbs_body =
                (*out_pbs_body).wrapping_add(Scalar::ONE << (delta_log.0 + bit_idx - 1));

            // Remove the extracted bit from the initial LWE to get a 0 at the extracted bit
            // location.
            izip!(lwe_in_buffer.as_mut(), lwe_out_pbs_buffer.as_ref())
                .for_each(|(out, inp)| *out = (*out).wrapping_sub(*inp));
        }
    }

    pub fn circuit_bootstrap_boolean_scratch<Scalar>(
        lwe_in_size: LweSize,
        bsk_output_lwe_size: LweSize,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        fft: FftView<'_>,
    ) -> Result<StackReq, SizeOverflow> {
        StackReq::try_new_aligned::<Scalar>(bsk_output_lwe_size.0, CACHELINE_ALIGN)?.try_and(
            homomorphic_shift_boolean_scratch::<Scalar>(
                lwe_in_size,
                glwe_size,
                polynomial_size,
                fft,
            )?,
        )
    }

    /// Circuit bootstrapping for boolean messages, i.e. containing only one bit of message
    ///
    /// The output GGSW ciphertext `ggsw_out` decomposition base log and level count are used as the
    /// circuit_bootstrap_boolean decomposition base log and level count.
    pub fn circuit_bootstrap_boolean<Scalar: UnsignedTorus + CastInto<usize>>(
        fourier_bsk: FourierLweBootstrapKeyView<'_>,
        lwe_in: LweCiphertext<&[Scalar]>,
        mut ggsw_out: GgswCiphertext<&mut [Scalar]>,
        delta_log: DeltaLog,
        pfpksk_list: LwePrivateFunctionalPackingKeyswitchKeyList<&[Scalar]>,
        fft: FftView<'_>,
        stack: PodStack<'_>,
    ) {
        debug_assert!(lwe_in.ciphertext_modulus() == ggsw_out.ciphertext_modulus());
        debug_assert!(ggsw_out.ciphertext_modulus() == pfpksk_list.ciphertext_modulus());

        debug_assert!(
            pfpksk_list.ciphertext_modulus().is_native_modulus(),
            "This operation currently only supports native moduli"
        );

        let level_cbs = ggsw_out.decomposition_level_count();
        let base_log_cbs = ggsw_out.decomposition_base_log();

        debug_assert!(
            level_cbs.0 >= 1,
            "level_cbs needs to be >= 1, got {}",
            level_cbs.0
        );
        debug_assert!(
            base_log_cbs.0 >= 1,
            "base_log_cbs needs to be >= 1, got {}",
            base_log_cbs.0
        );

        let fpksk_input_lwe_key_dimension = pfpksk_list.input_key_lwe_dimension();
        let fourier_bsk_output_lwe_dimension = fourier_bsk.output_lwe_dimension();

        debug_assert!(
            fpksk_input_lwe_key_dimension == fourier_bsk_output_lwe_dimension,
            "The fourier_bsk output_lwe_dimension, got {}, must be equal to the fpksk \
        input_lwe_key_dimension, got {}",
            fourier_bsk_output_lwe_dimension.0,
            fpksk_input_lwe_key_dimension.0
        );

        let fpksk_output_polynomial_size = pfpksk_list.output_polynomial_size();
        let fpksk_output_glwe_key_dimension = pfpksk_list.output_key_glwe_dimension();

        debug_assert!(
            ggsw_out.polynomial_size() == fpksk_output_polynomial_size,
            "The output GGSW ciphertext needs to have the same polynomial size as the fpksks, \
        got {}, expected {}",
            ggsw_out.polynomial_size().0,
            fpksk_output_polynomial_size.0
        );

        debug_assert!(
            ggsw_out.glwe_size().to_glwe_dimension() == fpksk_output_glwe_key_dimension,
            "The output GGSW ciphertext needs to have the same GLWE dimension as the fpksks, \
        got {}, expected {}",
            ggsw_out.glwe_size().to_glwe_dimension().0,
            fpksk_output_glwe_key_dimension.0
        );

        debug_assert!(
            ggsw_out.glwe_size().0 == pfpksk_list.lwe_pfpksk_count().0,
            "The input vector of pfpksk_list needs to have {} ggsw.glwe_size elements got {}",
            ggsw_out.glwe_size().0,
            pfpksk_list.lwe_pfpksk_count().0,
        );

        // Output for every bootstrapping
        let (mut lwe_out_bs_buffer_data, mut stack) = stack.make_aligned_with(
            fourier_bsk_output_lwe_dimension.to_lwe_size().0,
            CACHELINE_ALIGN,
            |_| Scalar::ZERO,
        );
        let mut lwe_out_bs_buffer = LweCiphertext::from_container(
            &mut *lwe_out_bs_buffer_data,
            lwe_in.ciphertext_modulus(),
        );

        for (decomposition_level_minus_one, mut ggsw_level_matrix) in
            ggsw_out.iter_mut().enumerate()
        {
            let decomposition_level = DecompositionLevel(decomposition_level_minus_one + 1);
            homomorphic_shift_boolean(
                fourier_bsk,
                lwe_out_bs_buffer.as_mut_view(),
                lwe_in.as_view(),
                decomposition_level,
                base_log_cbs,
                delta_log,
                fft,
                stack.rb_mut(),
            );

            for (pfpksk, mut glwe_out) in pfpksk_list
                .iter()
                .zip(ggsw_level_matrix.as_mut_glwe_list().iter_mut())
            {
                private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
                    &pfpksk,
                    &mut glwe_out,
                    &lwe_out_bs_buffer,
                );
            }
        }
    }

    pub fn homomorphic_shift_boolean_scratch<Scalar>(
        lwe_in_size: LweSize,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        fft: FftView<'_>,
    ) -> Result<StackReq, SizeOverflow> {
        let align = CACHELINE_ALIGN;
        StackReq::try_new_aligned::<Scalar>(lwe_in_size.0, align)?
            .try_and(StackReq::try_new_aligned::<Scalar>(
                polynomial_size.0 * glwe_size.0,
                align,
            )?)?
            .try_and(
                programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<Scalar>(
                    glwe_size,
                    polynomial_size,
                    fft,
                )?,
            )
    }

    /// Homomorphic shift for LWE without padding bit
    ///
    /// Starts by shifting the message bit at bit #delta_log to the padding bit and then shifts it
    /// to the right by base_log * level.
    pub fn homomorphic_shift_boolean<Scalar: UnsignedTorus + CastInto<usize>>(
        fourier_bsk: FourierLweBootstrapKeyView<'_>,
        mut lwe_out: LweCiphertext<&mut [Scalar]>,
        lwe_in: LweCiphertext<&[Scalar]>,
        level_count_cbs: DecompositionLevel,
        base_log_cbs: DecompositionBaseLog,
        delta_log: DeltaLog,
        fft: FftView<'_>,
        stack: PodStack<'_>,
    ) {
        debug_assert!(lwe_out.ciphertext_modulus() == lwe_in.ciphertext_modulus());
        debug_assert!(
            lwe_in.ciphertext_modulus().is_native_modulus(),
            "This operation currently only supports native moduli"
        );

        let ciphertext_n_bits = Scalar::BITS;
        let lwe_in_size = lwe_in.lwe_size();
        let polynomial_size = fourier_bsk.polynomial_size();
        let ciphertext_moudulus = lwe_out.ciphertext_modulus();

        let (mut lwe_left_shift_buffer_data, stack) =
            stack.make_aligned_with(lwe_in_size.0, CACHELINE_ALIGN, |_| Scalar::ZERO);
        let mut lwe_left_shift_buffer = LweCiphertext::from_container(
            &mut *lwe_left_shift_buffer_data,
            lwe_in.ciphertext_modulus(),
        );
        // Shift message LSB on padding bit, at this point we expect to have messages with only 1
        // bit of information
        lwe_ciphertext_cleartext_mul(
            &mut lwe_left_shift_buffer,
            &lwe_in,
            Cleartext(Scalar::ONE << (ciphertext_n_bits - delta_log.0 - 1)),
        );

        // Add q/4 to center the error while computing a negacyclic LUT
        let shift_buffer_body = lwe_left_shift_buffer.get_mut_body();
        *shift_buffer_body.data =
            (*shift_buffer_body.data).wrapping_add(Scalar::ONE << (ciphertext_n_bits - 2));

        let (mut pbs_accumulator_data, stack) = stack.make_aligned_with(
            polynomial_size.0 * fourier_bsk.glwe_size().0,
            CACHELINE_ALIGN,
            |_| Scalar::ZERO,
        );
        let mut pbs_accumulator = GlweCiphertextMutView::from_container(
            &mut *pbs_accumulator_data,
            polynomial_size,
            ciphertext_moudulus,
        );

        // Fill lut (equivalent to trivial encryption as mask is 0s)
        // The LUT is filled with -alpha in each coefficient where
        // alpha = 2^{log(q) - 1 - base_log * level}
        pbs_accumulator
            .get_mut_body()
            .as_mut()
            .fill(Scalar::ZERO.wrapping_sub(
                Scalar::ONE << (ciphertext_n_bits - 1 - base_log_cbs.0 * level_count_cbs.0),
            ));

        // Applying a negacyclic LUT on a ciphertext with one bit of message in the MSB and no bit
        // of padding
        fourier_bsk.bootstrap(
            lwe_out.as_mut_view(),
            lwe_left_shift_buffer.as_view(),
            pbs_accumulator.as_view(),
            fft,
            stack,
        );

        // Add alpha where alpha = 2^{log(q) - 1 - base_log * level}
        // To end up with an encryption of 0 if the message bit was 0 and 1 in the other case
        let out_body = lwe_out.get_mut_body();
        *out_body.data = (*out_body.data).wrapping_add(
            Scalar::ONE << (ciphertext_n_bits - 1 - base_log_cbs.0 * level_count_cbs.0),
        );
    }

    pub fn cmux_tree_memory_optimized_scratch<Scalar>(
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        nb_layer: usize,
        fft: FftView<'_>,
    ) -> Result<StackReq, SizeOverflow> {
        let t_scratch = StackReq::try_new_aligned::<Scalar>(
            polynomial_size.0 * glwe_size.0 * nb_layer,
            CACHELINE_ALIGN,
        )?;

        StackReq::try_all_of([
            t_scratch,                             // t_0
            t_scratch,                             // t_1
            StackReq::try_new::<usize>(nb_layer)?, // t_fill
            t_scratch,                             // diff
            add_external_product_assign_mem_optimized_requirement::<Scalar>(
                glwe_size,
                polynomial_size,
                fft,
            )?,
        ])
    }

    /// Perform a tree of cmux in a way that limits the total allocated memory to avoid issues for
    /// bigger trees.
    pub fn cmux_tree_memory_optimized<Scalar: UnsignedTorus + CastInto<usize>>(
        mut output_glwe: GlweCiphertext<&mut [Scalar]>,
        lut_per_layer: PolynomialList<&[Scalar]>,
        ggsw_list: FourierGgswCiphertextListView<'_>,
        fft: FftView<'_>,
        stack: PodStack<'_>,
    ) {
        debug_assert!(lut_per_layer.polynomial_count().0 == 1 << ggsw_list.count());

        if ggsw_list.count() > 0 {
            let glwe_size = output_glwe.glwe_size();
            let ciphertext_modulus = output_glwe.ciphertext_modulus();
            let polynomial_size = ggsw_list.polynomial_size();
            let nb_layer = ggsw_list.count();

            debug_assert!(stack.can_hold(
                cmux_tree_memory_optimized_scratch::<Scalar>(
                    glwe_size,
                    polynomial_size,
                    nb_layer,
                    fft
                )
                .unwrap()
            ));

            // These are accumulator that will be used to propagate the result from layer to layer
            // At index 0 you have the lut that will be loaded, and then the result for each layer
            // gets computed at the next index, last layer result gets stored in
            // `result`. This allow to use memory space in C * nb_layer instead of C' *
            // 2 ^ nb_layer
            let (mut t_0_data, stack) = stack.make_aligned_with(
                polynomial_size.0 * glwe_size.0 * nb_layer,
                CACHELINE_ALIGN,
                |_| Scalar::ZERO,
            );
            let (mut t_1_data, stack) = stack.make_aligned_with(
                polynomial_size.0 * glwe_size.0 * nb_layer,
                CACHELINE_ALIGN,
                |_| Scalar::ZERO,
            );

            let mut t_0 = GlweCiphertextList::from_container(
                t_0_data.as_mut(),
                glwe_size,
                polynomial_size,
                ciphertext_modulus,
            );
            let mut t_1 = GlweCiphertextList::from_container(
                t_1_data.as_mut(),
                glwe_size,
                polynomial_size,
                ciphertext_modulus,
            );

            let (mut t_fill, mut stack) = stack.make_with(nb_layer, |_| 0_usize);

            let mut lut_polynomial_iter = lut_per_layer.iter();
            loop {
                let even = lut_polynomial_iter.next();
                let odd = lut_polynomial_iter.next();

                let (lut_2i, lut_2i_plus_1) = match (even, odd) {
                    (Some(even), Some(odd)) => (even, odd),
                    _ => break,
                };

                let mut t_iter = izip!(t_0.iter_mut(), t_1.iter_mut(),).enumerate();

                let (mut j_counter, (mut t0_j, mut t1_j)) = t_iter.next().unwrap();

                t0_j.get_mut_body()
                    .as_mut()
                    .copy_from_slice(lut_2i.as_ref());

                t1_j.get_mut_body()
                    .as_mut()
                    .copy_from_slice(lut_2i_plus_1.as_ref());

                t_fill[0] = 2;

                for (j, ggsw) in ggsw_list.into_ggsw_iter().rev().enumerate() {
                    if t_fill[j] == 2 {
                        let (diff_data, stack) = stack.rb_mut().collect_aligned(
                            CACHELINE_ALIGN,
                            izip!(t1_j.as_ref(), t0_j.as_ref()).map(|(&a, &b)| a.wrapping_sub(b)),
                        );
                        let diff = GlweCiphertext::from_container(
                            &*diff_data,
                            polynomial_size,
                            ciphertext_modulus,
                        );

                        if j != nb_layer - 1 {
                            let (j_counter_plus_1, (mut t_0_j_plus_1, mut t_1_j_plus_1)) =
                                t_iter.next().unwrap();

                            assert_eq!(j_counter, j);
                            assert_eq!(j_counter_plus_1, j + 1);

                            let mut output = if t_fill[j + 1] == 0 {
                                t_0_j_plus_1.as_mut_view()
                            } else {
                                t_1_j_plus_1.as_mut_view()
                            };

                            output.as_mut().copy_from_slice(t0_j.as_ref());
                            add_external_product_assign_mem_optimized(
                                &mut output,
                                &ggsw,
                                &diff,
                                fft,
                                stack,
                            );
                            t_fill[j + 1] += 1;
                            t_fill[j] = 0;

                            drop(diff_data);

                            (j_counter, t0_j, t1_j) =
                                (j_counter_plus_1, t_0_j_plus_1, t_1_j_plus_1);
                        } else {
                            let mut output = output_glwe.as_mut_view();
                            output.as_mut().copy_from_slice(t0_j.as_ref());
                            add_external_product_assign_mem_optimized(
                                &mut output,
                                &ggsw,
                                &diff,
                                fft,
                                stack,
                            );
                        }
                    } else {
                        break;
                    }
                }
            }
        } else {
            output_glwe.get_mut_mask().as_mut().fill(Scalar::ZERO);
            output_glwe
                .get_mut_body()
                .as_mut()
                .copy_from_slice(lut_per_layer.as_ref());
        }
    }

    pub fn circuit_bootstrap_boolean_vertical_packing_scratch<Scalar>(
        lwe_list_in_count: LweCiphertextCount,
        lwe_list_out_count: LweCiphertextCount,
        lwe_in_size: LweSize,
        big_lut_polynomial_count: PolynomialCount,
        bsk_output_lwe_size: LweSize,
        glwe_size: GlweSize,
        fpksk_output_polynomial_size: PolynomialSize,
        level_cbs: DecompositionLevelCount,
        fft: FftView<'_>,
    ) -> Result<StackReq, SizeOverflow> {
        // We deduce the number of luts in the vec_lut from the number of cipherxtexts in
        // lwe_list_out
        let number_of_luts = lwe_list_out_count.0;
        let small_lut_size = PolynomialCount(big_lut_polynomial_count.0 / number_of_luts);

        StackReq::try_all_of([
            StackReq::try_new_aligned::<c64>(
                lwe_list_in_count.0 * fpksk_output_polynomial_size.0 / 2
                    * glwe_size.0
                    * glwe_size.0
                    * level_cbs.0,
                CACHELINE_ALIGN,
            )?,
            StackReq::try_new_aligned::<Scalar>(
                fpksk_output_polynomial_size.0 * glwe_size.0 * glwe_size.0 * level_cbs.0,
                CACHELINE_ALIGN,
            )?,
            StackReq::try_any_of([
                circuit_bootstrap_boolean_scratch::<Scalar>(
                    lwe_in_size,
                    bsk_output_lwe_size,
                    glwe_size,
                    fpksk_output_polynomial_size,
                    fft,
                )?,
                convert_standard_ggsw_ciphertext_to_fourier_mem_optimized_requirement(fft)?,
                vertical_packing_scratch::<Scalar>(
                    glwe_size,
                    fpksk_output_polynomial_size,
                    small_lut_size,
                    lwe_list_in_count.0,
                    fft,
                )?,
            ])?,
        ])
    }

    /// Perform a circuit bootstrap followed by a vertical packing on ciphertexts encrypting boolean
    /// messages.
    ///
    /// The circuit bootstrapping uses the private functional packing key switch.
    ///
    /// This is supposed to be used only with boolean (1 bit of message) LWE ciphertexts.
    pub fn circuit_bootstrap_boolean_vertical_packing<Scalar: UnsignedTorus + CastInto<usize>>(
        big_lut_as_polynomial_list: PolynomialList<&[Scalar]>,
        fourier_bsk: FourierLweBootstrapKeyView<'_>,
        mut lwe_list_out: LweCiphertextList<&mut [Scalar]>,
        lwe_list_in: LweCiphertextList<&[Scalar]>,
        pfpksk_list: LwePrivateFunctionalPackingKeyswitchKeyList<&[Scalar]>,
        level_cbs: DecompositionLevelCount,
        base_log_cbs: DecompositionBaseLog,
        fft: FftView<'_>,
        stack: PodStack<'_>,
    ) {
        debug_assert!(stack.can_hold(
            circuit_bootstrap_boolean_vertical_packing_scratch::<Scalar>(
                lwe_list_in.lwe_ciphertext_count(),
                lwe_list_out.lwe_ciphertext_count(),
                lwe_list_in.lwe_size(),
                big_lut_as_polynomial_list.polynomial_count(),
                fourier_bsk.output_lwe_dimension().to_lwe_size(),
                fourier_bsk.glwe_size(),
                pfpksk_list.output_polynomial_size(),
                level_cbs,
                fft
            )
            .unwrap()
        ));
        debug_assert!(
            lwe_list_in.lwe_ciphertext_count().0 != 0,
            "Got empty `lwe_list_in`"
        );
        debug_assert!(
            lwe_list_out.lwe_size().to_lwe_dimension() == fourier_bsk.output_lwe_dimension(),
            "Output LWE ciphertext needs to have an LweDimension of {}, got {}",
            lwe_list_out.lwe_size().to_lwe_dimension().0,
            fourier_bsk.output_lwe_dimension().0
        );
        debug_assert!(lwe_list_out.ciphertext_modulus() == lwe_list_in.ciphertext_modulus());
        debug_assert!(lwe_list_in.ciphertext_modulus() == pfpksk_list.ciphertext_modulus());
        debug_assert!(
            pfpksk_list.ciphertext_modulus().is_native_modulus(),
            "This operation currently only supports native moduli"
        );

        let glwe_size = pfpksk_list.output_key_glwe_dimension().to_glwe_size();
        let (mut ggsw_list_data, stack) = stack.make_aligned_with(
            lwe_list_in.lwe_ciphertext_count().0 * pfpksk_list.output_polynomial_size().0 / 2
                * glwe_size.0
                * glwe_size.0
                * level_cbs.0,
            CACHELINE_ALIGN,
            |_| c64::default(),
        );
        let (mut ggsw_res_data, mut stack) = stack.make_aligned_with(
            pfpksk_list.output_polynomial_size().0 * glwe_size.0 * glwe_size.0 * level_cbs.0,
            CACHELINE_ALIGN,
            |_| Scalar::ZERO,
        );

        let mut ggsw_list = FourierGgswCiphertextListMutView::new(
            &mut ggsw_list_data,
            lwe_list_in.lwe_ciphertext_count().0,
            glwe_size,
            pfpksk_list.output_polynomial_size(),
            base_log_cbs,
            level_cbs,
        );

        let mut ggsw_res = GgswCiphertext::from_container(
            &mut *ggsw_res_data,
            glwe_size,
            pfpksk_list.output_polynomial_size(),
            base_log_cbs,
            pfpksk_list.ciphertext_modulus(),
        );

        for (lwe_in, mut ggsw) in
            izip!(lwe_list_in.iter(), ggsw_list.as_mut_view().into_ggsw_iter(),)
        {
            circuit_bootstrap_boolean(
                fourier_bsk,
                lwe_in,
                ggsw_res.as_mut_view(),
                DeltaLog(Scalar::BITS - 1),
                pfpksk_list.as_view(),
                fft,
                stack.rb_mut(),
            );

            convert_standard_ggsw_ciphertext_to_fourier_mem_optimized(
                &ggsw_res,
                &mut ggsw,
                fft,
                stack.rb_mut(),
            );
        }

        // We deduce the number of luts in the vec_lut from the number of cipherxtexts in
        // lwe_list_out
        let number_of_luts = lwe_list_out.lwe_ciphertext_count().0;

        let small_lut_size = big_lut_as_polynomial_list.polynomial_count().0 / number_of_luts;

        for (lut, lwe_out) in izip!(
            big_lut_as_polynomial_list.chunks_exact(small_lut_size),
            lwe_list_out.iter_mut(),
        ) {
            vertical_packing(lut, lwe_out, ggsw_list.as_view(), fft, stack.rb_mut());
        }
    }

    pub fn vertical_packing_scratch<Scalar>(
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        lut_polynomial_count: PolynomialCount,
        ggsw_list_count: usize,
        fft: FftView<'_>,
    ) -> Result<StackReq, SizeOverflow> {
        let bits = core::mem::size_of::<Scalar>() * 8;

        // Get the base 2 logarithm (rounded down) of the number of polynomials in the list i.e. if
        // there is one polynomial, the number will be 0
        let log_lut_number: usize = bits - 1 - lut_polynomial_count.0.leading_zeros() as usize;

        let log_number_of_luts_for_cmux_tree = if log_lut_number > ggsw_list_count {
            // this means that we dont have enough GGSW to perform the CMux tree, we can only do the
            // Blind rotation
            0
        } else {
            log_lut_number
        };

        StackReq::try_all_of([
            // cmux_tree_lut_res
            StackReq::try_new_aligned::<Scalar>(polynomial_size.0 * glwe_size.0, CACHELINE_ALIGN)?,
            StackReq::try_any_of([
                blind_rotate_assign_scratch::<Scalar>(glwe_size, polynomial_size, fft)?,
                cmux_tree_memory_optimized_scratch::<Scalar>(
                    glwe_size,
                    polynomial_size,
                    log_number_of_luts_for_cmux_tree,
                    fft,
                )?,
            ])?,
        ])
    }

    // GGSW ciphertexts are stored from the msb (vec_ggsw[0]) to the lsb (vec_ggsw[last])
    pub fn vertical_packing<Scalar: UnsignedTorus + CastInto<usize>>(
        lut: PolynomialList<&[Scalar]>,
        mut lwe_out: LweCiphertext<&mut [Scalar]>,
        ggsw_list: FourierGgswCiphertextListView<'_>,
        fft: FftView<'_>,
        stack: PodStack<'_>,
    ) {
        debug_assert!(
            lwe_out.ciphertext_modulus().is_native_modulus(),
            "This operation currently only supports native moduli"
        );

        let polynomial_size = ggsw_list.polynomial_size();
        let glwe_size = ggsw_list.glwe_size();
        let glwe_dimension = glwe_size.to_glwe_dimension();
        let ciphertext_modulus = lwe_out.ciphertext_modulus();

        debug_assert!(
            lwe_out.lwe_size().to_lwe_dimension()
                == glwe_dimension.to_equivalent_lwe_dimension(polynomial_size),
            "Output LWE ciphertext needs to have an LweDimension of {:?}, got {:?}",
            glwe_dimension.to_equivalent_lwe_dimension(polynomial_size),
            lwe_out.lwe_size().to_lwe_dimension(),
        );

        // Get the base 2 logarithm (rounded down) of the number of polynomials in the list i.e. if
        // there is one polynomial, the number will be 0
        let log_lut_number: usize =
            Scalar::BITS - 1 - lut.polynomial_count().0.leading_zeros() as usize;

        let log_number_of_luts_for_cmux_tree = if log_lut_number > ggsw_list.count() {
            // this means that we dont have enough GGSW to perform the CMux tree, we can only do the
            // Blind rotation
            0
        } else {
            log_lut_number
        };

        // split the vec of GGSW in two, the msb GGSW is for the CMux tree and the lsb GGSW is for
        // the last blind rotation.
        let (cmux_ggsw, br_ggsw) = ggsw_list.split_at(log_number_of_luts_for_cmux_tree);

        let (mut cmux_tree_lut_res_data, mut stack) =
            stack.make_aligned_with(polynomial_size.0 * glwe_size.0, CACHELINE_ALIGN, |_| {
                Scalar::ZERO
            });
        let mut cmux_tree_lut_res = GlweCiphertext::from_container(
            &mut *cmux_tree_lut_res_data,
            polynomial_size,
            ciphertext_modulus,
        );

        cmux_tree_memory_optimized(
            cmux_tree_lut_res.as_mut_view(),
            lut,
            cmux_ggsw,
            fft,
            stack.rb_mut(),
        );
        blind_rotate_assign(
            cmux_tree_lut_res.as_mut_view(),
            br_ggsw,
            fft,
            stack.rb_mut(),
        );

        // sample extract of the RLWE of the Vertical packing
        extract_lwe_sample_from_glwe_ciphertext(&cmux_tree_lut_res, &mut lwe_out, MonomialDegree(0))
    }

    pub fn blind_rotate_assign_scratch<Scalar>(
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        fft: FftView<'_>,
    ) -> Result<StackReq, SizeOverflow> {
        StackReq::try_all_of([
            StackReq::try_new_aligned::<Scalar>(polynomial_size.0 * glwe_size.0, CACHELINE_ALIGN)?,
            cmux_assign_mem_optimized_requirement::<Scalar>(glwe_size, polynomial_size, fft)?,
        ])
    }

    pub fn blind_rotate_assign<Scalar: UnsignedTorus + CastInto<usize>>(
        mut lut: GlweCiphertext<&mut [Scalar]>,
        ggsw_list: FourierGgswCiphertextListView<'_>,
        fft: FftView<'_>,
        mut stack: PodStack<'_>,
    ) {
        let mut monomial_degree = MonomialDegree(1);

        for ggsw in ggsw_list.into_ggsw_iter().rev() {
            let mut ct_0 = lut.as_mut_view();
            let (mut ct1_data, stack) = stack
                .rb_mut()
                .collect_aligned(CACHELINE_ALIGN, ct_0.as_ref().iter().copied());
            let mut ct_1 = GlweCiphertext::from_container(
                &mut *ct1_data,
                ct_0.polynomial_size(),
                ct_0.ciphertext_modulus(),
            );
            ct_1.as_mut_polynomial_list()
                .iter_mut()
                .for_each(|mut poly| {
                    polynomial_wrapping_monic_monomial_div_assign(&mut poly, monomial_degree)
                });
            monomial_degree.0 <<= 1;
            cmux_assign_mem_optimized(&mut ct_0, &mut ct_1, &ggsw, fft, stack);
        }
    }
}
use implementation::*;

/// Allocate a new [`list of LWE private functional packing keyswitch
/// keys`](`LwePrivateFunctionalPackingKeyswitchKeyList`) and fill it with actual keys required to
/// perform a circuit bootstrap.
///
/// Consider using [`par_allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list`] for better
/// key generation times.
pub fn allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list<
    Scalar,
    LweKeyCont,
    GlweKeyCont,
    Gen,
>(
    input_lwe_secret_key: &LweSecretKey<LweKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<GlweKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_parameters: impl DispersionParameter,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LwePrivateFunctionalPackingKeyswitchKeyListOwned<Scalar>
where
    Scalar: UnsignedTorus,
    LweKeyCont: Container<Element = Scalar>,
    GlweKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        ciphertext_modulus.is_native_modulus(),
        "This operation currently only supports native moduli, got modulus {:?}",
        ciphertext_modulus
    );

    let mut cbs_pfpksk_list = LwePrivateFunctionalPackingKeyswitchKeyListOwned::new(
        Scalar::ZERO,
        decomp_base_log,
        decomp_level_count,
        input_lwe_secret_key.lwe_dimension(),
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output_glwe_secret_key.polynomial_size(),
        FunctionalPackingKeyswitchKeyCount(
            output_glwe_secret_key.glwe_dimension().to_glwe_size().0,
        ),
        ciphertext_modulus,
    );

    generate_circuit_bootstrap_lwe_pfpksk_list(
        &mut cbs_pfpksk_list,
        input_lwe_secret_key,
        output_glwe_secret_key,
        noise_parameters,
        generator,
    );

    cbs_pfpksk_list
}

/// Fill a [`list of LWE private functional packing keyswitch
/// keys`](`LwePrivateFunctionalPackingKeyswitchKeyList`) with actual keys required to perform a
/// circuit bootstrap.
///
/// Consider using [`par_generate_circuit_bootstrap_lwe_pfpksk_list`] for better key generation
/// times.
pub fn generate_circuit_bootstrap_lwe_pfpksk_list<
    Scalar,
    OutputCont,
    LweKeyCont,
    GlweKeyCont,
    Gen,
>(
    output_cbs_pfpksk_list: &mut LwePrivateFunctionalPackingKeyswitchKeyList<OutputCont>,
    input_lwe_secret_key: &LweSecretKey<LweKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<GlweKeyCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    OutputCont: ContainerMut<Element = Scalar>,
    LweKeyCont: Container<Element = Scalar>,
    GlweKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output_cbs_pfpksk_list.lwe_pfpksk_count().0
            == output_glwe_secret_key.glwe_dimension().to_glwe_size().0,
        "Current list has {} pfpksk, need to have {} \
        (output_glwe_key.glwe_dimension().to_glwe_size())",
        output_cbs_pfpksk_list.lwe_pfpksk_count().0,
        output_glwe_secret_key.glwe_dimension().to_glwe_size().0
    );

    assert!(
        output_cbs_pfpksk_list
            .ciphertext_modulus()
            .is_native_modulus(),
        "This operation currently only supports native moduli, got modulus {:?}",
        output_cbs_pfpksk_list.ciphertext_modulus()
    );

    let decomp_level_count = output_cbs_pfpksk_list.decomposition_level_count();

    let gen_iter = generator
        .fork_cbs_pfpksk_to_pfpksk::<Scalar>(
            decomp_level_count,
            output_glwe_secret_key.glwe_dimension().to_glwe_size(),
            output_glwe_secret_key.polynomial_size(),
            input_lwe_secret_key.lwe_dimension().to_lwe_size(),
            output_cbs_pfpksk_list.lwe_pfpksk_count(),
        )
        .unwrap();

    let mut last_polynomial_as_list = PolynomialListOwned::new(
        Scalar::ZERO,
        output_glwe_secret_key.polynomial_size(),
        PolynomialCount(1),
    );
    // We apply the x -> -x function so instead of putting one in the first coeff of the
    // polynomial, we put Scalar::MAX == - Scalar::One so that we can use a single function in
    // the loop avoiding branching
    last_polynomial_as_list.get_mut(0)[0] = Scalar::MAX;

    for ((mut lwe_pfpksk, polynomial_to_encrypt), mut loop_generator) in output_cbs_pfpksk_list
        .iter_mut()
        .zip(
            output_glwe_secret_key
                .as_polynomial_list()
                .iter()
                .chain(last_polynomial_as_list.iter()),
        )
        .zip(gen_iter)
    {
        generate_lwe_private_functional_packing_keyswitch_key(
            input_lwe_secret_key,
            output_glwe_secret_key,
            &mut lwe_pfpksk,
            noise_parameters,
            &mut loop_generator,
            |x| Scalar::ZERO.wrapping_sub(x),
            &polynomial_to_encrypt,
        );
    }
}

/// Parallel variant of [`allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list`], it is
/// recommended to use this function for better key generation times as the generated keys can be
/// quite large.
///
/// See [`circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized`] for usage.
pub fn par_allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list<
    Scalar,
    LweKeyCont,
    GlweKeyCont,
    Gen,
>(
    input_lwe_secret_key: &LweSecretKey<LweKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<GlweKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_parameters: impl DispersionParameter + Sync,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LwePrivateFunctionalPackingKeyswitchKeyListOwned<Scalar>
where
    Scalar: UnsignedTorus + Sync + Send,
    LweKeyCont: Container<Element = Scalar> + Sync,
    GlweKeyCont: Container<Element = Scalar> + Sync,
    Gen: ParallelByteRandomGenerator,
{
    assert!(
        ciphertext_modulus.is_native_modulus(),
        "This operation currently only supports native moduli, got modulus {:?}",
        ciphertext_modulus
    );

    let mut cbs_pfpksk_list = LwePrivateFunctionalPackingKeyswitchKeyListOwned::new(
        Scalar::ZERO,
        decomp_base_log,
        decomp_level_count,
        input_lwe_secret_key.lwe_dimension(),
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output_glwe_secret_key.polynomial_size(),
        FunctionalPackingKeyswitchKeyCount(
            output_glwe_secret_key.glwe_dimension().to_glwe_size().0,
        ),
        ciphertext_modulus,
    );

    par_generate_circuit_bootstrap_lwe_pfpksk_list(
        &mut cbs_pfpksk_list,
        input_lwe_secret_key,
        output_glwe_secret_key,
        noise_parameters,
        generator,
    );

    cbs_pfpksk_list
}

/// Parallel variant of [`generate_circuit_bootstrap_lwe_pfpksk_list`], it is recommended to use
/// this function for better key generation times as the generated keys can be quite large.
pub fn par_generate_circuit_bootstrap_lwe_pfpksk_list<
    Scalar,
    OutputCont,
    LweKeyCont,
    GlweKeyCont,
    Gen,
>(
    output_cbs_pfpksk_list: &mut LwePrivateFunctionalPackingKeyswitchKeyList<OutputCont>,
    input_lwe_secret_key: &LweSecretKey<LweKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<GlweKeyCont>,
    noise_parameters: impl DispersionParameter + Sync,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus + Sync + Send,
    OutputCont: ContainerMut<Element = Scalar>,
    LweKeyCont: Container<Element = Scalar> + Sync,
    GlweKeyCont: Container<Element = Scalar> + Sync,
    Gen: ParallelByteRandomGenerator,
{
    assert!(
        output_cbs_pfpksk_list.lwe_pfpksk_count().0
            == output_glwe_secret_key.glwe_dimension().to_glwe_size().0,
        "Current list has {} pfpksk, need to have {} \
        (output_glwe_key.glwe_dimension().to_glwe_size())",
        output_cbs_pfpksk_list.lwe_pfpksk_count().0,
        output_glwe_secret_key.glwe_dimension().to_glwe_size().0
    );

    assert!(
        output_cbs_pfpksk_list
            .ciphertext_modulus()
            .is_native_modulus(),
        "This operation currently only supports native moduli, got modulus {:?}",
        output_cbs_pfpksk_list.ciphertext_modulus()
    );

    let decomp_level_count = output_cbs_pfpksk_list.decomposition_level_count();

    let gen_iter = generator
        .par_fork_cbs_pfpksk_to_pfpksk::<Scalar>(
            decomp_level_count,
            output_glwe_secret_key.glwe_dimension().to_glwe_size(),
            output_glwe_secret_key.polynomial_size(),
            input_lwe_secret_key.lwe_dimension().to_lwe_size(),
            output_cbs_pfpksk_list.lwe_pfpksk_count(),
        )
        .unwrap();

    let mut last_polynomial_as_list = PolynomialListOwned::new(
        Scalar::ZERO,
        output_glwe_secret_key.polynomial_size(),
        PolynomialCount(1),
    );
    // We apply the x -> -x function so instead of putting one in the first coeff of the
    // polynomial, we put Scalar::MAX == - Scalar::One so that we can use a single function in
    // the loop avoiding branching
    last_polynomial_as_list.get_mut(0)[0] = Scalar::MAX;

    output_cbs_pfpksk_list
        .par_iter_mut()
        .zip(
            output_glwe_secret_key
                .as_polynomial_list()
                .par_iter()
                .chain(last_polynomial_as_list.par_iter()),
        )
        .zip(gen_iter)
        .for_each(
            |((mut lwe_pfpksk, polynomial_to_encrypt), mut loop_generator)| {
                par_generate_lwe_private_functional_packing_keyswitch_key(
                    input_lwe_secret_key,
                    output_glwe_secret_key,
                    &mut lwe_pfpksk,
                    noise_parameters,
                    &mut loop_generator,
                    |x| Scalar::ZERO.wrapping_sub(x),
                    &polynomial_to_encrypt,
                );
            },
        );
}

#[allow(clippy::too_many_arguments)]
/// Fill the `output` [`LWE ciphertext list`](`LweCiphertextList`) with the bit extraction of the
/// `input` [`LWE ciphertext`](`LweCiphertext`), extracting `number_of_bits_to_extract` bits
/// starting from the bit at index `delta_log` (0-indexed) included, and going towards the most
/// significant bits.
///
/// Output bits are ordered from the MSB to the LSB. Each one of them is output in a distinct [`LWE
/// ciphertext`](`LweCiphertext`), containing the encryption of the bit scaled by q/2 (i.e., the
/// most significant bit in the plaintext representation).
///
/// The caller must provide a properly configured [`FftView`] object and a `PodStack` used as a
/// memory buffer having a capacity at least as large as the result of
/// [`extract_bits_from_lwe_ciphertext_mem_optimized_requirement`].
///
/// See [`circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized`] for usage.
///
/// # Formal Definition
///
/// This function takes as input an [`LWE ciphertext`](`LweCiphertext`)
/// $$\mathsf{ct\} = \mathsf{LWE}^n\_{\vec{s}}( \mathsf{m}) \subseteq \mathbb{Z}\_q^{(n+1)}$$
/// which encrypts some message `m`. We extract bits $m\_i$ of this message into individual LWE
/// ciphertexts. Each of these ciphertexts contains an encryption of $m\_i \cdot q/2$, i.e.
/// $$\mathsf{ct\_i} = \mathsf{LWE}^n\_{\vec{s}}( \mathsf{m\_i} \cdot q/2 )$$.
pub fn extract_bits_from_lwe_ciphertext_mem_optimized<
    Scalar,
    InputCont,
    OutputCont,
    BskCont,
    KSKCont,
>(
    lwe_in: &LweCiphertext<InputCont>,
    lwe_list_out: &mut LweCiphertextList<OutputCont>,
    fourier_bsk: &FourierLweBootstrapKey<BskCont>,
    ksk: &LweKeyswitchKey<KSKCont>,
    delta_log: DeltaLog,
    number_of_bits_to_extract: ExtractedBitsCount,
    fft: FftView<'_>,
    stack: PodStack<'_>,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    BskCont: Container<Element = c64>,
    KSKCont: Container<Element = Scalar>,
{
    assert_eq!(
        lwe_list_out.ciphertext_modulus(),
        lwe_in.ciphertext_modulus()
    );
    assert_eq!(lwe_in.ciphertext_modulus(), ksk.ciphertext_modulus());
    assert!(
        ksk.ciphertext_modulus().is_native_modulus(),
        "This operation only supports native moduli"
    );

    extract_bits(
        lwe_list_out.as_mut_view(),
        lwe_in.as_view(),
        ksk.as_view(),
        fourier_bsk.as_view(),
        delta_log,
        number_of_bits_to_extract,
        fft,
        stack,
    )
}

/// Return the required memory for [`extract_bits_from_lwe_ciphertext_mem_optimized`].
pub fn extract_bits_from_lwe_ciphertext_mem_optimized_requirement<Scalar>(
    lwe_dimension: LweDimension,
    ksk_output_key_lwe_dimension: LweDimension,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    extract_bits_scratch::<Scalar>(
        lwe_dimension,
        ksk_output_key_lwe_dimension,
        glwe_size,
        polynomial_size,
        fft,
    )
}

#[allow(clippy::too_many_arguments)]
/// Perform a boolean circuit bootstrapping followed by a vertical packing to evaluate a look-up
/// table on an [`LWE ciphertext list`](`LweCiphertextList`). The term "boolean" refers to the fact
/// the input ciphertexts encrypt a single bit of message.
///
/// The provided "big" `luts` look-up table is expected to be divisible into the same number of
/// chunks of polynomials as there are ciphertexts in the `output` [`LWE Ciphertext
/// list`](`LweCiphertextList`). Each chunk of polynomials is used as a look-up table to evaluate
/// during the vertical packing operation to fill an output ciphertext.
///
/// Note that there should be enough polynomials provided in each chunk to perform the vertical
/// packing given the number of boolean input ciphertexts. The number of boolean input ciphertexts
/// is in fact a number of bits. For this example let's say we have 16 input ciphertexts
/// representing 16 bits and want to output 4 ciphertexts. The "big" `luts` will need to be
/// divisible into 4 chunks of equal size. If the polynomial size used is $1024 = 2^{10}$ then each
/// chunk must contain $2^6 = 64$ polynomials ($2^6 * 2^{10} = 2^{16}$) to match the amount of
/// values representable by the 16 input ciphertexts each encrypting a bit. The "big" `luts` then
/// has a layout looking as follows:
///
/// ```text
/// small lut for 1st output ciphertext|...|small lut for 4th output ciphertext
/// |[polynomial 1] ... [polynomial 64]|...|[polynomial 1] ... [polynomial 64]|
/// ```
///
/// The polynomials in the above representation are not necessarily the same, this is just for
/// illustration purposes.
///
/// It is also possible in the above example to have a single polynomial of size $2^{16} = 65 536$
/// for each chunk if the polynomial size is supported for computation. Chunks containing a single
/// polynomial of size $2^{10} = 1024$ would work for example for 10 input ciphertexts as that
/// polynomial size is supported for computations. The "big" `luts` layout would then look as
/// follows for that 10 bits example (still with 4 output ciphertexts):
///
/// ```text
/// small lut for 1st output ciphertext|...|small lut for 4th output ciphertext
/// |[          polynomial 1          ]|...|[          polynomial 1          ]|
/// ```
///
/// The caller must provide a properly configured [`FftView`] object and a `PodStack` used as a
/// memory buffer having a capacity at least as large as the result of
/// [`circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized_requirement`].
///
/// # Example
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// let polynomial_size = PolynomialSize(1024);
/// let glwe_dimension = GlweDimension(1);
/// let lwe_dimension = LweDimension(481);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// let var_small = Variance::from_variance(2f64.powf(-80.0));
/// let var_big = Variance::from_variance(2f64.powf(-70.0));
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_dimension,
///     polynomial_size,
///     &mut secret_generator,
/// );
/// let lwe_small_sk =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
/// let lwe_big_sk = glwe_sk.clone().into_lwe_secret_key();
///
/// let bsk_level_count = DecompositionLevelCount(9);
/// let bsk_base_log = DecompositionBaseLog(4);
///
/// let std_bsk: LweBootstrapKeyOwned<u64> = par_allocate_and_generate_new_lwe_bootstrap_key(
///     &lwe_small_sk,
///     &glwe_sk,
///     bsk_base_log,
///     bsk_level_count,
///     var_small,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// let mut fourier_bsk = FourierLweBootstrapKeyOwned::new(
///     std_bsk.input_lwe_dimension(),
///     std_bsk.glwe_size(),
///     std_bsk.polynomial_size(),
///     std_bsk.decomposition_base_log(),
///     std_bsk.decomposition_level_count(),
/// );
///
/// let ksk_level_count = DecompositionLevelCount(9);
/// let ksk_base_log = DecompositionBaseLog(1);
///
/// let ksk_big_to_small = allocate_and_generate_new_lwe_keyswitch_key(
///     &lwe_big_sk,
///     &lwe_small_sk,
///     ksk_base_log,
///     ksk_level_count,
///     var_big,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// let pfpksk_level_count = DecompositionLevelCount(9);
/// let pfpksk_base_log = DecompositionBaseLog(4);
///
/// let cbs_pfpksk = par_allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list(
///     &lwe_big_sk,
///     &glwe_sk,
///     pfpksk_base_log,
///     pfpksk_level_count,
///     var_small,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// // We will have a message with 10 bits of information
/// let message_bits = 10;
/// let bits_to_extract = ExtractedBitsCount(message_bits);
///
/// // Note that this particular table will not trigger the cmux tree from the vertical packing,
/// // adapt the LUT generation to your usage.
/// //  Here we apply a single look-up table as we output a single ciphertext.
/// let number_of_luts_and_output_vp_ciphertexts = LweCiphertextCount(1);
///
/// let cbs_level_count = DecompositionLevelCount(4);
/// let cbs_base_log = DecompositionBaseLog(6);
///
/// let fft = Fft::new(polynomial_size);
/// let fft = fft.as_view();
/// let mut buffers = ComputationBuffers::new();
///
/// let buffer_size_req =
///     convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized_requirement(fft)
///         .unwrap()
///         .unaligned_bytes_required();
/// let buffer_size_req = buffer_size_req.max(
///     extract_bits_from_lwe_ciphertext_mem_optimized_requirement::<u64>(
///         lwe_dimension,
///         ksk_big_to_small.output_key_lwe_dimension(),
///         glwe_dimension.to_glwe_size(),
///         polynomial_size,
///         fft,
///     )
///     .unwrap()
///     .unaligned_bytes_required(),
/// );
/// let buffer_size_req = buffer_size_req.max(
///     circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized_requirement::<
///         u64,
///     >(
///         LweCiphertextCount(bits_to_extract.0),
///         number_of_luts_and_output_vp_ciphertexts,
///         lwe_dimension.to_lwe_size(),
///         PolynomialCount(1),
///         fourier_bsk.output_lwe_dimension().to_lwe_size(),
///         fourier_bsk.glwe_size(),
///         polynomial_size,
///         cbs_level_count,
///         fft,
///     )
///     .unwrap()
///     .unaligned_bytes_required(),
/// );
///
/// // We resize our buffers once
/// buffers.resize(buffer_size_req);
///
/// convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized(
///     &std_bsk,
///     &mut fourier_bsk,
///     fft,
///     buffers.stack(),
/// );
///
/// // The value we encrypt is 42, we will extract the bits of this value and apply the
/// // circuit bootstrapping followed by the vertical packing on the extracted bits.
/// let cleartext = 42;
/// let delta_log_msg = DeltaLog(64 - message_bits);
///
/// let encoded_message = Plaintext(cleartext << delta_log_msg.0);
/// let lwe_in = allocate_and_encrypt_new_lwe_ciphertext(
///     &lwe_big_sk,
///     encoded_message,
///     var_big,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// // Bit extraction output, use the zero_encrypt engine to allocate a ciphertext vector
/// let mut bit_extraction_output = LweCiphertextList::new(
///     0u64,
///     lwe_dimension.to_lwe_size(),
///     LweCiphertextCount(bits_to_extract.0),
///     ciphertext_modulus,
/// );
///
/// extract_bits_from_lwe_ciphertext_mem_optimized(
///     &lwe_in,
///     &mut bit_extraction_output,
///     &fourier_bsk,
///     &ksk_big_to_small,
///     delta_log_msg,
///     bits_to_extract,
///     fft,
///     buffers.stack(),
/// );
///
/// // Though the delta log here is the same as the message delta log, in the general case they
/// // are different, so we create two DeltaLog parameters
/// let delta_log_lut = DeltaLog(64 - message_bits);
///
/// // Create a look-up table we want to apply during vertical packing, here just the identity
/// // with the proper encoding.
/// // Note that this particular table will not trigger the cmux tree from the vertical packing,
/// // adapt the LUT generation to your usage.
/// // Here we apply a single look-up table as we output a single ciphertext.
/// let lut_size = 1 << bits_to_extract.0;
/// let mut lut: Vec<u64> = Vec::with_capacity(lut_size);
///
/// for i in 0..lut_size {
///     lut.push((i as u64 % (1 << message_bits)) << delta_log_lut.0);
/// }
///
/// let lut_as_polynomial_list = PolynomialList::from_container(lut, polynomial_size);
///
/// let mut output_cbs_vp = LweCiphertextList::new(
///     0u64,
///     lwe_big_sk.lwe_dimension().to_lwe_size(),
///     number_of_luts_and_output_vp_ciphertexts,
///     ciphertext_modulus,
/// );
///
/// circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized(
///     &bit_extraction_output,
///     &mut output_cbs_vp,
///     &lut_as_polynomial_list,
///     &fourier_bsk,
///     &cbs_pfpksk,
///     cbs_base_log,
///     cbs_level_count,
///     fft,
///     buffers.stack(),
/// );
///
/// // We have a single output ct
/// let result_ct = output_cbs_vp.iter().next().unwrap();
///
/// let decomposer = SignedDecomposer::new(
///     DecompositionBaseLog(bits_to_extract.0),
///     DecompositionLevelCount(1),
/// );
///
/// // decrypt result
/// let decrypted_message = decrypt_lwe_ciphertext(&lwe_big_sk, &result_ct);
/// let decoded_message = decomposer.closest_representable(decrypted_message.0) >> delta_log_lut.0;
///
/// // print information if the result is wrong
/// assert_eq!(
///     decoded_message, cleartext,
///     "decoded_message ({decoded_message:?}) != cleartext ({cleartext:?})\n\
/// decrypted_message: {decrypted_message:?}, decoded_message: {decoded_message:?}",
/// );
/// ```
pub fn circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized<
    Scalar,
    InputCont,
    OutputCont,
    LutCont,
    BskCont,
    PFPKSKCont,
>(
    lwe_list_in: &LweCiphertextList<InputCont>,
    lwe_list_out: &mut LweCiphertextList<OutputCont>,
    big_lut_as_polynomial_list: &PolynomialList<LutCont>,
    fourier_bsk: &FourierLweBootstrapKey<BskCont>,
    pfpksk_list: &LwePrivateFunctionalPackingKeyswitchKeyList<PFPKSKCont>,
    base_log_cbs: DecompositionBaseLog,
    level_cbs: DecompositionLevelCount,
    fft: FftView<'_>,
    stack: PodStack<'_>,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    LutCont: Container<Element = Scalar>,
    BskCont: Container<Element = c64>,
    PFPKSKCont: Container<Element = Scalar>,
{
    assert_eq!(
        lwe_list_out.ciphertext_modulus(),
        lwe_list_in.ciphertext_modulus()
    );
    assert_eq!(
        lwe_list_in.ciphertext_modulus(),
        pfpksk_list.ciphertext_modulus()
    );
    assert!(
        pfpksk_list.ciphertext_modulus().is_native_modulus(),
        "This operation currently only supports native moduli"
    );

    circuit_bootstrap_boolean_vertical_packing(
        big_lut_as_polynomial_list.as_view(),
        fourier_bsk.as_view(),
        lwe_list_out.as_mut_view(),
        lwe_list_in.as_view(),
        pfpksk_list.as_view(),
        level_cbs,
        base_log_cbs,
        fft,
        stack,
    )
}

#[allow(clippy::too_many_arguments)]
/// Return the required memory for
/// [`circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized`].
pub fn circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized_requirement<
    Scalar,
>(
    lwe_list_in_count: LweCiphertextCount,
    lwe_list_out_count: LweCiphertextCount,
    lwe_in_size: LweSize,
    big_lut_polynomial_count: PolynomialCount,
    bsk_output_lwe_size: LweSize,
    glwe_size: GlweSize,
    fpksk_output_polynomial_size: PolynomialSize,
    level_cbs: DecompositionLevelCount,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    circuit_bootstrap_boolean_vertical_packing_scratch::<Scalar>(
        lwe_list_in_count,
        lwe_list_out_count,
        lwe_in_size,
        big_lut_polynomial_count,
        bsk_output_lwe_size,
        glwe_size,
        fpksk_output_polynomial_size,
        level_cbs,
        fft,
    )
}

#[cfg(test)]
mod tests;
