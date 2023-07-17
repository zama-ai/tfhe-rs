use aligned_vec;
use aligned_vec::CACHELINE_ALIGN;
use concrete_fft::c64;
use dyn_stack::{PodStack, ReborrowMut};
use itertools::izip;
use tfhe::core_crypto::commons::parameters::PolynomialCount;
use tfhe::core_crypto::entities::*;
use tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::FourierGgswCiphertextListView;
use tfhe::core_crypto::fft_impl::fft64::crypto::wop_pbs::{
    circuit_bootstrap_boolean, circuit_bootstrap_boolean_scratch,
    cmux_tree_memory_optimized_scratch,
};
use tfhe::core_crypto::fft_impl::fft64::math::fft::FftView;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::gen_keys;
use tfhe::shortint::parameters::parameters_wopbs_message_carry::{
    WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS, WOPBS_PARAM_MESSAGE_3_CARRY_1_KS_PBS,
};
use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_3_CARRY_1_KS_PBS};
use tfhe::shortint::wopbs::WopbsKey;

// Function to be able to work with an already encrypted Lut stored in a GlweCiphertext (stepping
// through the Turing Machine) it's adapted from our cmux_tree_memory_optimized function
pub fn glwe_cmux_tree_memory_optimized<Scalar: UnsignedTorus + CastInto<usize>>(
    mut output_glwe: GlweCiphertext<&mut [Scalar]>,
    lut_per_layer: &GlweCiphertextList<Vec<Scalar>>,
    ggsw_list: FourierGgswCiphertextListView<'_>,
    fft: FftView<'_>,
    stack: PodStack<'_>,
) {
    debug_assert!(lut_per_layer.glwe_ciphertext_count().0 == 1 << ggsw_list.count());

    if ggsw_list.count() > 0 {
        let glwe_size = output_glwe.glwe_size();
        let ciphertext_modulus = output_glwe.ciphertext_modulus();
        let polynomial_size = ggsw_list.polynomial_size();
        let nb_layer = ggsw_list.count();

        debug_assert!(stack.can_hold(
            cmux_tree_memory_optimized_scratch::<Scalar>(glwe_size, polynomial_size, nb_layer, fft)
                .unwrap()
        ));

        // These are accumulator that will be used to propagate the result from layer to layer
        // At index 0 you have the lut that will be loaded, and then the result for each layer gets
        // computed at the next index, last layer result gets stored in `result`.
        // This allow to use memory space in C * nb_layer instead of C' * 2 ^ nb_layer
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

        let mut lut_glwe_iter = lut_per_layer.iter();
        loop {
            let even = lut_glwe_iter.next();
            let odd = lut_glwe_iter.next();

            let (lut_2i, lut_2i_plus_1) = match (even, odd) {
                (Some(even), Some(odd)) => (even, odd),
                _ => break,
            };

            let mut t_iter = izip!(t_0.iter_mut(), t_1.iter_mut(),).enumerate();

            let (mut j_counter, (mut t0_j, mut t1_j)) = t_iter.next().unwrap();

            t0_j.as_mut().copy_from_slice(lut_2i.as_ref());

            t1_j.as_mut().copy_from_slice(lut_2i_plus_1.as_ref());

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
                        tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::add_external_product_assign(output, ggsw, diff, fft, stack);
                        t_fill[j + 1] += 1;
                        t_fill[j] = 0;

                        drop(diff_data);

                        (j_counter, t0_j, t1_j) = (j_counter_plus_1, t_0_j_plus_1, t_1_j_plus_1);
                    } else {
                        let mut output = output_glwe.as_mut_view();
                        output.as_mut().copy_from_slice(t0_j.as_ref());
                        tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::add_external_product_assign(output, ggsw, diff, fft, stack);
                    }
                } else {
                    break;
                }
            }
        }
    } else {
        output_glwe.as_mut().copy_from_slice(lut_per_layer.as_ref());
    }
}

pub fn main() {
    // Select parameters with the same GlweDimension and PolynomialSize
    let mut wop_params = WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    // This may break some assumptions about error probability, but classic parameters for 2_2 and
    // 3_1 params were identical so we'll take a chance here for now. Also 2_2 params for wop look
    // to work ok but 3_1 and 3_0 did not seem to work properly.
    // LUT sizes will be 2048 instead of 1024 for now
    wop_params.message_modulus.0 = 1 << 3;
    wop_params.carry_modulus.0 = 1 << 1;
    let params = PARAM_MESSAGE_3_CARRY_1_KS_PBS;
    let (cks, sks) = gen_keys(params);

    let (wop_key, (associated_lwe_sk, associated_glwe_sk)) =
        WopbsKey::new_wopbs_key_return_secret_keys(&cks, &sks, &wop_params);

    let total_modulus = params.carry_modulus.0 * params.message_modulus.0;
    let num_bits = (total_modulus).ilog2();

    let delta = (1u64 << 63) / (total_modulus) as u64;
    // casting to usize is fine, ilog2 of u64 is guaranteed to be < 64
    let delta_log = DeltaLog(delta.ilog2() as usize);

    // 2u64 * delta
    // let mut lut_as_poly_list =
    //     PolynomialList::new(0u64, wop_params.polynomial_size, PolynomialCount(4));

    // lut_as_poly_list.get_mut(0).as_mut().fill(0 * delta);
    // lut_as_poly_list.get_mut(1).as_mut().fill(1 * delta);
    // lut_as_poly_list.get_mut(2).as_mut().fill(2 * delta);

    // let lut_as_poly_list = lut_as_poly_list;

    let mut initial_tape = GlweCiphertext::new(
        0u64,
        wop_params.glwe_dimension.to_glwe_size(),
        wop_params.polynomial_size,
        CiphertextModulus::new_native(),
    );

    for i in 0..initial_tape.polynomial_size().0 {
        initial_tape.get_mut_body().as_mut()[i] = (i as u64 % 8).wrapping_mul(delta);
    }

    // Lut shifted to the left
    let mut left_shift_tape = initial_tape.clone();
    initial_tape
        .as_polynomial_list()
        .iter()
        .zip(left_shift_tape.as_mut_polynomial_list().iter_mut())
        .for_each(|(src, mut dst)| {
            polynomial_algorithms::polynomial_wrapping_monic_monomial_div(
                &mut dst,
                &src,
                MonomialDegree(1),
            )
        });

    // Lut shifted to the left
    let mut right_shift_tape = initial_tape.clone();
    initial_tape
        .as_polynomial_list()
        .iter()
        .zip(right_shift_tape.as_mut_polynomial_list().iter_mut())
        .for_each(|(src, mut dst)| {
            polynomial_algorithms::polynomial_wrapping_monic_monomial_mul(
                &mut dst,
                &src,
                MonomialDegree(1),
            )
        });

    let mut tape_list = GlweCiphertextList::new(
        0u64,
        initial_tape.glwe_size(),
        initial_tape.polynomial_size(),
        GlweCiphertextCount(4),
        initial_tape.ciphertext_modulus(),
    );

    // Copy tapes to different slots of a GlweCiphertextList
    tape_list
        .get_mut(0)
        .as_mut()
        .copy_from_slice(initial_tape.as_ref());
    tape_list
        .get_mut(1)
        .as_mut()
        .copy_from_slice(left_shift_tape.as_ref());
    tape_list
        .get_mut(2)
        .as_mut()
        .copy_from_slice(right_shift_tape.as_ref());

    let fft = Fft::new(wop_params.polynomial_size);
    let fft = fft.as_view();

    let mut buffers = ComputationBuffers::new();
    buffers.resize(
        cmux_tree_memory_optimized_scratch::<u64>(
            wop_params.glwe_dimension.to_glwe_size(),
            wop_params.polynomial_size,
            // 2 bits to select LUTs
            2,
            fft,
        )
        .unwrap()
        .try_unaligned_bytes_required()
        .unwrap()
        .max(
            circuit_bootstrap_boolean_scratch::<u64>(
                wop_params.lwe_dimension.to_lwe_size(),
                associated_glwe_sk
                    .clone()
                    .into_lwe_secret_key()
                    .lwe_dimension()
                    .to_lwe_size(),
                wop_params.glwe_dimension.to_glwe_size(),
                wop_params.polynomial_size,
                fft,
            )
            .unwrap()
            .try_unaligned_bytes_required()
            .unwrap(),
        ),
    );

    let decomposer = SignedDecomposer::new(
        // Include the padding bit
        DecompositionBaseLog(num_bits as usize + 1),
        DecompositionLevelCount(1),
    );
    let bit_decomposer = SignedDecomposer::new(DecompositionBaseLog(1), DecompositionLevelCount(1));

    for msg in [0, 1, 2] {
        let ct = cks.encrypt(msg);

        // Go to wopbs params
        let ct = wop_key.keyswitch_to_wopbs_params(&sks, &ct);

        let sanity_decrypt =
            decrypt_lwe_ciphertext(&associated_glwe_sk.clone().into_lwe_secret_key(), &ct.ct);

        let sanity_decrypt = decomposer.closest_representable(sanity_decrypt.0) / delta;
        println!("sanity decrypt={sanity_decrypt}",);
        assert_eq!(sanity_decrypt, msg);

        // We will extract the 2 LSBs in our case
        let extracted_bits = wop_key.extract_bits(delta_log, &ct, 2);

        println!("msg_b: {msg:064b}");
        for ct_bit in extracted_bits.iter() {
            let sanity_decrypt = decrypt_lwe_ciphertext(&associated_lwe_sk, &ct_bit);
            println!(
                "bit: {}",
                bit_decomposer.closest_representable(sanity_decrypt.0) >> 63
            );
        }

        let mut ggsw_ciphertext_list = GgswCiphertextList::new(
            0u64,
            wop_params.glwe_dimension.to_glwe_size(),
            wop_params.polynomial_size,
            wop_params.cbs_base_log,
            wop_params.cbs_level,
            GgswCiphertextCount(extracted_bits.entity_count()),
            CiphertextModulus::new_native(),
        );

        let fourier_bsk = match &wop_key.wopbs_server_key.bootstrapping_key {
            tfhe::shortint::server_key::ShortintBootstrappingKey::Classic(fbsk) => fbsk,
            tfhe::shortint::server_key::ShortintBootstrappingKey::MultiBit { .. } => unreachable!(),
        };

        ggsw_ciphertext_list
            .iter_mut()
            .zip(extracted_bits.iter())
            .for_each(|(mut dst, src)| {
                circuit_bootstrap_boolean(
                    fourier_bsk.as_view(),
                    src.as_view(),
                    dst.as_mut_view(),
                    // The bit was put on the MSB by the bit extract
                    DeltaLog(63),
                    wop_key.cbs_pfpksk.as_view(),
                    fft,
                    buffers.stack(),
                )
            });

        let mut fourier_ggsw_list = FourierGgswCiphertextList::new(
            aligned_vec::avec!(
                c64::default();
                ggsw_ciphertext_list.entity_count()
                    * ggsw_ciphertext_list.polynomial_size().0
                    / 2
                    * ggsw_ciphertext_list.glwe_size().0
                    * ggsw_ciphertext_list.glwe_size().0
                    * ggsw_ciphertext_list.decomposition_level_count().0
            )
            .into_boxed_slice(),
            ggsw_ciphertext_list.entity_count(),
            ggsw_ciphertext_list.glwe_size(),
            ggsw_ciphertext_list.polynomial_size(),
            ggsw_ciphertext_list.decomposition_base_log(),
            ggsw_ciphertext_list.decomposition_level_count(),
        );

        fourier_ggsw_list
            .as_mut_view()
            .into_ggsw_iter()
            .zip(ggsw_ciphertext_list.iter())
            .for_each(|(mut dst, src)| {
                dst.as_mut_view()
                    .fill_with_forward_fourier(src.as_view(), fft, buffers.stack())
            });

        let mut glwe_ciphertext = GlweCiphertext::new(
            0u64,
            wop_params.glwe_dimension.to_glwe_size(),
            wop_params.polynomial_size,
            CiphertextModulus::new_native(),
        );

        // Glwe Selection
        glwe_cmux_tree_memory_optimized(
            glwe_ciphertext.as_mut_view(),
            &tape_list,
            fourier_ggsw_list.as_view(),
            fft,
            buffers.stack(),
        );

        let mut output_plaintext_list =
            PlaintextList::new(0u64, PlaintextCount(glwe_ciphertext.polynomial_size().0));

        decrypt_glwe_ciphertext(
            &associated_glwe_sk,
            &glwe_ciphertext,
            &mut output_plaintext_list,
        );

        output_plaintext_list
            .iter_mut()
            .for_each(|x| *x.0 = decomposer.closest_representable(*x.0) / delta);

        println!("msg={msg}\nOutput: {output_plaintext_list:?}");
    }
}
