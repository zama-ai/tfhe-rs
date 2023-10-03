use dyn_stack::{GlobalPodBuffer, PodStack, ReborrowMut};

use super::super::super::{fft128, fft128_u128};
use super::super::math::fft::{Fft128, Fft128View};
use crate::core_crypto::prelude::*;
use aligned_vec::CACHELINE_ALIGN;

fn sqr(x: f64) -> f64 {
    x * x
}

#[test]
fn test_split_external_product() {
    let small_lwe_dimension = LweDimension(742);
    let glwe_dimension = GlweDimension(1);
    let polynomial_size = PolynomialSize(2048);
    let pbs_base_log = DecompositionBaseLog(23);
    let pbs_level = DecompositionLevelCount(1);
    let glwe_modular_std_dev = StandardDev(sqr(0.00000000000000029403601535432533));
    let ciphertext_modulus = CiphertextModulus::<u128>::new_native();
    let ciphertext_modulus_split = CiphertextModulus::<u64>::new_native();

    let mut glwe = GlweCiphertext::new(
        0u128,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ciphertext_modulus,
    );

    for x in glwe.as_mut() {
        *x = rand::random();
    }

    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    let small_lwe_sk =
        LweSecretKey::generate_new_binary(small_lwe_dimension, &mut secret_generator);
    let glwe_sk =
        GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);

    let std_bootstrapping_key = par_allocate_and_generate_new_lwe_bootstrap_key(
        &small_lwe_sk,
        &glwe_sk,
        pbs_base_log,
        pbs_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let mut fourier_bsk = Fourier128LweBootstrapKey::new(
        std_bootstrapping_key.input_lwe_dimension(),
        std_bootstrapping_key.glwe_size(),
        std_bootstrapping_key.polynomial_size(),
        std_bootstrapping_key.decomposition_base_log(),
        std_bootstrapping_key.decomposition_level_count(),
    );

    let fft = Fft128::new(polynomial_size);
    let fft = fft.as_view();
    fourier_bsk.fill_with_forward_fourier(&std_bootstrapping_key, fft);
    let ggsw = fourier_bsk.as_view().into_ggsw_iter().next().unwrap();

    let mut glwe_lo = GlweCiphertext::new(
        0u64,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ciphertext_modulus_split,
    );
    let mut glwe_hi = GlweCiphertext::new(
        0u64,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ciphertext_modulus_split,
    );

    for ((lo, hi), val) in glwe_lo
        .as_mut()
        .iter_mut()
        .zip(glwe_hi.as_mut())
        .zip(glwe.as_ref())
    {
        *lo = *val as u64;
        *hi = (*val >> 64) as u64;
    }

    let mut out = GlweCiphertext::new(
        0u128,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ciphertext_modulus,
    );

    fft128::crypto::ggsw::add_external_product_assign(
        &mut out,
        &ggsw,
        &glwe,
        fft,
        PodStack::new(&mut GlobalPodBuffer::new(
            fft128::crypto::ggsw::add_external_product_assign_scratch::<u128>(
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                fft,
            )
            .unwrap(),
        )),
    );

    let mut out_lo = GlweCiphertext::new(
        0u64,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ciphertext_modulus_split,
    );
    let mut out_hi = GlweCiphertext::new(
        0u64,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ciphertext_modulus_split,
    );

    fft128_u128::crypto::ggsw::add_external_product_assign_split(
        &mut out_lo,
        &mut out_hi,
        &ggsw,
        &glwe_lo,
        &glwe_hi,
        fft,
        PodStack::new(&mut GlobalPodBuffer::new(
            fft128::crypto::ggsw::add_external_product_assign_scratch::<u128>(
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                fft,
            )
            .unwrap(),
        )),
    );

    for ((lo, hi), val) in out_lo
        .as_ref()
        .iter()
        .zip(out_hi.as_ref())
        .zip(out.as_ref())
    {
        assert_eq!(*val as u64, *lo);
        assert_eq!((*val >> 64) as u64, *hi);
    }
}

#[test]
fn test_split_pbs() {
    let small_lwe_dimension = LweDimension(742);
    let glwe_dimension = GlweDimension(1);
    let polynomial_size = PolynomialSize(2048);
    let pbs_base_log = DecompositionBaseLog(23);
    let pbs_level = DecompositionLevelCount(1);
    let glwe_modular_std_dev = StandardDev(sqr(0.00000000000000029403601535432533));
    let ciphertext_modulus = CiphertextModulus::<u128>::new_native();

    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    let small_lwe_sk =
        LweSecretKey::generate_new_binary(small_lwe_dimension, &mut secret_generator);
    let glwe_sk =
        GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);

    let std_bootstrapping_key = par_allocate_and_generate_new_lwe_bootstrap_key(
        &small_lwe_sk,
        &glwe_sk,
        pbs_base_log,
        pbs_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let mut fourier_bsk = Fourier128LweBootstrapKey::new(
        std_bootstrapping_key.input_lwe_dimension(),
        std_bootstrapping_key.glwe_size(),
        std_bootstrapping_key.polynomial_size(),
        std_bootstrapping_key.decomposition_base_log(),
        std_bootstrapping_key.decomposition_level_count(),
    );

    let fft = Fft128::new(polynomial_size);
    let fft = fft.as_view();
    fourier_bsk.fill_with_forward_fourier(&std_bootstrapping_key, fft);

    let mut lwe_in =
        LweCiphertext::new(0u128, small_lwe_dimension.to_lwe_size(), ciphertext_modulus);
    let mut accumulator = GlweCiphertext::new(
        0u128,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ciphertext_modulus,
    );

    for x in lwe_in.as_mut() {
        *x = rand::random();
    }
    for x in accumulator.as_mut() {
        *x = rand::random();
    }

    let mut mem = GlobalPodBuffer::new(
        fft128::crypto::bootstrap::bootstrap_scratch::<u128>(
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            fft,
        )
        .unwrap(),
    );
    let mut stack = PodStack::new(&mut mem);

    let mut lwe_out_non_split = LweCiphertext::new(
        0u128,
        glwe_dimension
            .to_equivalent_lwe_dimension(polynomial_size)
            .to_lwe_size(),
        ciphertext_modulus,
    );

    // Needed as the basic bootstrap function dispatches to the more efficient split version for
    // u128
    fn bootstrap_non_split<Scalar: UnsignedTorus + CastInto<usize>>(
        this: Fourier128LweBootstrapKey<&[f64]>,
        mut lwe_out: LweCiphertext<&mut [Scalar]>,
        lwe_in: LweCiphertext<&[Scalar]>,
        accumulator: GlweCiphertext<&[Scalar]>,
        fft: Fft128View<'_>,
        stack: PodStack<'_>,
    ) {
        let (mut local_accumulator_data, stack) =
            stack.collect_aligned(CACHELINE_ALIGN, accumulator.as_ref().iter().copied());
        let mut local_accumulator = GlweCiphertextMutView::from_container(
            &mut *local_accumulator_data,
            accumulator.polynomial_size(),
            accumulator.ciphertext_modulus(),
        );
        this.blind_rotate_assign(&mut local_accumulator.as_mut_view(), &lwe_in, fft, stack);
        extract_lwe_sample_from_glwe_ciphertext(
            &local_accumulator,
            &mut lwe_out,
            MonomialDegree(0),
        );
    }

    bootstrap_non_split(
        fourier_bsk.as_view(),
        lwe_out_non_split.as_mut_view(),
        lwe_in.as_view(),
        accumulator.as_view(),
        fft,
        stack.rb_mut(),
    );

    let mut lwe_out_split = LweCiphertext::new(
        0u128,
        glwe_dimension
            .to_equivalent_lwe_dimension(polynomial_size)
            .to_lwe_size(),
        ciphertext_modulus,
    );
    fourier_bsk.bootstrap_u128(
        &mut lwe_out_split,
        &lwe_in,
        &accumulator,
        fft,
        stack.rb_mut(),
    );

    assert_eq!(lwe_out_split, lwe_out_non_split);
}
