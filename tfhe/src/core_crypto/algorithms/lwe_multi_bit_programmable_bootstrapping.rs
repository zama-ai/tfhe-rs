use crate::core_crypto::algorithms::extract_lwe_sample_from_glwe_ciphertext;
use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::common::pbs_modulus_switch;
use crate::core_crypto::fft_impl::fft64::crypto::ggsw::{
    add_external_product_assign, add_external_product_assign_scratch, update_with_fmadd,
};
use crate::core_crypto::fft_impl::fft64::math::fft::{Fft, FftView};
use concrete_fft::c64;
use std::sync::{mpsc, Condvar, Mutex};
use std::thread;

pub fn prepare_multi_bit_ggsw_mem_optimized<
    Scalar,
    GgswBufferCont,
    GgswGroupCont,
    PolyCont,
    FourierPolyCont,
>(
    fourier_ggsw_buffer: &mut FourierGgswCiphertext<GgswBufferCont>,
    ggsw_group: &[FourierGgswCiphertext<GgswGroupCont>],
    lwe_mask_elements: &[Scalar],
    a_monomial: &mut Polynomial<PolyCont>,
    fourier_a_monomial: &mut FourierPolynomial<FourierPolyCont>,
    fft: FftView<'_>,
    buffers: &mut ComputationBuffers,
) where
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize>,
    GgswBufferCont: ContainerMut<Element = c64>,
    GgswGroupCont: Container<Element = c64>,
    PolyCont: ContainerMut<Element = Scalar>,
    FourierPolyCont: ContainerMut<Element = c64>,
{
    let mut ggsw_group_iter = ggsw_group.iter();

    // Keygen guarantees the first term is a constant term of the polynomial, no
    // polynomial multiplication required
    let ggsw_a_none = ggsw_group_iter.next().unwrap();

    fourier_ggsw_buffer
        .as_mut_view()
        .data()
        .copy_from_slice(ggsw_a_none.as_view().data());

    let multi_bit_fourier_ggsw = fourier_ggsw_buffer.as_mut_view().data();

    let polynomial_size = a_monomial.polynomial_size();

    for (ggsw_idx, fourier_ggsw) in ggsw_group_iter.enumerate() {
        // We already processed the first ggsw, advance the index by 1
        let ggsw_idx = ggsw_idx + 1;

        // Select the proper mask elements to build the monomial degree depending on
        // the order the GGSW were generated in, using the bits from mask_idx and
        // ggsw_idx as selector bits
        let mut monomial_degree = Scalar::ZERO;
        for (mask_idx, &mask_element) in lwe_mask_elements.iter().enumerate() {
            let mask_position = lwe_mask_elements.len() - (mask_idx + 1);
            let selection_bit: Scalar = Scalar::cast_from((ggsw_idx >> mask_position) & 1);
            monomial_degree =
                monomial_degree.wrapping_add(selection_bit.wrapping_mul(mask_element));
        }

        let switched_degree = pbs_modulus_switch(
            monomial_degree,
            polynomial_size,
            ModulusSwitchOffset(0),
            LutCountLog(0),
        );

        a_monomial.as_mut()[0] = Scalar::ONE;
        a_monomial.as_mut()[1..].fill(Scalar::ZERO);
        polynomial_wrapping_monic_monomial_mul_assign(a_monomial, MonomialDegree(switched_degree));

        fft.forward_as_integer(
            fourier_a_monomial.as_mut_view(),
            a_monomial.as_view(),
            buffers.stack(),
        );

        update_with_fmadd(
            multi_bit_fourier_ggsw,
            fourier_ggsw.as_view().data(),
            fourier_a_monomial.as_view().data,
            false,
            polynomial_size.to_fourier_polynomial_size().0,
        );
    }
}

/// Perform a blind rotation given an input [`LWE ciphertext`](`LweCiphertext`), modifying a look-up
/// table passed as a [`GLWE ciphertext`](`GlweCiphertext`) and an [`LWE bootstrap
/// key`](`LweMultiBitBootstrapKey`) in the fourier domain.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define the parameters for a 4 bits message able to hold the doubled 2 bits message
/// let small_lwe_dimension = LweDimension(742);
/// let glwe_dimension = GlweDimension(1);
/// let polynomial_size = PolynomialSize(2048);
/// let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
/// let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
/// let pbs_base_log = DecompositionBaseLog(23);
/// let pbs_level = DecompositionLevelCount(1);
/// let grouping_factor = LweBskGroupingFactor(2); // Group bits in pairs
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Request the best seeder possible, starting with hardware entropy sources and falling back to
/// // /dev/random on Unix systems if enabled via cargo features
/// let mut boxed_seeder = new_seeder();
/// // Get a mutable reference to the seeder as a trait object from the Box returned by new_seeder
/// let seeder = boxed_seeder.as_mut();
///
/// // Create a generator which uses a CSPRNG to generate secret keys
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// // Create a generator which uses two CSPRNGs to generate public masks and secret encryption
/// // noise
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
///
/// println!("Generating keys...");
///
/// // Generate an LweSecretKey with binary coefficients
/// let small_lwe_sk =
///     LweSecretKey::generate_new_binary(small_lwe_dimension, &mut secret_generator);
///
/// // Generate a GlweSecretKey with binary coefficients
/// let glwe_sk =
///     GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
///
/// // Create a copy of the GlweSecretKey re-interpreted as an LweSecretKey
/// let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();
///
/// let mut bsk = LweMultiBitBootstrapKey::new(
///     0u64,
///     glwe_dimension.to_glwe_size(),
///     polynomial_size,
///     pbs_base_log,
///     pbs_level,
///     small_lwe_dimension,
///     grouping_factor,
///     ciphertext_modulus,
/// );
///
/// par_generate_lwe_multi_bit_bootstrap_key(
///     &small_lwe_sk,
///     &glwe_sk,
///     &mut bsk,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// let mut multi_bit_bsk = FourierLweMultiBitBootstrapKey::new(
///     bsk.input_lwe_dimension(),
///     bsk.glwe_size(),
///     bsk.polynomial_size(),
///     bsk.decomposition_base_log(),
///     bsk.decomposition_level_count(),
///     bsk.grouping_factor(),
/// );
///
/// convert_standard_lwe_multi_bit_bootstrap_key_to_fourier(&bsk, &mut multi_bit_bsk);
///
/// // We don't need the standard bootstrapping key anymore
/// drop(bsk);
///
/// // Our 4 bits message space
/// let message_modulus = 1u64 << 4;
///
/// // Our input message
/// let input_message = 3u64;
///
/// // Delta used to encode 4 bits of message + a bit of padding on u64
/// let delta = (1_u64 << 63) / message_modulus;
///
/// // Apply our encoding
/// let plaintext = Plaintext(input_message * delta);
///
/// // Allocate a new LweCiphertext and encrypt our plaintext
/// let lwe_ciphertext_in: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
///     &small_lwe_sk,
///     plaintext,
///     lwe_modular_std_dev,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// // Now we will use a PBS to compute a multiplication by 2, it is NOT the recommended way of
/// // doing this operation in terms of performance as it's much more costly than a multiplication
/// // with a cleartext, however it resets the noise in a ciphertext to a nominal level and allows
/// // to evaluate arbitrary functions so depending on your use case it can be a better fit.
///
/// // Here we will define a helper function to generate an accumulator for a PBS
/// fn generate_accumulator<F>(
///     polynomial_size: PolynomialSize,
///     glwe_size: GlweSize,
///     message_modulus: usize,
///     ciphertext_modulus: CiphertextModulus<u64>,
///     delta: u64,
///     f: F,
/// ) -> GlweCiphertextOwned<u64>
/// where
///     F: Fn(u64) -> u64,
/// {
///     // N/(p/2) = size of each block, to correct noise from the input we introduce the notion of
///     // box, which manages redundancy to yield a denoised value for several noisy values around
///     // a true input value.
///     let box_size = polynomial_size.0 / message_modulus;
///
///     // Create the accumulator
///     let mut accumulator_u64 = vec![0_u64; polynomial_size.0];
///
///     // Fill each box with the encoded denoised value
///     for i in 0..message_modulus {
///         let index = i * box_size;
///         accumulator_u64[index..index + box_size]
///             .iter_mut()
///             .for_each(|a| *a = f(i as u64) * delta);
///     }
///
///     let half_box_size = box_size / 2;
///
///     // Negate the first half_box_size coefficients to manage negacyclicity and rotate
///     for a_i in accumulator_u64[0..half_box_size].iter_mut() {
///         *a_i = (*a_i).wrapping_neg();
///     }
///
///     // Rotate the accumulator
///     accumulator_u64.rotate_left(half_box_size);
///
///     let accumulator_plaintext = PlaintextList::from_container(accumulator_u64);
///
///     let accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
///         glwe_size,
///         &accumulator_plaintext,
///         ciphertext_modulus,
///     );
///
///     accumulator
/// }
///
/// // Generate the accumulator for our multiplication by 2 using a simple closure
/// let mut accumulator: GlweCiphertextOwned<u64> = generate_accumulator(
///     polynomial_size,
///     glwe_dimension.to_glwe_size(),
///     message_modulus as usize,
///     ciphertext_modulus,
///     delta,
///     |x: u64| 2 * x,
/// );
///
/// // Allocate the LweCiphertext to store the result of the PBS
/// let mut pbs_multiplication_ct = LweCiphertext::new(
///     0u64,
///     big_lwe_sk.lwe_dimension().to_lwe_size(),
///     ciphertext_modulus,
/// );
/// println!("Performing blind rotation...");
/// // Use 4 threads for the multi-bit blind rotation for example
/// multi_bit_blind_rotate_assign(
///     &lwe_ciphertext_in,
///     &mut accumulator,
///     &multi_bit_bsk,
///     ThreadCount(4),
/// );
/// println!("Performing sample extraction...");
/// extract_lwe_sample_from_glwe_ciphertext(
///     &accumulator,
///     &mut pbs_multiplication_ct,
///     MonomialDegree(0),
/// );
///
/// // Decrypt the PBS multiplication result
/// let pbs_multiplication_plaintext: Plaintext<u64> =
///     decrypt_lwe_ciphertext(&big_lwe_sk, &pbs_multiplication_ct);
///
/// // Create a SignedDecomposer to perform the rounding of the decrypted plaintext
/// // We pass a DecompositionBaseLog of 5 and a DecompositionLevelCount of 1 indicating we want to
/// // round the 5 MSB, 1 bit of padding plus our 4 bits of message
/// let signed_decomposer =
///     SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));
///
/// // Round and remove our encoding
/// let pbs_multiplication_result: u64 =
///     signed_decomposer.closest_representable(pbs_multiplication_plaintext.0) / delta;
///
/// println!("Checking result...");
/// assert_eq!(6, pbs_multiplication_result);
/// println!(
///     "Mulitplication via PBS result is correct! Expected 6, got {pbs_multiplication_result}"
/// );
/// ```
pub fn multi_bit_blind_rotate_assign<Scalar, InputCont, OutputCont, KeyCont>(
    input: &LweCiphertext<InputCont>,
    accumulator: &mut GlweCiphertext<OutputCont>,
    multi_bit_bsk: &FourierLweMultiBitBootstrapKey<KeyCont>,
    thread_count: ThreadCount,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Sync,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    KeyCont: Container<Element = c64> + Sync,
{
    assert_eq!(
        input.lwe_size().to_lwe_dimension(),
        multi_bit_bsk.input_lwe_dimension(),
        "Mimatched input LweDimension. LweCiphertext input LweDimension {:?}. \
        FourierLweMultiBitBootstrapKey input LweDimension {:?}.",
        input.lwe_size().to_lwe_dimension(),
        multi_bit_bsk.input_lwe_dimension(),
    );

    assert_eq!(
        accumulator.glwe_size(),
        multi_bit_bsk.glwe_size(),
        "Mimatched GlweSize. Accumulator GlweSize {:?}. \
        FourierLweMultiBitBootstrapKey GlweSize {:?}.",
        accumulator.glwe_size(),
        multi_bit_bsk.glwe_size(),
    );

    assert_eq!(
        accumulator.polynomial_size(),
        multi_bit_bsk.polynomial_size(),
        "Mimatched PolynomialSize. Accumulator PolynomialSize {:?}. \
        FourierLweMultiBitBootstrapKey PolynomialSize {:?}.",
        accumulator.polynomial_size(),
        multi_bit_bsk.polynomial_size(),
    );

    assert_eq!(
        input.ciphertext_modulus(),
        accumulator.ciphertext_modulus(),
        "Mismatched CiphertextModulus between input ({:?}) and accumulator ({:?})",
        input.ciphertext_modulus(),
        accumulator.ciphertext_modulus(),
    );

    assert!(
        thread_count.0 != 0,
        "Got thread_count == 0, this is not supported"
    );

    assert!(accumulator
        .ciphertext_modulus()
        .is_compatible_with_native_modulus());

    let (lwe_mask, lwe_body) = input.get_mask_and_body();

    // No way to chunk the result of ggsw_iter at the moment
    let ggsw_vec: Vec<_> = multi_bit_bsk.ggsw_iter().collect();
    let mut work_queue = Vec::with_capacity(multi_bit_bsk.multi_bit_input_lwe_dimension().0);

    let grouping_factor = multi_bit_bsk.grouping_factor();
    let ggsw_per_multi_bit_element = grouping_factor.ggsw_per_multi_bit_element();

    for (lwe_mask_elements, ggsw_group) in lwe_mask
        .as_ref()
        .chunks_exact(grouping_factor.0)
        .zip(ggsw_vec.chunks_exact(ggsw_per_multi_bit_element.0))
    {
        work_queue.push((lwe_mask_elements, ggsw_group));
    }

    assert!(work_queue.len() == lwe_mask.lwe_dimension().0 / grouping_factor.0);

    let work_queue = Mutex::new(work_queue);

    let lut_poly_size = accumulator.polynomial_size();
    let monomial_degree = pbs_modulus_switch(
        *lwe_body.data,
        lut_poly_size,
        ModulusSwitchOffset(0),
        LutCountLog(0),
    );

    // Modulus switching
    accumulator
        .as_mut_polynomial_list()
        .iter_mut()
        .for_each(|mut poly| {
            polynomial_wrapping_monic_monomial_div_assign(
                &mut poly,
                MonomialDegree(monomial_degree),
            )
        });

    let fourier_multi_bit_ggsw_buffers = (0..thread_count.0)
        .map(|_| {
            (
                Mutex::new(false),
                Condvar::new(),
                Mutex::new(FourierGgswCiphertext::new(
                    multi_bit_bsk.glwe_size(),
                    multi_bit_bsk.polynomial_size(),
                    multi_bit_bsk.decomposition_base_log(),
                    multi_bit_bsk.decomposition_level_count(),
                )),
            )
        })
        .collect::<Vec<_>>();

    let (tx, rx) = mpsc::channel::<usize>();

    let fft = Fft::new(multi_bit_bsk.polynomial_size());
    let fft = fft.as_view();
    thread::scope(|s| {
        let produce_multi_bit_fourier_ggsw = |thread_id: usize, tx: mpsc::Sender<usize>| {
            let mut buffers = ComputationBuffers::new();

            buffers.resize(fft.forward_scratch().unwrap().unaligned_bytes_required());

            let mut a_monomial = Polynomial::new(Scalar::ZERO, multi_bit_bsk.polynomial_size());
            let mut fourier_a_monomial = FourierPolynomial::new(multi_bit_bsk.polynomial_size());

            let work_queue = &work_queue;

            let dest_idx = thread_id;
            let (ready_for_consumer_lock, condvar, fourier_ggsw_buffer) =
                &fourier_multi_bit_ggsw_buffers[dest_idx];

            loop {
                let maybe_work = {
                    let mut queue_lock = work_queue.lock().unwrap();
                    queue_lock.pop()
                };

                let Some((lwe_mask_elements, ggsw_group)) = maybe_work else {break};
                let mut ready_for_consumer = ready_for_consumer_lock.lock().unwrap();

                // Wait while the buffer is not ready for processing and wait on the condvar
                // to get notified when we can start processing again
                while *ready_for_consumer {
                    ready_for_consumer = condvar.wait(ready_for_consumer).unwrap();
                }

                let mut fourier_ggsw_buffer = fourier_ggsw_buffer.lock().unwrap();

                prepare_multi_bit_ggsw_mem_optimized(
                    &mut fourier_ggsw_buffer,
                    ggsw_group,
                    lwe_mask_elements,
                    &mut a_monomial,
                    &mut fourier_a_monomial,
                    fft,
                    &mut buffers,
                );

                // Drop the lock before we wake other threads
                drop(fourier_ggsw_buffer);

                *ready_for_consumer = true;
                tx.send(dest_idx).unwrap();

                // Wake threads waiting on the condvar
                condvar.notify_all();
            }
        };

        let threads: Vec<_> = (0..thread_count.0)
            .map(|id| {
                let tx = tx.clone();
                s.spawn(move || produce_multi_bit_fourier_ggsw(id, tx))
            })
            .collect();

        // We initialize ct0 for the successive external products
        let ct0 = accumulator;
        let mut ct1 = GlweCiphertext::new(
            Scalar::ZERO,
            ct0.glwe_size(),
            ct0.polynomial_size(),
            ct0.ciphertext_modulus(),
        );
        let ct1 = &mut ct1;

        let mut buffers = ComputationBuffers::new();

        buffers.resize(
            add_external_product_assign_scratch::<Scalar>(
                multi_bit_bsk.glwe_size(),
                multi_bit_bsk.polynomial_size(),
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );

        let mut src_idx = 1usize;

        for _ in 0..multi_bit_bsk.multi_bit_input_lwe_dimension().0 {
            src_idx ^= 1;
            let idx = rx.recv().unwrap();
            let (ready_lock, condvar, multi_bit_fourier_ggsw) =
                &fourier_multi_bit_ggsw_buffers[idx];

            let (src_ct, mut dst_ct) = if src_idx == 0 {
                (ct0.as_view(), ct1.as_mut_view())
            } else {
                (ct1.as_view(), ct0.as_mut_view())
            };

            dst_ct.as_mut().fill(Scalar::ZERO);

            let mut ready = ready_lock.lock().unwrap();
            assert!(*ready);

            let multi_bit_fourier_ggsw = multi_bit_fourier_ggsw.lock().unwrap();
            add_external_product_assign(
                dst_ct,
                multi_bit_fourier_ggsw.as_view(),
                src_ct,
                fft,
                buffers.stack(),
            );
            drop(multi_bit_fourier_ggsw);

            *ready = false;
            // Wake a single producer thread sleeping on the condvar (only one will get to work
            // anyways)
            condvar.notify_one();
        }

        if src_idx == 0 {
            ct0.as_mut().copy_from_slice(ct1.as_ref());
        }

        let ciphertext_modulus = ct0.ciphertext_modulus();
        if !ciphertext_modulus.is_native_modulus() {
            // When we convert back from the fourier domain, integer values will contain up to 53
            // MSBs with information. In our representation of power of 2 moduli < native modulus we
            // fill the MSBs and leave the LSBs empty, this usage of the signed decomposer allows to
            // round while keeping the data in the MSBs
            let signed_decomposer = SignedDecomposer::new(
                DecompositionBaseLog(ciphertext_modulus.get_custom_modulus().ilog2() as usize),
                DecompositionLevelCount(1),
            );
            ct0.as_mut()
                .iter_mut()
                .for_each(|x| *x = signed_decomposer.closest_representable(*x));
        }

        threads.into_iter().for_each(|t| t.join().unwrap());
    });
}

/// Deterministic version of [`multi_bit_blind_rotate_assign`].
pub fn multi_bit_deterministic_blind_rotate_assign<Scalar, InputCont, OutputCont, KeyCont>(
    input: &LweCiphertext<InputCont>,
    accumulator: &mut GlweCiphertext<OutputCont>,
    multi_bit_bsk: &FourierLweMultiBitBootstrapKey<KeyCont>,
    thread_count: ThreadCount,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Sync,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    KeyCont: Container<Element = c64> + Sync,
{
    assert_eq!(
        input.lwe_size().to_lwe_dimension(),
        multi_bit_bsk.input_lwe_dimension(),
        "Mimatched input LweDimension. LweCiphertext input LweDimension {:?}. \
        FourierLweMultiBitBootstrapKey input LweDimension {:?}.",
        input.lwe_size().to_lwe_dimension(),
        multi_bit_bsk.input_lwe_dimension(),
    );

    assert_eq!(
        accumulator.glwe_size(),
        multi_bit_bsk.glwe_size(),
        "Mimatched GlweSize. Accumulator GlweSize {:?}. \
        FourierLweMultiBitBootstrapKey GlweSize {:?}.",
        accumulator.glwe_size(),
        multi_bit_bsk.glwe_size(),
    );

    assert_eq!(
        accumulator.polynomial_size(),
        multi_bit_bsk.polynomial_size(),
        "Mimatched PolynomialSize. Accumulator PolynomialSize {:?}. \
        FourierLweMultiBitBootstrapKey PolynomialSize {:?}.",
        accumulator.polynomial_size(),
        multi_bit_bsk.polynomial_size(),
    );

    assert_eq!(
        input.ciphertext_modulus(),
        accumulator.ciphertext_modulus(),
        "Mismatched CiphertextModulus between input ({:?}) and accumulator ({:?})",
        input.ciphertext_modulus(),
        accumulator.ciphertext_modulus(),
    );

    assert!(
        thread_count.0 != 0,
        "Got thread_count == 0, this is not supported"
    );

    let (lwe_mask, lwe_body) = input.get_mask_and_body();

    // No way to chunk the result of ggsw_iter at the moment
    let ggsw_vec: Vec<_> = multi_bit_bsk.ggsw_iter().collect();
    let mut work_queue = Vec::with_capacity(multi_bit_bsk.multi_bit_input_lwe_dimension().0);

    let grouping_factor = multi_bit_bsk.grouping_factor();
    let ggsw_per_multi_bit_element = grouping_factor.ggsw_per_multi_bit_element();

    for (lwe_mask_elements, ggsw_group) in lwe_mask
        .as_ref()
        .chunks_exact(grouping_factor.0)
        .zip(ggsw_vec.chunks_exact(ggsw_per_multi_bit_element.0))
    {
        work_queue.push((lwe_mask_elements, ggsw_group));
    }

    assert!(work_queue.len() == lwe_mask.lwe_dimension().0 / grouping_factor.0);

    let work_queue = &work_queue;

    let lut_poly_size = accumulator.polynomial_size();
    let monomial_degree = pbs_modulus_switch(
        *lwe_body.data,
        lut_poly_size,
        ModulusSwitchOffset(0),
        LutCountLog(0),
    );

    // Modulus switching
    accumulator
        .as_mut_polynomial_list()
        .iter_mut()
        .for_each(|mut poly| {
            polynomial_wrapping_monic_monomial_div_assign(
                &mut poly,
                MonomialDegree(monomial_degree),
            )
        });

    let fourier_multi_bit_ggsw_buffers = (0..thread_count.0)
        .map(|_| {
            (
                Mutex::new(false),
                Condvar::new(),
                Mutex::new(FourierGgswCiphertext::new(
                    multi_bit_bsk.glwe_size(),
                    multi_bit_bsk.polynomial_size(),
                    multi_bit_bsk.decomposition_base_log(),
                    multi_bit_bsk.decomposition_level_count(),
                )),
            )
        })
        .collect::<Vec<_>>();

    thread::scope(|s| {
        let produce_multi_bit_fourier_ggsw = |thread_id| {
            let mut buffers = ComputationBuffers::new();

            let fft = Fft::new(multi_bit_bsk.polynomial_size());
            let fft = fft.as_view();

            buffers.resize(fft.forward_scratch().unwrap().unaligned_bytes_required());

            let mut unit_polynomial =
                Polynomial::new(Scalar::ZERO, multi_bit_bsk.polynomial_size());
            unit_polynomial.as_mut()[0] = Scalar::ONE;
            let mut a_monomial = unit_polynomial.clone();
            let mut fourier_a_monomial = FourierPolynomial::new(multi_bit_bsk.polynomial_size());

            let dest_idx = thread_id;
            for (lwe_mask_elements, ggsw_group) in
                work_queue.iter().skip(thread_id).step_by(thread_count.0)
            {
                let (ready_for_consumer_lock, condvar, fourier_ggsw_buffer) =
                    &fourier_multi_bit_ggsw_buffers[dest_idx];

                let mut ready_for_consumer = ready_for_consumer_lock.lock().unwrap();

                // Wait while the buffer is not ready for processing and wait on the condvar to
                // get notified when we can start processing again
                while *ready_for_consumer {
                    ready_for_consumer = condvar.wait(ready_for_consumer).unwrap();
                }

                let mut fourier_ggsw_buffer = fourier_ggsw_buffer.lock().unwrap();

                let mut bunch_iter = ggsw_group.iter();

                // Keygen guarantees the first term is a constant term of the polynomial, no
                // polynomial multiplication required
                let ggsw_a_none = bunch_iter.next().unwrap();

                fourier_ggsw_buffer
                    .as_mut_view()
                    .data()
                    .copy_from_slice(ggsw_a_none.as_view().data());

                let multi_bit_fourier_ggsw = fourier_ggsw_buffer.as_mut_view().data();

                for (ggsw_idx, fourier_ggsw) in bunch_iter.enumerate() {
                    // We already processed the first ggsw, advance the index by 1
                    let ggsw_idx = ggsw_idx + 1;

                    let mut monomial_degree = Scalar::ZERO;
                    for (mask_idx, &mask_element) in lwe_mask_elements.iter().enumerate() {
                        let mask_position = lwe_mask_elements.len() - (mask_idx + 1);
                        let selection_bit: Scalar =
                            Scalar::cast_from((ggsw_idx >> mask_position) & 1);
                        monomial_degree =
                            monomial_degree.wrapping_add(selection_bit.wrapping_mul(mask_element));
                    }

                    let switched_degree = pbs_modulus_switch(
                        monomial_degree,
                        lut_poly_size,
                        ModulusSwitchOffset(0),
                        LutCountLog(0),
                    );

                    a_monomial
                        .as_mut()
                        .copy_from_slice(unit_polynomial.as_ref());
                    polynomial_wrapping_monic_monomial_mul_assign(
                        &mut a_monomial,
                        MonomialDegree(switched_degree),
                    );

                    fft.forward_as_integer(
                        fourier_a_monomial.as_mut_view(),
                        a_monomial.as_view(),
                        buffers.stack(),
                    );

                    update_with_fmadd(
                        multi_bit_fourier_ggsw,
                        fourier_ggsw.as_view().data(),
                        fourier_a_monomial.as_view().data,
                        false,
                        lut_poly_size.to_fourier_polynomial_size().0,
                    );
                }

                // Drop the lock before we wake other threads
                drop(fourier_ggsw_buffer);

                *ready_for_consumer = true;

                // Wake threads waiting on the condvar
                condvar.notify_all();
            }
        };

        let threads: Vec<_> = (0..thread_count.0)
            .map(|idx| s.spawn(move || produce_multi_bit_fourier_ggsw(idx)))
            .collect();

        // We initialize ct0 for the successive external products
        let ct0 = accumulator;
        let mut ct1 = GlweCiphertext::new(
            Scalar::ZERO,
            ct0.glwe_size(),
            ct0.polynomial_size(),
            ct0.ciphertext_modulus(),
        );
        let ct1 = &mut ct1;

        let mut buffers = ComputationBuffers::new();

        let fft = Fft::new(multi_bit_bsk.polynomial_size());
        let fft = fft.as_view();

        buffers.resize(
            add_external_product_assign_scratch::<Scalar>(
                multi_bit_bsk.glwe_size(),
                multi_bit_bsk.polynomial_size(),
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );

        let mut src_idx = 1usize;

        for (ready_lock, condvar, multi_bit_fourier_ggsw) in fourier_multi_bit_ggsw_buffers
            .iter()
            .cycle()
            .take(multi_bit_bsk.multi_bit_input_lwe_dimension().0)
        {
            src_idx ^= 1;

            let (src_ct, mut dst_ct) = if src_idx == 0 {
                (ct0.as_view(), ct1.as_mut_view())
            } else {
                (ct1.as_view(), ct0.as_mut_view())
            };

            dst_ct.as_mut().fill(Scalar::ZERO);

            let mut ready = ready_lock.lock().unwrap();

            while !*ready {
                ready = condvar.wait(ready).unwrap();
            }

            let multi_bit_fourier_ggsw = multi_bit_fourier_ggsw.lock().unwrap();

            add_external_product_assign(
                dst_ct,
                multi_bit_fourier_ggsw.as_view(),
                src_ct,
                fft,
                buffers.stack(),
            );

            *ready = false;

            // Wake a single producer thread sleeping on the condvar (only one will get to work
            // anyways)
            condvar.notify_one();
        }

        if src_idx == 0 {
            ct0.as_mut().copy_from_slice(ct1.as_ref());
        }

        let ciphertext_modulus = ct0.ciphertext_modulus();
        if !ciphertext_modulus.is_native_modulus() {
            // When we convert back from the fourier domain, integer values will contain up to 53
            // MSBs with information. In our representation of power of 2 moduli < native modulus we
            // fill the MSBs and leave the LSBs empty, this usage of the signed decomposer allows to
            // round while keeping the data in the MSBs
            let signed_decomposer = SignedDecomposer::new(
                DecompositionBaseLog(ciphertext_modulus.get_custom_modulus().ilog2() as usize),
                DecompositionLevelCount(1),
            );
            ct0.as_mut()
                .iter_mut()
                .for_each(|x| *x = signed_decomposer.closest_representable(*x));
        }

        threads.into_iter().for_each(|t| t.join().unwrap());
    });
}

/// Perform a programmable bootstrap with given an input [`LWE ciphertext`](`LweCiphertext`), a
/// look-up table passed as a [`GLWE ciphertext`](`GlweCiphertext`) and an [`LWE multi-bit bootstrap
/// key`](`LweMultiBitBootstrapKey`) in the fourier domain. The result is written in the provided
/// output [`LWE ciphertext`](`LweCiphertext`).
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define the parameters for a 4 bits message able to hold the doubled 2 bits message
/// let small_lwe_dimension = LweDimension(742);
/// let glwe_dimension = GlweDimension(1);
/// let polynomial_size = PolynomialSize(2048);
/// let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
/// let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
/// let pbs_base_log = DecompositionBaseLog(23);
/// let pbs_level = DecompositionLevelCount(1);
/// let grouping_factor = LweBskGroupingFactor(2); // Group bits in pairs
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Request the best seeder possible, starting with hardware entropy sources and falling back to
/// // /dev/random on Unix systems if enabled via cargo features
/// let mut boxed_seeder = new_seeder();
/// // Get a mutable reference to the seeder as a trait object from the Box returned by new_seeder
/// let seeder = boxed_seeder.as_mut();
///
/// // Create a generator which uses a CSPRNG to generate secret keys
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// // Create a generator which uses two CSPRNGs to generate public masks and secret encryption
/// // noise
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
///
/// println!("Generating keys...");
///
/// // Generate an LweSecretKey with binary coefficients
/// let small_lwe_sk =
///     LweSecretKey::generate_new_binary(small_lwe_dimension, &mut secret_generator);
///
/// // Generate a GlweSecretKey with binary coefficients
/// let glwe_sk =
///     GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
///
/// // Create a copy of the GlweSecretKey re-interpreted as an LweSecretKey
/// let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();
///
/// let mut bsk = LweMultiBitBootstrapKey::new(
///     0u64,
///     glwe_dimension.to_glwe_size(),
///     polynomial_size,
///     pbs_base_log,
///     pbs_level,
///     small_lwe_dimension,
///     grouping_factor,
///     ciphertext_modulus,
/// );
///
/// par_generate_lwe_multi_bit_bootstrap_key(
///     &small_lwe_sk,
///     &glwe_sk,
///     &mut bsk,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// let mut multi_bit_bsk = FourierLweMultiBitBootstrapKey::new(
///     bsk.input_lwe_dimension(),
///     bsk.glwe_size(),
///     bsk.polynomial_size(),
///     bsk.decomposition_base_log(),
///     bsk.decomposition_level_count(),
///     bsk.grouping_factor(),
/// );
///
/// convert_standard_lwe_multi_bit_bootstrap_key_to_fourier(&bsk, &mut multi_bit_bsk);
///
/// // We don't need the standard bootstrapping key anymore
/// drop(bsk);
///
/// // Our 4 bits message space
/// let message_modulus = 1u64 << 4;
///
/// // Our input message
/// let input_message = 3u64;
///
/// // Delta used to encode 4 bits of message + a bit of padding on u64
/// let delta = (1_u64 << 63) / message_modulus;
///
/// // Apply our encoding
/// let plaintext = Plaintext(input_message * delta);
///
/// // Allocate a new LweCiphertext and encrypt our plaintext
/// let lwe_ciphertext_in: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
///     &small_lwe_sk,
///     plaintext,
///     lwe_modular_std_dev,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// // Now we will use a PBS to compute a multiplication by 2, it is NOT the recommended way of
/// // doing this operation in terms of performance as it's much more costly than a multiplication
/// // with a cleartext, however it resets the noise in a ciphertext to a nominal level and allows
/// // to evaluate arbitrary functions so depending on your use case it can be a better fit.
///
/// // Here we will define a helper function to generate an accumulator for a PBS
/// fn generate_accumulator<F>(
///     polynomial_size: PolynomialSize,
///     glwe_size: GlweSize,
///     message_modulus: usize,
///     ciphertext_modulus: CiphertextModulus<u64>,
///     delta: u64,
///     f: F,
/// ) -> GlweCiphertextOwned<u64>
/// where
///     F: Fn(u64) -> u64,
/// {
///     // N/(p/2) = size of each block, to correct noise from the input we introduce the notion of
///     // box, which manages redundancy to yield a denoised value for several noisy values around
///     // a true input value.
///     let box_size = polynomial_size.0 / message_modulus;
///
///     // Create the accumulator
///     let mut accumulator_u64 = vec![0_u64; polynomial_size.0];
///
///     // Fill each box with the encoded denoised value
///     for i in 0..message_modulus {
///         let index = i * box_size;
///         accumulator_u64[index..index + box_size]
///             .iter_mut()
///             .for_each(|a| *a = f(i as u64) * delta);
///     }
///
///     let half_box_size = box_size / 2;
///
///     // Negate the first half_box_size coefficients to manage negacyclicity and rotate
///     for a_i in accumulator_u64[0..half_box_size].iter_mut() {
///         *a_i = (*a_i).wrapping_neg();
///     }
///
///     // Rotate the accumulator
///     accumulator_u64.rotate_left(half_box_size);
///
///     let accumulator_plaintext = PlaintextList::from_container(accumulator_u64);
///
///     let accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
///         glwe_size,
///         &accumulator_plaintext,
///         ciphertext_modulus,
///     );
///
///     accumulator
/// }
///
/// // Generate the accumulator for our multiplication by 2 using a simple closure
/// let accumulator: GlweCiphertextOwned<u64> = generate_accumulator(
///     polynomial_size,
///     glwe_dimension.to_glwe_size(),
///     message_modulus as usize,
///     ciphertext_modulus,
///     delta,
///     |x: u64| 2 * x,
/// );
///
/// // Allocate the LweCiphertext to store the result of the PBS
/// let mut pbs_multiplication_ct = LweCiphertext::new(
///     0u64,
///     big_lwe_sk.lwe_dimension().to_lwe_size(),
///     ciphertext_modulus,
/// );
/// println!("Computing PBS...");
/// // Use 4 threads to compute the multi-bit PBS
/// multi_bit_programmable_bootstrap_lwe_ciphertext(
///     &lwe_ciphertext_in,
///     &mut pbs_multiplication_ct,
///     &accumulator,
///     &multi_bit_bsk,
///     ThreadCount(4),
/// );
///
/// // Decrypt the PBS multiplication result
/// let pbs_multiplication_plaintext: Plaintext<u64> =
///     decrypt_lwe_ciphertext(&big_lwe_sk, &pbs_multiplication_ct);
///
/// // Create a SignedDecomposer to perform the rounding of the decrypted plaintext
/// // We pass a DecompositionBaseLog of 5 and a DecompositionLevelCount of 1 indicating we want to
/// // round the 5 MSB, 1 bit of padding plus our 4 bits of message
/// let signed_decomposer =
///     SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));
///
/// // Round and remove our encoding
/// let pbs_multiplication_result: u64 =
///     signed_decomposer.closest_representable(pbs_multiplication_plaintext.0) / delta;
///
/// println!("Checking result...");
/// assert_eq!(6, pbs_multiplication_result);
/// println!(
///     "Mulitplication via PBS result is correct! Expected 6, got {pbs_multiplication_result}"
/// );
/// ```
pub fn multi_bit_programmable_bootstrap_lwe_ciphertext<
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
    thread_count: ThreadCount,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Sync,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    AccCont: Container<Element = Scalar>,
    KeyCont: Container<Element = c64> + Sync,
{
    assert_eq!(
        input.lwe_size().to_lwe_dimension(),
        multi_bit_bsk.input_lwe_dimension(),
        "Mimatched input LweDimension. LweCiphertext input LweDimension {:?}. \
        FourierLweMultiBitBootstrapKey input LweDimension {:?}.",
        input.lwe_size().to_lwe_dimension(),
        multi_bit_bsk.input_lwe_dimension(),
    );

    assert_eq!(
        output.lwe_size().to_lwe_dimension(),
        multi_bit_bsk.output_lwe_dimension(),
        "Mimatched output LweDimension. LweCiphertext output LweDimension {:?}. \
        FourierLweMultiBitBootstrapKey output LweDimension {:?}.",
        output.lwe_size().to_lwe_dimension(),
        multi_bit_bsk.output_lwe_dimension(),
    );

    assert_eq!(
        accumulator.glwe_size(),
        multi_bit_bsk.glwe_size(),
        "Mimatched GlweSize. Accumulator GlweSize {:?}. \
        FourierLweMultiBitBootstrapKey GlweSize {:?}.",
        accumulator.glwe_size(),
        multi_bit_bsk.glwe_size(),
    );

    assert_eq!(
        accumulator.polynomial_size(),
        multi_bit_bsk.polynomial_size(),
        "Mimatched PolynomialSize. Accumulator PolynomialSize {:?}. \
        FourierLweMultiBitBootstrapKey PolynomialSize {:?}.",
        accumulator.polynomial_size(),
        multi_bit_bsk.polynomial_size(),
    );

    assert_eq!(
        input.ciphertext_modulus(),
        output.ciphertext_modulus(),
        "Mismatched CiphertextModulus between input ({:?}) and output ({:?})",
        input.ciphertext_modulus(),
        output.ciphertext_modulus(),
    );

    assert_eq!(
        input.ciphertext_modulus(),
        accumulator.ciphertext_modulus(),
        "Mismatched CiphertextModulus between input ({:?}) and accumulator ({:?})",
        input.ciphertext_modulus(),
        accumulator.ciphertext_modulus(),
    );

    assert!(
        thread_count.0 != 0,
        "Got thread_count == 0, this is not supported"
    );

    let mut local_accumulator = GlweCiphertext::new(
        Scalar::ZERO,
        accumulator.glwe_size(),
        accumulator.polynomial_size(),
        accumulator.ciphertext_modulus(),
    );
    local_accumulator
        .as_mut()
        .copy_from_slice(accumulator.as_ref());

    multi_bit_blind_rotate_assign(input, &mut local_accumulator, multi_bit_bsk, thread_count);

    extract_lwe_sample_from_glwe_ciphertext(&local_accumulator, output, MonomialDegree(0));
}

/// Deterministic version of [`multi_bit_programmable_bootstrap_lwe_ciphertext`]. Performance may be
/// slightly worse than the non deterministic version.
pub fn multi_bit_deterministic_programmable_bootstrap_lwe_ciphertext<
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
    thread_count: ThreadCount,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Sync,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    AccCont: Container<Element = Scalar>,
    KeyCont: Container<Element = c64> + Sync,
{
    assert_eq!(
        input.lwe_size().to_lwe_dimension(),
        multi_bit_bsk.input_lwe_dimension(),
        "Mimatched input LweDimension. LweCiphertext input LweDimension {:?}. \
        FourierLweMultiBitBootstrapKey input LweDimension {:?}.",
        input.lwe_size().to_lwe_dimension(),
        multi_bit_bsk.input_lwe_dimension(),
    );

    assert_eq!(
        output.lwe_size().to_lwe_dimension(),
        multi_bit_bsk.output_lwe_dimension(),
        "Mimatched output LweDimension. LweCiphertext output LweDimension {:?}. \
        FourierLweMultiBitBootstrapKey output LweDimension {:?}.",
        output.lwe_size().to_lwe_dimension(),
        multi_bit_bsk.output_lwe_dimension(),
    );

    assert_eq!(
        accumulator.glwe_size(),
        multi_bit_bsk.glwe_size(),
        "Mimatched GlweSize. Accumulator GlweSize {:?}. \
        FourierLweMultiBitBootstrapKey GlweSize {:?}.",
        accumulator.glwe_size(),
        multi_bit_bsk.glwe_size(),
    );

    assert_eq!(
        accumulator.polynomial_size(),
        multi_bit_bsk.polynomial_size(),
        "Mimatched PolynomialSize. Accumulator PolynomialSize {:?}. \
        FourierLweMultiBitBootstrapKey PolynomialSize {:?}.",
        accumulator.polynomial_size(),
        multi_bit_bsk.polynomial_size(),
    );

    assert_eq!(
        input.ciphertext_modulus(),
        output.ciphertext_modulus(),
        "Mismatched CiphertextModulus between input ({:?}) and output ({:?})",
        input.ciphertext_modulus(),
        output.ciphertext_modulus(),
    );

    assert_eq!(
        input.ciphertext_modulus(),
        accumulator.ciphertext_modulus(),
        "Mismatched CiphertextModulus between input ({:?}) and accumulator ({:?})",
        input.ciphertext_modulus(),
        accumulator.ciphertext_modulus(),
    );

    assert!(
        thread_count.0 != 0,
        "Got thread_count == 0, this is not supported"
    );

    let mut local_accumulator = GlweCiphertext::new(
        Scalar::ZERO,
        accumulator.glwe_size(),
        accumulator.polynomial_size(),
        accumulator.ciphertext_modulus(),
    );
    local_accumulator
        .as_mut()
        .copy_from_slice(accumulator.as_ref());

    multi_bit_deterministic_blind_rotate_assign(
        input,
        &mut local_accumulator,
        multi_bit_bsk,
        thread_count,
    );

    extract_lwe_sample_from_glwe_ciphertext(&local_accumulator, output, MonomialDegree(0));
}

pub fn std_prepare_multi_bit_ggsw<Scalar, GgswBufferCont, TmpGgswBufferCont, GgswGroupCont>(
    multi_bit_ggsw: &mut GgswCiphertext<GgswBufferCont>,
    tmp_ggsw_buffer: &mut GgswCiphertext<TmpGgswBufferCont>,
    ggsw_group: &GgswCiphertextList<GgswGroupCont>,
    lwe_mask_elements: &[Scalar],
) where
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize>,
    GgswBufferCont: ContainerMut<Element = Scalar>,
    TmpGgswBufferCont: ContainerMut<Element = Scalar>,
    GgswGroupCont: Container<Element = Scalar>,
{
    let mut ggsw_group_iter = ggsw_group.iter();

    // Keygen guarantees the first term is a constant term of the polynomial, no
    // polynomial multiplication required
    let ggsw_a_none = ggsw_group_iter.next().unwrap();

    multi_bit_ggsw
        .as_mut()
        .copy_from_slice(ggsw_a_none.as_ref());

    let polynomial_size = multi_bit_ggsw.polynomial_size();

    for (ggsw_idx, std_ggsw) in ggsw_group_iter.enumerate() {
        // We already processed the first ggsw, advance the index by 1
        let ggsw_idx = ggsw_idx + 1;

        // Select the proper mask elements to build the monomial degree depending on
        // the order the GGSW were generated in, using the bits from mask_idx and
        // ggsw_idx as selector bits
        let mut monomial_degree = Scalar::ZERO;
        for (mask_idx, &mask_element) in lwe_mask_elements.iter().enumerate() {
            let mask_position = lwe_mask_elements.len() - (mask_idx + 1);
            let selection_bit: Scalar = Scalar::cast_from((ggsw_idx >> mask_position) & 1);
            monomial_degree =
                monomial_degree.wrapping_add(selection_bit.wrapping_mul(mask_element));
        }

        let switched_degree = pbs_modulus_switch(
            monomial_degree,
            polynomial_size,
            ModulusSwitchOffset(0),
            LutCountLog(0),
        );

        tmp_ggsw_buffer
            .as_mut_polynomial_list()
            .iter_mut()
            .zip(std_ggsw.as_polynomial_list().iter())
            .for_each(|(mut tmp_polynomial, input_polynomial)| {
                polynomial_wrapping_monic_monomial_mul(
                    &mut tmp_polynomial,
                    &input_polynomial,
                    MonomialDegree(switched_degree),
                );
            });

        slice_wrapping_add_assign(multi_bit_ggsw.as_mut(), tmp_ggsw_buffer.as_ref());
    }
}

pub fn std_multi_bit_blind_rotate_assign<Scalar, InputCont, OutputCont, KeyCont>(
    input: &LweCiphertext<InputCont>,
    accumulator: &mut GlweCiphertext<OutputCont>,
    multi_bit_bsk: &LweMultiBitBootstrapKey<KeyCont>,
    thread_count: ThreadCount,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Sync + Send,
    InputCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    KeyCont: Container<Element = Scalar> + Sync,
{
    assert_eq!(
        input.lwe_size().to_lwe_dimension(),
        multi_bit_bsk.input_lwe_dimension(),
        "Mimatched input LweDimension. LweCiphertext input LweDimension {:?}. \
        FourierLweMultiBitBootstrapKey input LweDimension {:?}.",
        input.lwe_size().to_lwe_dimension(),
        multi_bit_bsk.input_lwe_dimension(),
    );

    assert_eq!(
        accumulator.glwe_size(),
        multi_bit_bsk.glwe_size(),
        "Mimatched GlweSize. Accumulator GlweSize {:?}. \
        FourierLweMultiBitBootstrapKey GlweSize {:?}.",
        accumulator.glwe_size(),
        multi_bit_bsk.glwe_size(),
    );

    assert_eq!(
        accumulator.polynomial_size(),
        multi_bit_bsk.polynomial_size(),
        "Mimatched PolynomialSize. Accumulator PolynomialSize {:?}. \
        FourierLweMultiBitBootstrapKey PolynomialSize {:?}.",
        accumulator.polynomial_size(),
        multi_bit_bsk.polynomial_size(),
    );

    assert_eq!(
        input.ciphertext_modulus(),
        accumulator.ciphertext_modulus(),
        "Mismatched CiphertextModulus between input ({:?}) and accumulator ({:?})",
        input.ciphertext_modulus(),
        accumulator.ciphertext_modulus(),
    );

    assert_eq!(
        input.ciphertext_modulus(),
        multi_bit_bsk.ciphertext_modulus(),
        "Mimatched CiphertextModulus. LweCiphertext CiphertextModulus {:?}. \
        LweMultiBitBootstrapKey CiphertextModulus {:?}.",
        input.ciphertext_modulus(),
        multi_bit_bsk.ciphertext_modulus(),
    );

    assert!(
        thread_count.0 != 0,
        "Got thread_count == 0, this is not supported"
    );

    let (lwe_mask, lwe_body) = input.get_mask_and_body();

    // No way to chunk the result of ggsw_iter at the moment
    // let ggsw_vec: Vec<_> = multi_bit_bsk.ggsw_iter().collect();
    let mut work_queue = Vec::with_capacity(multi_bit_bsk.multi_bit_input_lwe_dimension().0);

    let grouping_factor = multi_bit_bsk.grouping_factor();
    let ggsw_per_multi_bit_element = grouping_factor.ggsw_per_multi_bit_element();

    for (lwe_mask_elements, ggsw_group) in lwe_mask
        .as_ref()
        .chunks_exact(grouping_factor.0)
        .zip(multi_bit_bsk.chunks_exact(ggsw_per_multi_bit_element.0))
    {
        work_queue.push((lwe_mask_elements, ggsw_group));
    }

    assert!(work_queue.len() == lwe_mask.lwe_dimension().0 / grouping_factor.0);

    let work_queue = Mutex::new(work_queue);

    let lut_poly_size = accumulator.polynomial_size();
    let monomial_degree = pbs_modulus_switch(
        *lwe_body.data,
        lut_poly_size,
        ModulusSwitchOffset(0),
        LutCountLog(0),
    );

    // Modulus switching
    accumulator
        .as_mut_polynomial_list()
        .iter_mut()
        .for_each(|mut poly| {
            polynomial_wrapping_monic_monomial_div_assign(
                &mut poly,
                MonomialDegree(monomial_degree),
            )
        });

    let fourier_multi_bit_ggsw_buffers = (0..thread_count.0)
        .map(|_| {
            (
                Mutex::new(false),
                Condvar::new(),
                Mutex::new(FourierGgswCiphertext::new(
                    multi_bit_bsk.glwe_size(),
                    multi_bit_bsk.polynomial_size(),
                    multi_bit_bsk.decomposition_base_log(),
                    multi_bit_bsk.decomposition_level_count(),
                )),
            )
        })
        .collect::<Vec<_>>();

    let (tx, rx) = mpsc::channel::<usize>();

    let fft = Fft::new(multi_bit_bsk.polynomial_size());
    let fft = fft.as_view();
    thread::scope(|s| {
        let produce_multi_bit_fourier_ggsw = |thread_id: usize, tx: mpsc::Sender<usize>| {
            let mut buffers = ComputationBuffers::new();

            buffers.resize(fft.forward_scratch().unwrap().unaligned_bytes_required());

            let mut std_ggsw_buffer = GgswCiphertext::new(
                Scalar::ZERO,
                multi_bit_bsk.glwe_size(),
                multi_bit_bsk.polynomial_size(),
                multi_bit_bsk.decomposition_base_log(),
                multi_bit_bsk.decomposition_level_count(),
                multi_bit_bsk.ciphertext_modulus(),
            );

            let mut tmp_ggsw_buffer = GgswCiphertext::new(
                Scalar::ZERO,
                multi_bit_bsk.glwe_size(),
                multi_bit_bsk.polynomial_size(),
                multi_bit_bsk.decomposition_base_log(),
                multi_bit_bsk.decomposition_level_count(),
                multi_bit_bsk.ciphertext_modulus(),
            );

            let work_queue = &work_queue;

            let dest_idx = thread_id;
            let (ready_for_consumer_lock, condvar, fourier_ggsw_buffer) =
                &fourier_multi_bit_ggsw_buffers[dest_idx];

            loop {
                let maybe_work = {
                    let mut queue_lock = work_queue.lock().unwrap();
                    queue_lock.pop()
                };

                let Some((lwe_mask_elements, ggsw_group)) = maybe_work else {break};
                let mut ready_for_consumer = ready_for_consumer_lock.lock().unwrap();

                // Wait while the buffer is not ready for processing and wait on the condvar
                // to get notified when we can start processing again
                while *ready_for_consumer {
                    ready_for_consumer = condvar.wait(ready_for_consumer).unwrap();
                }

                let mut fourier_ggsw_buffer = fourier_ggsw_buffer.lock().unwrap();

                std_prepare_multi_bit_ggsw(
                    &mut std_ggsw_buffer,
                    &mut tmp_ggsw_buffer,
                    &ggsw_group,
                    lwe_mask_elements,
                );

                fourier_ggsw_buffer.as_mut_view().fill_with_forward_fourier(
                    std_ggsw_buffer.as_view(),
                    fft,
                    buffers.stack(),
                );

                // Drop the lock before we wake other threads
                drop(fourier_ggsw_buffer);

                *ready_for_consumer = true;
                tx.send(dest_idx).unwrap();

                // Wake threads waiting on the condvar
                condvar.notify_all();
            }
        };

        let threads: Vec<_> = (0..thread_count.0)
            .map(|id| {
                let tx = tx.clone();
                s.spawn(move || produce_multi_bit_fourier_ggsw(id, tx))
            })
            .collect();

        // We initialize ct0 for the successive external products
        let ct0 = accumulator;
        let mut ct1 = GlweCiphertext::new(
            Scalar::ZERO,
            ct0.glwe_size(),
            ct0.polynomial_size(),
            ct0.ciphertext_modulus(),
        );
        let ct1 = &mut ct1;

        let mut buffers = ComputationBuffers::new();

        buffers.resize(
            add_external_product_assign_scratch::<Scalar>(
                multi_bit_bsk.glwe_size(),
                multi_bit_bsk.polynomial_size(),
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );

        let mut src_idx = 1usize;

        for _ in 0..multi_bit_bsk.multi_bit_input_lwe_dimension().0 {
            src_idx ^= 1;
            let idx = rx.recv().unwrap();
            let (ready_lock, condvar, multi_bit_fourier_ggsw) =
                &fourier_multi_bit_ggsw_buffers[idx];

            let (src_ct, mut dst_ct) = if src_idx == 0 {
                (ct0.as_view(), ct1.as_mut_view())
            } else {
                (ct1.as_view(), ct0.as_mut_view())
            };

            dst_ct.as_mut().fill(Scalar::ZERO);

            let mut ready = ready_lock.lock().unwrap();
            assert!(*ready);

            let multi_bit_fourier_ggsw = multi_bit_fourier_ggsw.lock().unwrap();
            add_external_product_assign(
                dst_ct,
                multi_bit_fourier_ggsw.as_view(),
                src_ct,
                fft,
                buffers.stack(),
            );
            drop(multi_bit_fourier_ggsw);

            *ready = false;
            // Wake a single producer thread sleeping on the condvar (only one will get to work
            // anyways)
            condvar.notify_one();
        }

        if src_idx == 0 {
            ct0.as_mut().copy_from_slice(ct1.as_ref());
        }

        let ciphertext_modulus = ct0.ciphertext_modulus();
        if !ciphertext_modulus.is_native_modulus() {
            // When we convert back from the fourier domain, integer values will contain up to 53
            // MSBs with information. In our representation of power of 2 moduli < native modulus we
            // fill the MSBs and leave the LSBs empty, this usage of the signed decomposer allows to
            // round while keeping the data in the MSBs
            let signed_decomposer = SignedDecomposer::new(
                DecompositionBaseLog(ciphertext_modulus.get_custom_modulus().ilog2() as usize),
                DecompositionLevelCount(1),
            );
            ct0.as_mut()
                .iter_mut()
                .for_each(|x| *x = signed_decomposer.closest_representable(*x));
        }

        threads.into_iter().for_each(|t| t.join().unwrap());
    });
}

/// Deterministic variant of [`std_multi_bit_blind_rotate_assign`]. Performance
/// may be slightly worse than the non deterministic version.
pub fn std_multi_bit_deterministic_blind_rotate_assign<Scalar, InputCont, OutputCont, KeyCont>(
    input: &LweCiphertext<InputCont>,
    accumulator: &mut GlweCiphertext<OutputCont>,
    multi_bit_bsk: &LweMultiBitBootstrapKey<KeyCont>,
    thread_count: ThreadCount,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Sync,
    InputCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    KeyCont: Container<Element = Scalar> + Sync,
{
    assert_eq!(
        input.lwe_size().to_lwe_dimension(),
        multi_bit_bsk.input_lwe_dimension(),
        "Mimatched input LweDimension. LweCiphertext input LweDimension {:?}. \
        FourierLweMultiBitBootstrapKey input LweDimension {:?}.",
        input.lwe_size().to_lwe_dimension(),
        multi_bit_bsk.input_lwe_dimension(),
    );

    assert_eq!(
        accumulator.glwe_size(),
        multi_bit_bsk.glwe_size(),
        "Mimatched GlweSize. Accumulator GlweSize {:?}. \
        FourierLweMultiBitBootstrapKey GlweSize {:?}.",
        accumulator.glwe_size(),
        multi_bit_bsk.glwe_size(),
    );

    assert_eq!(
        accumulator.polynomial_size(),
        multi_bit_bsk.polynomial_size(),
        "Mimatched PolynomialSize. Accumulator PolynomialSize {:?}. \
        FourierLweMultiBitBootstrapKey PolynomialSize {:?}.",
        accumulator.polynomial_size(),
        multi_bit_bsk.polynomial_size(),
    );

    assert_eq!(
        input.ciphertext_modulus(),
        accumulator.ciphertext_modulus(),
        "Mismatched CiphertextModulus between input ({:?}) and accumulator ({:?})",
        input.ciphertext_modulus(),
        accumulator.ciphertext_modulus(),
    );

    assert_eq!(
        accumulator.ciphertext_modulus(),
        multi_bit_bsk.ciphertext_modulus(),
        "Mimatched CiphertextModulus. Accumulator CiphertextModulus {:?}. \
        LweMultiBitBootstrapKey CiphertextModulus {:?}.",
        accumulator.ciphertext_modulus(),
        multi_bit_bsk.ciphertext_modulus(),
    );

    assert!(
        thread_count.0 != 0,
        "Got thread_count == 0, this is not supported"
    );

    let (lwe_mask, lwe_body) = input.get_mask_and_body();

    // No way to chunk the result of ggsw_iter at the moment
    // let ggsw_vec: Vec<_> = multi_bit_bsk.ggsw_iter().collect();
    let mut work_queue = Vec::with_capacity(multi_bit_bsk.multi_bit_input_lwe_dimension().0);

    let grouping_factor = multi_bit_bsk.grouping_factor();
    let ggsw_per_multi_bit_element = grouping_factor.ggsw_per_multi_bit_element();

    for (lwe_mask_elements, ggsw_group) in lwe_mask
        .as_ref()
        .chunks_exact(grouping_factor.0)
        .zip(multi_bit_bsk.chunks_exact(ggsw_per_multi_bit_element.0))
    {
        work_queue.push((lwe_mask_elements, ggsw_group));
    }

    assert!(work_queue.len() == lwe_mask.lwe_dimension().0 / grouping_factor.0);

    let work_queue = &work_queue;

    let lut_poly_size = accumulator.polynomial_size();
    let monomial_degree = pbs_modulus_switch(
        *lwe_body.data,
        lut_poly_size,
        ModulusSwitchOffset(0),
        LutCountLog(0),
    );

    // Modulus switching
    accumulator
        .as_mut_polynomial_list()
        .iter_mut()
        .for_each(|mut poly| {
            polynomial_wrapping_monic_monomial_div_assign(
                &mut poly,
                MonomialDegree(monomial_degree),
            )
        });

    let fourier_multi_bit_ggsw_buffers = (0..thread_count.0)
        .map(|_| {
            (
                Mutex::new(false),
                Condvar::new(),
                Mutex::new(FourierGgswCiphertext::new(
                    multi_bit_bsk.glwe_size(),
                    multi_bit_bsk.polynomial_size(),
                    multi_bit_bsk.decomposition_base_log(),
                    multi_bit_bsk.decomposition_level_count(),
                )),
            )
        })
        .collect::<Vec<_>>();

    let fft = Fft::new(multi_bit_bsk.polynomial_size());
    let fft = fft.as_view();
    thread::scope(|s| {
        let produce_multi_bit_fourier_ggsw = |thread_id| {
            let mut buffers = ComputationBuffers::new();

            buffers.resize(fft.forward_scratch().unwrap().unaligned_bytes_required());

            let mut std_ggsw_buffer = GgswCiphertext::new(
                Scalar::ZERO,
                multi_bit_bsk.glwe_size(),
                multi_bit_bsk.polynomial_size(),
                multi_bit_bsk.decomposition_base_log(),
                multi_bit_bsk.decomposition_level_count(),
                multi_bit_bsk.ciphertext_modulus(),
            );

            let mut tmp_ggsw_buffer = GgswCiphertext::new(
                Scalar::ZERO,
                multi_bit_bsk.glwe_size(),
                multi_bit_bsk.polynomial_size(),
                multi_bit_bsk.decomposition_base_log(),
                multi_bit_bsk.decomposition_level_count(),
                multi_bit_bsk.ciphertext_modulus(),
            );

            let dest_idx = thread_id;
            for (lwe_mask_elements, ggsw_group) in
                work_queue.iter().skip(thread_id).step_by(thread_count.0)
            {
                let (ready_for_consumer_lock, condvar, fourier_ggsw_buffer) =
                    &fourier_multi_bit_ggsw_buffers[dest_idx];

                let mut ready_for_consumer = ready_for_consumer_lock.lock().unwrap();

                // Wait while the buffer is not ready for processing and wait on the condvar
                // to get notified when we can start processing again
                while *ready_for_consumer {
                    ready_for_consumer = condvar.wait(ready_for_consumer).unwrap();
                }

                let mut fourier_ggsw_buffer = fourier_ggsw_buffer.lock().unwrap();

                std_prepare_multi_bit_ggsw(
                    &mut std_ggsw_buffer,
                    &mut tmp_ggsw_buffer,
                    ggsw_group,
                    lwe_mask_elements,
                );

                fourier_ggsw_buffer.as_mut_view().fill_with_forward_fourier(
                    std_ggsw_buffer.as_view(),
                    fft,
                    buffers.stack(),
                );

                // Drop the lock before we wake other threads
                drop(fourier_ggsw_buffer);

                *ready_for_consumer = true;

                // Wake threads waiting on the condvar
                condvar.notify_all();
            }
        };

        let threads: Vec<_> = (0..thread_count.0)
            .map(|id| s.spawn(move || produce_multi_bit_fourier_ggsw(id)))
            .collect();

        // We initialize ct0 for the successive external products
        let ct0 = accumulator;
        let mut ct1 = GlweCiphertext::new(
            Scalar::ZERO,
            ct0.glwe_size(),
            ct0.polynomial_size(),
            ct0.ciphertext_modulus(),
        );
        let ct1 = &mut ct1;

        let mut buffers = ComputationBuffers::new();

        buffers.resize(
            add_external_product_assign_scratch::<Scalar>(
                multi_bit_bsk.glwe_size(),
                multi_bit_bsk.polynomial_size(),
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );

        let mut src_idx = 1usize;

        for (ready_lock, condvar, multi_bit_fourier_ggsw) in fourier_multi_bit_ggsw_buffers
            .iter()
            .cycle()
            .take(multi_bit_bsk.multi_bit_input_lwe_dimension().0)
        {
            src_idx ^= 1;

            let (src_ct, mut dst_ct) = if src_idx == 0 {
                (ct0.as_view(), ct1.as_mut_view())
            } else {
                (ct1.as_view(), ct0.as_mut_view())
            };

            dst_ct.as_mut().fill(Scalar::ZERO);

            let mut ready = ready_lock.lock().unwrap();

            while !*ready {
                ready = condvar.wait(ready).unwrap();
            }

            let multi_bit_fourier_ggsw = multi_bit_fourier_ggsw.lock().unwrap();

            add_external_product_assign(
                dst_ct,
                multi_bit_fourier_ggsw.as_view(),
                src_ct,
                fft,
                buffers.stack(),
            );

            *ready = false;

            // Wake a single producer thread sleeping on the condvar (only one will get to work
            // anyways)
            condvar.notify_one();
        }

        if src_idx == 0 {
            ct0.as_mut().copy_from_slice(ct1.as_ref());
        }

        let ciphertext_modulus = ct0.ciphertext_modulus();
        if !ciphertext_modulus.is_native_modulus() {
            // When we convert back from the fourier domain, integer values will contain up to 53
            // MSBs with information. In our representation of power of 2 moduli < native modulus we
            // fill the MSBs and leave the LSBs empty, this usage of the signed decomposer allows to
            // round while keeping the data in the MSBs
            let signed_decomposer = SignedDecomposer::new(
                DecompositionBaseLog(ciphertext_modulus.get_custom_modulus().ilog2() as usize),
                DecompositionLevelCount(1),
            );
            ct0.as_mut()
                .iter_mut()
                .for_each(|x| *x = signed_decomposer.closest_representable(*x));
        }

        threads.into_iter().for_each(|t| t.join().unwrap());
    });
}

pub fn std_multi_bit_programmable_bootstrap_lwe_ciphertext<
    Scalar,
    InputCont,
    OutputCont,
    AccCont,
    KeyCont,
>(
    input: &LweCiphertext<InputCont>,
    output: &mut LweCiphertext<OutputCont>,
    accumulator: &GlweCiphertext<AccCont>,
    multi_bit_bsk: &LweMultiBitBootstrapKey<KeyCont>,
    thread_count: ThreadCount,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Sync + Send,
    InputCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    AccCont: Container<Element = Scalar>,
    KeyCont: Container<Element = Scalar> + Sync,
{
    assert_eq!(
        input.lwe_size().to_lwe_dimension(),
        multi_bit_bsk.input_lwe_dimension(),
        "Mimatched input LweDimension. LweCiphertext input LweDimension {:?}. \
        FourierLweMultiBitBootstrapKey input LweDimension {:?}.",
        input.lwe_size().to_lwe_dimension(),
        multi_bit_bsk.input_lwe_dimension(),
    );

    assert_eq!(
        output.lwe_size().to_lwe_dimension(),
        multi_bit_bsk.output_lwe_dimension(),
        "Mimatched output LweDimension. LweCiphertext output LweDimension {:?}. \
        FourierLweMultiBitBootstrapKey output LweDimension {:?}.",
        output.lwe_size().to_lwe_dimension(),
        multi_bit_bsk.output_lwe_dimension(),
    );

    assert_eq!(
        accumulator.glwe_size(),
        multi_bit_bsk.glwe_size(),
        "Mimatched GlweSize. Accumulator GlweSize {:?}. \
        FourierLweMultiBitBootstrapKey GlweSize {:?}.",
        accumulator.glwe_size(),
        multi_bit_bsk.glwe_size(),
    );

    assert_eq!(
        accumulator.polynomial_size(),
        multi_bit_bsk.polynomial_size(),
        "Mimatched PolynomialSize. Accumulator PolynomialSize {:?}. \
        FourierLweMultiBitBootstrapKey PolynomialSize {:?}.",
        accumulator.polynomial_size(),
        multi_bit_bsk.polynomial_size(),
    );

    assert_eq!(
        input.ciphertext_modulus(),
        output.ciphertext_modulus(),
        "Mismatched CiphertextModulus between input ({:?}) and output ({:?})",
        input.ciphertext_modulus(),
        output.ciphertext_modulus(),
    );

    assert_eq!(
        input.ciphertext_modulus(),
        accumulator.ciphertext_modulus(),
        "Mismatched CiphertextModulus between input ({:?}) and accumulator ({:?})",
        input.ciphertext_modulus(),
        accumulator.ciphertext_modulus(),
    );

    assert!(
        thread_count.0 != 0,
        "Got thread_count == 0, this is not supported"
    );

    let mut local_accumulator = GlweCiphertext::new(
        Scalar::ZERO,
        accumulator.glwe_size(),
        accumulator.polynomial_size(),
        accumulator.ciphertext_modulus(),
    );
    local_accumulator
        .as_mut()
        .copy_from_slice(accumulator.as_ref());

    std_multi_bit_blind_rotate_assign(input, &mut local_accumulator, multi_bit_bsk, thread_count);

    extract_lwe_sample_from_glwe_ciphertext(&local_accumulator, output, MonomialDegree(0));
}

/// Deterministic variant of [`std_multi_bit_programmable_bootstrap_lwe_ciphertext`]. Performance
/// may be slightly worse than the non deterministic version.
pub fn std_multi_bit_deterministic_programmable_bootstrap_lwe_ciphertext<
    Scalar,
    InputCont,
    OutputCont,
    AccCont,
    KeyCont,
>(
    input: &LweCiphertext<InputCont>,
    output: &mut LweCiphertext<OutputCont>,
    accumulator: &GlweCiphertext<AccCont>,
    multi_bit_bsk: &LweMultiBitBootstrapKey<KeyCont>,
    thread_count: ThreadCount,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Sync,
    InputCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    AccCont: Container<Element = Scalar>,
    KeyCont: Container<Element = Scalar> + Sync,
{
    assert_eq!(
        input.lwe_size().to_lwe_dimension(),
        multi_bit_bsk.input_lwe_dimension(),
        "Mimatched input LweDimension. LweCiphertext input LweDimension {:?}. \
        FourierLweMultiBitBootstrapKey input LweDimension {:?}.",
        input.lwe_size().to_lwe_dimension(),
        multi_bit_bsk.input_lwe_dimension(),
    );

    assert_eq!(
        output.lwe_size().to_lwe_dimension(),
        multi_bit_bsk.output_lwe_dimension(),
        "Mimatched output LweDimension. LweCiphertext output LweDimension {:?}. \
        FourierLweMultiBitBootstrapKey output LweDimension {:?}.",
        output.lwe_size().to_lwe_dimension(),
        multi_bit_bsk.output_lwe_dimension(),
    );

    assert_eq!(
        accumulator.glwe_size(),
        multi_bit_bsk.glwe_size(),
        "Mimatched GlweSize. Accumulator GlweSize {:?}. \
        FourierLweMultiBitBootstrapKey GlweSize {:?}.",
        accumulator.glwe_size(),
        multi_bit_bsk.glwe_size(),
    );

    assert_eq!(
        accumulator.polynomial_size(),
        multi_bit_bsk.polynomial_size(),
        "Mimatched PolynomialSize. Accumulator PolynomialSize {:?}. \
        FourierLweMultiBitBootstrapKey PolynomialSize {:?}.",
        accumulator.polynomial_size(),
        multi_bit_bsk.polynomial_size(),
    );

    assert_eq!(
        input.ciphertext_modulus(),
        output.ciphertext_modulus(),
        "Mismatched CiphertextModulus between input ({:?}) and output ({:?})",
        input.ciphertext_modulus(),
        output.ciphertext_modulus(),
    );

    assert_eq!(
        input.ciphertext_modulus(),
        accumulator.ciphertext_modulus(),
        "Mismatched CiphertextModulus between input ({:?}) and accumulator ({:?})",
        input.ciphertext_modulus(),
        accumulator.ciphertext_modulus(),
    );

    assert!(
        thread_count.0 != 0,
        "Got thread_count == 0, this is not supported"
    );

    let mut local_accumulator = GlweCiphertext::new(
        Scalar::ZERO,
        accumulator.glwe_size(),
        accumulator.polynomial_size(),
        accumulator.ciphertext_modulus(),
    );
    local_accumulator
        .as_mut()
        .copy_from_slice(accumulator.as_ref());

    std_multi_bit_deterministic_blind_rotate_assign(
        input,
        &mut local_accumulator,
        multi_bit_bsk,
        thread_count,
    );

    extract_lwe_sample_from_glwe_ciphertext(&local_accumulator, output, MonomialDegree(0));
}
