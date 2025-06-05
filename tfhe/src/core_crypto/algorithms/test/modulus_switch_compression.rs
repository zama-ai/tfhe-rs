use super::*;
use crate::core_crypto::fft_impl::common::modulus_switch;
use itertools::Itertools;

#[cfg(not(tarpaulin))]
const NB_TESTS: usize = 10;
#[cfg(tarpaulin)]
const NB_TESTS: usize = 1;

fn encryption_ms_decryption<Scalar: UnsignedTorus + Sync + Send + CastInto<u64> + CastFrom<u64>>(
    params: ClassicTestParams<Scalar>,
) where
    usize: CastFrom<Scalar>,
{
    let ClassicTestParams {
        lwe_noise_distribution,
        message_modulus_log,
        ciphertext_modulus,
        polynomial_size,
        ..
    } = params;

    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);

    let mut rsc: TestResources = TestResources::new();

    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

    let log_modulus = polynomial_size.to_blind_rotation_input_modulus_log();

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
            // Create the LweSecretKey
            let lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key::<Scalar, _>(
                params.lwe_dimension,
                &mut rsc.secret_random_generator,
            );

            let lwe = allocate_and_encrypt_new_lwe_ciphertext(
                &lwe_secret_key,
                Plaintext(msg * delta),
                lwe_noise_distribution,
                ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            let lwe = lwe_ciphertext_modulus_switch::<_, Scalar, _>(lwe.as_view(), log_modulus);

            // Can be stored using much less space than the standard lwe ciphertexts
            let compressed = lwe.compress::<u64>();

            let container: Vec<Scalar> = compressed
                .extract::<u64>()
                .container()
                .iter()
                .map(|i| (*i).cast_into())
                .map(|i: Scalar| i << (Scalar::BITS - log_modulus.0))
                .collect();

            let lwe_ms_ed = LweCiphertext::from_container(container, ciphertext_modulus);

            let decrypted = decrypt_lwe_ciphertext(&lwe_secret_key, &lwe_ms_ed);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;
            assert_eq!(decoded, msg);
        }

        // In coverage, we break after one while loop iteration, changing message values does
        // not yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

fn assert_ms_compression<Scalar>(ct: &LweCiphertext<Vec<Scalar>>, log_modulus: CiphertextModulusLog)
where
    Scalar: UnsignedTorus + CastInto<u64>,
    u64: CastInto<Scalar>,
{
    let msed_ct = lwe_ciphertext_modulus_switch::<_, u64, _>(ct.as_view(), log_modulus);

    let a = msed_ct.compress::<u64>();

    let b = a.extract::<u64>();
    let b = b.container();

    for (i, j) in ct.as_ref().iter().zip_eq(b.iter()) {
        let i_ms: u64 = modulus_switch(*i, log_modulus).cast_into();

        assert_eq!(i_ms, *j);
    }
}

fn assert_ms_multi_bit_compression<
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + CastInto<u64>,
>(
    ct: &LweCiphertext<Vec<Scalar>>,
    log_modulus: CiphertextModulusLog,
    grouping_factor: LweBskGroupingFactor,
) {
    let a = StandardMultiBitModulusSwitchedCt {
        input: ct.as_view(),
        grouping_factor,
        log_modulus,
    };

    let b = CompressedModulusSwitchedMultiBitLweCiphertext::<u64>::compress(
        ct,
        log_modulus,
        grouping_factor,
    );

    let c = b.extract();

    assert_eq!(
        a.switched_modulus_input_lwe_body(),
        c.switched_modulus_input_lwe_body()
    );

    for i in 0..ct.lwe_size().to_lwe_dimension().0 / grouping_factor.0 {
        for (j, k) in a
            .switched_modulus_input_mask_per_group(i)
            .zip_eq(c.switched_modulus_input_mask_per_group(i))
        {
            assert_eq!(j, k);
        }
    }
}

#[test]
fn test_ms_with_packing() {
    for ciphertext_modulus in [
        CiphertextModulus::new(1 << 63),
        CiphertextModulus::new_native(),
    ] {
        for lwe_dimension in (10..1025).map(LweDimension) {
            for log_modulus in (10..15).map(CiphertextModulusLog) {
                let mut lwe_ciphertext_in =
                    LweCiphertextOwned::new(0_u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);

                for j in lwe_ciphertext_in.as_mut() {
                    *j = rand::random();
                }

                assert_ms_compression(&lwe_ciphertext_in, log_modulus);

                for grouping_factor in (1..6).map(LweBskGroupingFactor) {
                    if lwe_dimension.0 % grouping_factor.0 == 0 {
                        assert_ms_multi_bit_compression(
                            &lwe_ciphertext_in,
                            log_modulus,
                            grouping_factor,
                        );
                    }
                }
            }
        }
    }
}

create_parameterized_test!(encryption_ms_decryption);
