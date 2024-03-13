use super::*;
use std::ops::Shl;
use crate::core_crypto::algorithms::polynomial_algorithms::*;

//#[cfg(not(feature = "__coverage"))]
//const NB_TESTS: usize = 10;
//#[cfg(feature = "__coverage")]
const NB_TESTS: usize = 1;


#[test]
fn glwe_encrypt_tensor_prod_decrypt()
{
    //let lwe_dimension = LweDimension(730);
    let glwe_dimension = GlweDimension(2);
    let polynomial_size = PolynomialSize(1024);
    //let lwe_modular_std_dev = StandardDev(0.0000112785073554907);
    let glwe_modular_std_dev = StandardDev(0.000000000000000315293223915005);
    let ciphertext_modulus = CiphertextModulus::new_native();
    let message_modulus_log = CiphertextModulusLog(2);
    let msg_modulus = u64::ONE.shl(message_modulus_log.0);
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    //let pbs_base_log = DecompositionBaseLog(15);
    //let pbs_level = DecompositionLevelCount(2);
    //let ks_level = DecompositionLevelCount(5);
    //let ks_base_log = DecompositionBaseLog(3);
    let relin_level = DecompositionLevelCount(1);
    let relin_base_log = DecompositionBaseLog(23);

    let mut rsc = TestResources::new();
    let carry_modulus = 4u64;
    let delta: u64 = encoding_with_padding / (msg_modulus*carry_modulus);
    let mut msg = msg_modulus;

    while msg != u64::ZERO {
        msg = msg.wrapping_sub(u64::ONE);

        let input_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
            glwe_dimension,
            polynomial_size,
            &mut rsc.secret_random_generator,
        );

        //let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        //    glwe_dimension,
        //    polynomial_size,
        //    &mut rsc.secret_random_generator,
        //);

        let relin_key = allocate_and_generate_glwe_relinearisation_key(
            &input_glwe_secret_key,
            relin_base_log,
            relin_level,
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut rsc.encryption_random_generator,
        );

        for _ in 0..NB_TESTS {

            let mut plaintext_list =
            PlaintextList::new(0u64, PlaintextCount(input_glwe_secret_key.polynomial_size().0));
            plaintext_list.as_mut()[0] = msg * delta;
            //PlaintextList::from_container([msg * delta] + [0u64 ;input_glwe_secret_key.polynomial_size().0]);

            let mut glwe_lhs = GlweCiphertext::new(
                u64::ZERO,
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                ciphertext_modulus,
            );

            encrypt_glwe_ciphertext(
                &input_glwe_secret_key,
                &mut glwe_lhs,
                &plaintext_list,
                glwe_modular_std_dev,
                &mut rsc.encryption_random_generator,
            );

            let mut glwe_rhs = GlweCiphertext::new(
                u64::ZERO,
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                ciphertext_modulus,
            );

            encrypt_glwe_ciphertext(
                &input_glwe_secret_key,
                &mut glwe_rhs,
                &plaintext_list,
                glwe_modular_std_dev,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &glwe_lhs,
                ciphertext_modulus
            ));

            assert!(check_encrypted_content_respects_mod(
                &glwe_rhs,
                ciphertext_modulus
            ));

            let mut out_tensor_prod_ct = GlweCiphertext::new(
                u64::ZERO,
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                ciphertext_modulus,
            );

            tensor_mult_with_relin(
                &glwe_lhs,
                &glwe_rhs,
                delta,
                &relin_key,
                &mut out_tensor_prod_ct,
            );

            //assert!(check_encrypted_content_respects_mod(
            //    &out_tensor_prod_ct,
            //    ciphertext_modulus
            //));

            let mut output_plaintext_list =
            PlaintextList::new(u64::ZERO, PlaintextCount(out_tensor_prod_ct.polynomial_size().0));

            decrypt_glwe_ciphertext(&input_glwe_secret_key, &out_tensor_prod_ct, &mut output_plaintext_list);

            let mut decoded = vec![u64::ZERO; output_plaintext_list.plaintext_count().0];

            decoded
                .iter_mut()
                .zip(output_plaintext_list.iter())
                .for_each(|(dst, src)| *dst = round_decode(*src.0, delta) % (msg_modulus*carry_modulus));


            let pt1 = Polynomial::from_container(
                plaintext_list.clone().into_container()
                .iter()
                .map(|&x| <u64 as CastInto<u128>>::cast_into(x))
                .collect::<Vec<_>>(),
            );
            let pt2 = Polynomial::from_container(
                plaintext_list.clone().into_container()
                .iter()
                .map(|&x| <u64 as CastInto<u128>>::cast_into(x))
                .collect::<Vec<_>>(),
            );
            
            let mut product = Polynomial::new(0u128, polynomial_size);
            polynomial_wrapping_mul(&mut product, &pt1, &pt2);

            let mut scaled_product = Polynomial::new(0u64, polynomial_size);
            scaled_product
                .as_mut()
                .iter_mut()
                .zip(product.as_ref().iter())
                .for_each(|(dest, &source)| {
                *dest = u64::cast_from(source / <u64 as CastInto<u128>>::cast_into(delta))
                >> 59 //log2(delta)
            });

            // Check we recovered the correct message
            decoded
            .iter()
            .zip(scaled_product.iter())
            .for_each(|(&elt, coeff)| assert_eq!(elt, *coeff));
        }
    }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        //#[cfg(feature = "__coverage")]
        //break;
}



