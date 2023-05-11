use tfhe::core_crypto::prelude::*;
use tfhe_01::shortint::{Ciphertext as CT01, ClientKey as CKS01, ServerKey as SKS01};

fn convert_ct_01_to_02(ct_01: CT01) -> tfhe::shortint::CiphertextBig {
    tfhe::shortint::CiphertextBig {
        ct: LweCiphertext::from_container(
            ct_01.ct.into_container(),
            CiphertextModulus::new_native(),
        ),
        degree: unsafe { std::mem::transmute(ct_01.degree) },
        message_modulus: unsafe { std::mem::transmute(ct_01.message_modulus) },
        carry_modulus: unsafe { std::mem::transmute(ct_01.carry_modulus) },
        _order_marker: std::marker::PhantomData,
    }
}

fn convert_cks_01_to_02(cks_01: CKS01) -> tfhe::shortint::ClientKey {
    tfhe::shortint::ClientKey {
        large_lwe_secret_key: LweSecretKey::from_container(cks_01.lwe_secret_key.into_container()),
        glwe_secret_key: GlweSecretKey::from_container(
            cks_01.glwe_secret_key.as_ref().to_vec(),
            PolynomialSize(cks_01.glwe_secret_key.polynomial_size().0),
        ),
        small_lwe_secret_key: LweSecretKey::from_container(
            cks_01.lwe_secret_key_after_ks.into_container(),
        ),
        parameters: tfhe::shortint::Parameters {
            lwe_dimension: unsafe { std::mem::transmute(cks_01.parameters.lwe_dimension) },
            glwe_dimension: unsafe { std::mem::transmute(cks_01.parameters.glwe_dimension) },
            polynomial_size: unsafe { std::mem::transmute(cks_01.parameters.polynomial_size) },
            lwe_modular_std_dev: unsafe {
                std::mem::transmute(cks_01.parameters.lwe_modular_std_dev)
            },
            glwe_modular_std_dev: unsafe {
                std::mem::transmute(cks_01.parameters.glwe_modular_std_dev)
            },
            pbs_base_log: unsafe { std::mem::transmute(cks_01.parameters.pbs_base_log) },
            pbs_level: unsafe { std::mem::transmute(cks_01.parameters.pbs_level) },
            ks_base_log: unsafe { std::mem::transmute(cks_01.parameters.ks_base_log) },
            ks_level: unsafe { std::mem::transmute(cks_01.parameters.ks_level) },
            pfks_level: unsafe { std::mem::transmute(cks_01.parameters.pfks_level) },
            pfks_base_log: unsafe { std::mem::transmute(cks_01.parameters.pfks_base_log) },
            pfks_modular_std_dev: unsafe {
                std::mem::transmute(cks_01.parameters.pfks_modular_std_dev)
            },
            cbs_level: unsafe { std::mem::transmute(cks_01.parameters.cbs_level) },
            cbs_base_log: unsafe { std::mem::transmute(cks_01.parameters.cbs_base_log) },
            message_modulus: unsafe { std::mem::transmute(cks_01.parameters.message_modulus) },
            carry_modulus: unsafe { std::mem::transmute(cks_01.parameters.carry_modulus) },
            ciphertext_modulus: CiphertextModulus::new_native(),
        },
    }
}

fn convert_sks_01_to_02(sks_01: SKS01) -> tfhe::shortint::ServerKey {
    let SKS01 {
        key_switching_key,
        bootstrapping_key,
        message_modulus,
        carry_modulus,
        max_degree,
    } = sks_01;

    let mut ksk_02 = LweKeyswitchKeyOwned::new(
        0u64,
        unsafe { std::mem::transmute(key_switching_key.decomposition_base_log()) },
        unsafe { std::mem::transmute(key_switching_key.decomposition_level_count()) },
        unsafe { std::mem::transmute(key_switching_key.input_key_lwe_dimension()) },
        unsafe { std::mem::transmute(key_switching_key.output_key_lwe_dimension()) },
        CiphertextModulus::new_native(),
    );

    let ksk_block_size = lwe_keyswitch_key_input_key_element_encrypted_size(
        ksk_02.decomposition_level_count(),
        ksk_02.output_lwe_size(),
    );

    ksk_02
        .as_mut()
        .chunks_exact_mut(ksk_block_size)
        .zip(key_switching_key.as_ref().chunks_exact(ksk_block_size))
        .for_each(|(dst, src)| {
            dst.chunks_exact_mut(key_switching_key.output_lwe_size().0)
                .zip(
                    src.chunks_exact(key_switching_key.output_lwe_size().0)
                        .rev(),
                )
                .for_each(|(dst, src)| dst.copy_from_slice(src))
        });

    tfhe::shortint::ServerKey {
        key_switching_key: ksk_02,
        bootstrapping_key: FourierLweBootstrapKey::from_container(
            bootstrapping_key.clone().data(),
            unsafe { std::mem::transmute(bootstrapping_key.input_lwe_dimension()) },
            unsafe { std::mem::transmute(bootstrapping_key.glwe_size()) },
            unsafe { std::mem::transmute(bootstrapping_key.polynomial_size()) },
            unsafe { std::mem::transmute(bootstrapping_key.decomposition_base_log()) },
            unsafe { std::mem::transmute(bootstrapping_key.decomposition_level_count()) },
        ),
        message_modulus: unsafe { std::mem::transmute(message_modulus) },
        carry_modulus: unsafe { std::mem::transmute(carry_modulus) },
        max_degree: unsafe { std::mem::transmute(max_degree) },
        ciphertext_modulus: CiphertextModulus::new_native(),
    }
}

pub fn main() {
    use std::fs::File;
    use std::io::{BufReader, BufWriter};
    let file_path = std::env::args().skip(1).next().unwrap();

    let file = File::open(&file_path).unwrap();
    let (_, (cks_01, sks_01)) = {
        let file_reader = BufReader::new(&file);
        bincode::deserialize_from::<_, (tfhe_01::shortint::Parameters, (CKS01, SKS01))>(file_reader)
            .unwrap()
    };

    let cks_02 = convert_cks_01_to_02(cks_01);
    let sks_02 = convert_sks_01_to_02(sks_01);
    let params = cks_02.parameters;

    let file = File::create(&file_path).unwrap();
    let file_writer = BufWriter::new(&file);
    bincode::serialize_into(file_writer, &(params, (cks_02, sks_02))).unwrap();
}

// pub fn _sanity_check() {
//     // Serialized data in 0.1
//     let (cks, sks, ct) = {
//         use tfhe_01::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
//         use tfhe_01::shortint::prelude::*;

//         let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);

//         let mut ct = cks.encrypt(3);

//         let ser_cks = bincode::serialize(&cks).unwrap();
//         let ser_sks = bincode::serialize(&sks).unwrap();
//         let set_ct = bincode::serialize(&ct).unwrap();

//         let scalar_mul = sks.smart_scalar_mul(&mut ct, 2);
//         let dec = cks.decrypt(&scalar_mul);
//         assert_eq!(
//             dec,
//             (3 * 2) % PARAM_MESSAGE_2_CARRY_2.message_modulus.0 as u64
//         );
//         (ser_cks, ser_sks, set_ct)
//     };

//     // Conversion process with bridge to 0.2
//     let (cks, sks, ct) = {
//         use tfhe_01::shortint::{Ciphertext as CT01, ClientKey as CKS01, ServerKey as SKS01};

//         let cks_01: CKS01 = bincode::deserialize(&cks).unwrap();
//         let sks_01: SKS01 = bincode::deserialize(&sks).unwrap();
//         let ct_01: CT01 = bincode::deserialize(&ct).unwrap();

//         use tfhe::core_crypto::prelude::*;

//         fn convert_ct_01_to_02(ct_01: CT01) -> tfhe::shortint::CiphertextBig {
//             tfhe::shortint::CiphertextBig {
//                 ct: LweCiphertext::from_container(
//                     ct_01.ct.into_container(),
//                     CiphertextModulus::new_native(),
//                 ),
//                 degree: unsafe { std::mem::transmute(ct_01.degree) },
//                 message_modulus: unsafe { std::mem::transmute(ct_01.message_modulus) },
//                 carry_modulus: unsafe { std::mem::transmute(ct_01.carry_modulus) },
//                 _order_marker: std::marker::PhantomData,
//             }
//         }

//         fn convert_cks_01_to_02(cks_01: CKS01) -> tfhe::shortint::ClientKey {
//             tfhe::shortint::ClientKey {
//                 large_lwe_secret_key: LweSecretKey::from_container(
//                     cks_01.lwe_secret_key.into_container(),
//                 ),
//                 glwe_secret_key: GlweSecretKey::from_container(
//                     cks_01.glwe_secret_key.as_ref().to_vec(),
//                     PolynomialSize(cks_01.glwe_secret_key.polynomial_size().0),
//                 ),
//                 small_lwe_secret_key: LweSecretKey::from_container(
//                     cks_01.lwe_secret_key_after_ks.into_container(),
//                 ),
//                 parameters: tfhe::shortint::Parameters {
//                     lwe_dimension: unsafe { std::mem::transmute(cks_01.parameters.lwe_dimension)
// },                     glwe_dimension: unsafe {
//                         std::mem::transmute(cks_01.parameters.glwe_dimension)
//                     },
//                     polynomial_size: unsafe {
//                         std::mem::transmute(cks_01.parameters.polynomial_size)
//                     },
//                     lwe_modular_std_dev: unsafe {
//                         std::mem::transmute(cks_01.parameters.lwe_modular_std_dev)
//                     },
//                     glwe_modular_std_dev: unsafe {
//                         std::mem::transmute(cks_01.parameters.glwe_modular_std_dev)
//                     },
//                     pbs_base_log: unsafe { std::mem::transmute(cks_01.parameters.pbs_base_log) },
//                     pbs_level: unsafe { std::mem::transmute(cks_01.parameters.pbs_level) },
//                     ks_base_log: unsafe { std::mem::transmute(cks_01.parameters.ks_base_log) },
//                     ks_level: unsafe { std::mem::transmute(cks_01.parameters.ks_level) },
//                     pfks_level: unsafe { std::mem::transmute(cks_01.parameters.pfks_level) },
//                     pfks_base_log: unsafe { std::mem::transmute(cks_01.parameters.pfks_base_log)
// },                     pfks_modular_std_dev: unsafe {
//                         std::mem::transmute(cks_01.parameters.pfks_modular_std_dev)
//                     },
//                     cbs_level: unsafe { std::mem::transmute(cks_01.parameters.cbs_level) },
//                     cbs_base_log: unsafe { std::mem::transmute(cks_01.parameters.cbs_base_log) },
//                     message_modulus: unsafe {
//                         std::mem::transmute(cks_01.parameters.message_modulus)
//                     },
//                     carry_modulus: unsafe { std::mem::transmute(cks_01.parameters.carry_modulus)
// },                     ciphertext_modulus: CiphertextModulus::new_native(),
//                 },
//             }
//         }

//         fn convert_sks_01_to_02(sks_01: SKS01) -> tfhe::shortint::ServerKey {
//             let SKS01 {
//                 key_switching_key,
//                 bootstrapping_key,
//                 message_modulus,
//                 carry_modulus,
//                 max_degree,
//             } = sks_01;

//             let mut ksk_02 = LweKeyswitchKeyOwned::new(
//                 0u64,
//                 unsafe { std::mem::transmute(key_switching_key.decomposition_base_log()) },
//                 unsafe { std::mem::transmute(key_switching_key.decomposition_level_count()) },
//                 unsafe { std::mem::transmute(key_switching_key.input_key_lwe_dimension()) },
//                 unsafe { std::mem::transmute(key_switching_key.output_key_lwe_dimension()) },
//                 CiphertextModulus::new_native(),
//             );

//             let ksk_block_size = lwe_keyswitch_key_input_key_element_encrypted_size(
//                 ksk_02.decomposition_level_count(),
//                 ksk_02.output_lwe_size(),
//             );

//             ksk_02
//                 .as_mut()
//                 .chunks_exact_mut(ksk_block_size)
//                 .zip(key_switching_key.as_ref().chunks_exact(ksk_block_size))
//                 .for_each(|(dst, src)| {
//                     dst.chunks_exact_mut(key_switching_key.output_lwe_size().0)
//                         .zip(
//                             src.chunks_exact(key_switching_key.output_lwe_size().0)
//                                 .rev(),
//                         )
//                         .for_each(|(dst, src)| dst.copy_from_slice(src))
//                 });

//             tfhe::shortint::ServerKey {
//                 key_switching_key: ksk_02,
//                 bootstrapping_key: FourierLweBootstrapKey::from_container(
//                     bootstrapping_key.clone().data(),
//                     unsafe { std::mem::transmute(bootstrapping_key.input_lwe_dimension()) },
//                     unsafe { std::mem::transmute(bootstrapping_key.glwe_size()) },
//                     unsafe { std::mem::transmute(bootstrapping_key.polynomial_size()) },
//                     unsafe { std::mem::transmute(bootstrapping_key.decomposition_base_log()) },
//                     unsafe { std::mem::transmute(bootstrapping_key.decomposition_level_count())
// },                 ),
//                 message_modulus: unsafe { std::mem::transmute(message_modulus) },
//                 carry_modulus: unsafe { std::mem::transmute(carry_modulus) },
//                 max_degree: unsafe { std::mem::transmute(max_degree) },
//                 ciphertext_modulus: CiphertextModulus::new_native(),
//             }
//         }

//         let cks_02 = convert_cks_01_to_02(cks_01);

//         let mut ct_02 = convert_ct_01_to_02(ct_01);

//         let sks_02 = convert_sks_01_to_02(sks_01);

//         let dec = cks_02.decrypt(&ct_02);
//         assert_eq!(dec, 3);
//         println!("assert ok");

//         let mut rhs = ct_02.clone();
//         let bitand = sks_02.smart_bitand(&mut ct_02, &mut rhs);
//         let dec = cks_02.decrypt(&bitand);
//         assert_eq!(dec, 3 & 3);
//         println!("bitand ok");

//         let mut rhs = cks_02.encrypt(1);
//         let bitand = sks_02.smart_bitand(&mut ct_02, &mut rhs);
//         let dec = cks_02.decrypt(&bitand);
//         assert_eq!(dec, 3 & 1);
//         println!("bitand ok");
//         (cks, sks, ct)
//     };
// }
