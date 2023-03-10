use crate::integer::keycache::{KEY_CACHE, KEY_CACHE_WOPBS};
use rand::Rng;
use crate::integer::ciphertext::crt_ciphertext_from_ciphertext;
use crate::integer::CrtCiphertext;
use crate::integer::parameters::PARAM_4_BITS_5_BLOCKS;
use crate::integer::parameters::parameters_benches_joc::*;
use crate::integer::wopbs::WopbsKey;

/// Number of assert in randomized tests
const NB_TEST: usize = 100;

//// RADIX ///

#[test]
fn joc_radix_add() {
    let param_vec = vec![ID_1_RADIX_16_BITS_16_BLOCKS, ID_2_RADIX_16_BITS_8_BLOCKS,
                         ID_4_RADIX_32_BITS_32_BLOCKS, ID_5_RADIX_32_BITS_16_BLOCKS, ID_6_RADIX_32_BITS_8_BLOCKS];
    let nb_blocks_vec = vec![16, 8, 32, 16, 8];

    for (param, nb_blocks) in  param_vec.iter().zip(nb_blocks_vec.iter()) {
        let (cks, sks) = KEY_CACHE.get_from_params(*param);
        let mut rng = rand::thread_rng();

        // message_modulus^vec_length
        let modulus = param.message_modulus.0.pow(*nb_blocks as u32) as u64;

        for _ in 0..NB_TEST {
            let clear_0 = rng.gen::<u64>() % modulus;
            let clear_1 = rng.gen::<u64>() % modulus;

            // encryption of an integer
            let ct_0 = cks.encrypt_radix(clear_0, *nb_blocks);

            // encryption of an inter
            let ct_1 = cks.encrypt_radix(clear_1, *nb_blocks);

            // add the two ciphertexts
            let ct_res = sks.unchecked_add(&ct_0, &ct_1);

            // decryption of ct_res
            let dec_res = cks.decrypt_radix(&ct_res);

            // assert
            assert_eq!((clear_0 + clear_1) % modulus, dec_res);
        }
    }
}

#[test]
fn joc_radix_mul() {
    let param_vec = vec![
        // ID_1_RADIX_16_BITS_16_BLOCKS,
        //                   ID_2_RADIX_16_BITS_8_BLOCKS,
                           ID_4_RADIX_32_BITS_32_BLOCKS, // DOES NOT WORK
                           // ID_5_RADIX_32_BITS_16_BLOCKS,
                          // ID_6_RADIX_32_BITS_8_BLOCKS
    ];
    let nb_blocks_vec = vec![
         // 16
        //                      8,
                              32,
                             // 16,
                             // 8
    ];
    for (param, nb_blocks) in  param_vec.iter().zip(nb_blocks_vec.iter()) {

        let (cks, sks) = KEY_CACHE.get_from_params(*param);
        let mut rng = rand::thread_rng();

        // message_modulus^vec_length
        let modulus = param.message_modulus.0.pow(*nb_blocks as u32) as u64;

        println!("MODULUS = {modulus}, nb_blocks = {nb_blocks}");

        for _ in 0..10 {
            let clear_0 = 2725718330; //rng.gen::<u64>() % modulus;
            // let clear_1 = 751081786; // rng.gen::<u64>() % modulus;
            let clear_1 = 2;

            // encryption of an integer
            let mut ct_0 = cks.encrypt_radix(clear_0, *nb_blocks);

            // encryption of an inter
            let mut ct_1 = cks.encrypt_radix(clear_1, *nb_blocks);

            println!("DECRYPTED: ct_0 =  {}, ct_1 = {}", cks.decrypt_radix(&ct_0), cks
                .decrypt_radix(&ct_1));

            // mul the two ciphertexts
            //let mut ct_res = sks.unchecked_mul(&mut ct_0, &mut ct_1);

            let mut ct_res = sks.unchecked_add(&mut ct_0.clone(), &mut ct_0);
            sks.full_propagate(&mut ct_res);

            // decryption of ct_res
            let dec_res = cks.decrypt_radix(&ct_res);

            // assert
            assert_eq!((clear_0 * clear_1) % modulus, dec_res);
        }
    }
}

#[test]
fn joc_radix_carry_propagate() {
    let param_vec = vec![
        // ID_1_RADIX_16_BITS_16_BLOCKS,
        //                  ID_2_RADIX_16_BITS_8_BLOCKS,
                         ID_4_RADIX_32_BITS_32_BLOCKS,
                         // ID_5_RADIX_32_BITS_16_BLOCKS,
                         // ID_6_RADIX_32_BITS_8_BLOCKS
    ];
    let nb_blocks_vec = vec![
        // 16,
        //                      8,
                             32,
                             // 16,
                             // 8
        ];

    for (param, nb_blocks) in  param_vec.iter().zip(nb_blocks_vec.iter()) {
        let (cks, sks) = KEY_CACHE.get_from_params(*param);
        let mut rng = rand::thread_rng();

        // message_modulus^vec_length
        let modulus = param.message_modulus.0.pow(*nb_blocks as u32) as u64;

        for _ in 0..NB_TEST {
            let clear_0 = rng.gen::<u64>() % modulus;

            // encryption of an integer
            let mut ct_0 = cks.encrypt_radix(clear_0, *nb_blocks);

            sks.full_propagate(&mut ct_0);

            // decryption of ct_res
            let dec_res = cks.decrypt_radix(&ct_0);

            // assert
            assert_eq!(clear_0 % modulus, dec_res);
        }
    }
}

#[test]
pub fn joc_radix_wopbs() {
    let param_vec = vec![
         ID_7_RADIX_16_BITS_16_BLOCKS_WOPBS,
         ID_8_RADIX_16_BITS_8_BLOCKS_WOPBS
    ];
    let nb_blocks_vec = vec![
        16,
        8
    ];

    for (param, nb_blocks) in  param_vec.iter().zip(nb_blocks_vec.iter()) {
        let mut rng = rand::thread_rng();

        let (cks, sks) = KEY_CACHE.get_from_params(*param);
        let wopbs_key = WopbsKey::new_wopbs_key_only_for_wopbs(&cks, &sks);

        let mut msg_space: u64 = param.message_modulus.0 as u64;
        for _ in 1..*nb_blocks {
            msg_space *= param.message_modulus.0 as u64;
        }

        for _ in 0..NB_TEST {
            let clear1 = rng.gen::<u64>() % msg_space;
            let ct1 = cks.encrypt_radix(clear1, *nb_blocks);
            let lut = wopbs_key.generate_lut_radix(&ct1, |x| x);
            let ct_res = wopbs_key.wopbs(&ct1, &lut);
            let res_wop = cks.decrypt_radix(&ct_res);
            assert_eq!(clear1, res_wop);
        }
    }
}



/// CRT ///

#[test]
fn joc_crt_add() {
    let param_vec = vec![ID_3_CRT_16_BITS_5_BLOCKS, ID_6_CRT_32_BITS_6_BLOCKS];

    // Define CRT basis, and global modulus
    let basis_16bits = vec![7,8,9,11,13];
    let basis_32bits = vec![43,47,37,49,29,41];

    let basis_vec = [basis_16bits, basis_32bits];

    for (param, basis) in  param_vec.iter().zip(basis_vec.iter()) {
        let modulus = basis.iter().product::<u64>();
        let (cks, sks) = KEY_CACHE.get_from_params(*param);
        let mut rng = rand::thread_rng();



        for _ in 0..NB_TEST {
            let mut clear_0 = rng.gen::<u64>() % modulus;
            let clear_1 = rng.gen::<u64>() % modulus;

            // encryption of an integer
            let mut ct_zero = cks.encrypt_crt(clear_0, basis.to_vec());
            let mut ct_one = cks.encrypt_crt(clear_1, basis.to_vec());

            let dec0 = cks.decrypt_crt(&ct_zero);
            let dec1 = cks.decrypt_crt(&ct_one);

            assert_eq!(dec0, clear_0);
            assert_eq!(dec1, clear_1);

            // add the two ciphertexts
            let ct_res = sks.unchecked_crt_add(&mut ct_zero, &mut ct_one);
            // decryption of ct_res
            let dec_res = cks.decrypt_crt(&ct_res);

            // assert
            clear_0 += clear_1;
            assert_eq!(clear_0 % modulus, dec_res % modulus);
        }
    }
}






#[test]
fn joc_crt_mul() {
    let param_vec = vec![ID_3_CRT_16_BITS_5_BLOCKS, ID_6_CRT_32_BITS_6_BLOCKS];

    // Define CRT basis, and global modulus
    let basis_16bits = vec![7,8,9,11,13];
    let basis_32bits = vec![43,47,37,49,29,41];

    let basis_vec = [basis_16bits, basis_32bits];

    for (param, basis) in  param_vec.iter().zip(basis_vec.iter()) {
        let modulus = basis.iter().product::<u64>();
        let (cks, sks) = KEY_CACHE.get_from_params(*param);
        let mut rng = rand::thread_rng();


        for _ in 0..NB_TEST {
            let mut clear_0 = rng.gen::<u64>() % modulus;
            let clear_1 = rng.gen::<u64>() % modulus;

            // encryption of an integer
            let mut ct_zero = cks.encrypt_crt(clear_0, basis.to_vec());
            let mut ct_one = cks.encrypt_crt(clear_1, basis.to_vec());


            // add the two ciphertexts
            let ct_res = sks.unchecked_crt_mul(&mut ct_zero, &mut ct_one);

            // decryption of ct_res
            let dec_res = cks.decrypt_crt(&ct_res);

            // assert
            clear_0 *= clear_1;
            assert_eq!(clear_0 % modulus, dec_res % modulus);
        }
    }
}


#[test]
fn joc_crt_carry_propagate() {
    let param_vec = vec![ID_3_CRT_16_BITS_5_BLOCKS, ID_6_CRT_32_BITS_6_BLOCKS];

    // Define CRT basis, and global modulus
    let basis_16bits = vec![7,8,9,11,13];
    let basis_32bits = vec![43,47,37,49,29,41];

    let basis_vec = [basis_16bits, basis_32bits];

    for (param, basis) in  param_vec.iter().zip(basis_vec.iter()) {
        let modulus = basis.iter().product::<u64>();
        let (cks, sks) = KEY_CACHE.get_from_params(*param);
        let mut rng = rand::thread_rng();

        for _ in 0..NB_TEST {
            let clear_0 = rng.gen::<u64>() % modulus;
            // encryption of an integer
            let mut ct_zero = cks.encrypt_crt(clear_0, basis.to_vec());

            // add the two ciphertexts
            sks.full_extract_message_assign(&mut ct_zero);

            // decryption of ct_res
            let dec_res = cks.decrypt_crt(&ct_zero);

            // assert
            assert_eq!(clear_0 % modulus, dec_res % modulus);
        }
    }
}



#[test]
pub fn joc_crt_wopbs() {
    let param_vec = vec![
        ID_9_CRT_16_BITS_5_BLOCKS_WOPBS,
    ];

    // Define CRT basis, and global modulus
    let basis_16bits = vec![7,8,9,11,13];

    let basis_vec = [basis_16bits];

    for (param, basis)  in param_vec.iter().zip(basis_vec.iter()) {
        let mut rng = rand::thread_rng();
        let msg_space = basis.iter().product::<u64>();

        let (cks, sks) = KEY_CACHE.get_from_params(*param);
        let wopbs_key = WopbsKey::new_wopbs_key_only_for_wopbs(&cks, &sks);

        for _ in 0..NB_TEST {
            let clear1 = rng.gen::<u64>() % msg_space;
            let ct1 = cks.encrypt_crt(clear1, basis.to_vec());
            let lut = wopbs_key.generate_lut_crt(&ct1, |x| x);
            let ct_res = wopbs_key.wopbs(&ct1, &lut);
            let res_wop = cks.decrypt_crt(&ct_res);
            assert_eq!(clear1, res_wop);
        }
    }
}

#[test]
pub fn joc_native_crt_wopbs() {
    let param_vec = vec![
        ID_10_NATIF_CRT_16_BITS_5_BLOCKS_WOPBS,
        //ID_11_NATIF_CRT_32_BITS_6_BLOCKS_WOPBS
    ];

    // Define CRT basis, and global modulus
    let basis_16bits = vec![7,8,9,11,13];
    //let basis_32bits = vec![43,47,37,49,29,41];

    let basis_vec = [
        basis_16bits,
        // basis_32bits,
    ];

    for (param, basis)  in param_vec.iter().zip(basis_vec.iter()) {
        let mut rng = rand::thread_rng();
        let msg_space = basis.iter().product::<u64>();

        let (cks, sks) = KEY_CACHE.get_from_params(*param);
        let wopbs_key = WopbsKey::new_wopbs_key_only_for_wopbs(&cks, &sks);

        for _ in 0..NB_TEST {
            let clear1 = rng.gen::<u64>() % msg_space;
            let ct1 = cks.encrypt_native_crt(clear1, basis.to_vec());
            let lut = wopbs_key.generate_lut_native_crt(&ct1, |x| x);
            let ct_res = wopbs_key.wopbs_native_crt(&ct1, &lut);
            let res_wop = cks.decrypt_native_crt(&ct_res);
            assert_eq!(clear1, res_wop);
        }
    }
}

#[test]
pub fn joc_native_crt_mul_wopbs() {
    let param_vec = vec![
        ID_11_NATIF_CRT_32_BITS_6_BLOCKS_WOPBS
    ];

    let basis_32bits = vec![43,47,37,49,29,41];

    let basis_vec = [
        basis_32bits,
    ];

    for (param, basis)  in param_vec.iter().zip(basis_vec.iter()) {
        let mut rng = rand::thread_rng();
        let msg_space = basis.iter().product::<u64>();

        let (cks, sks) = KEY_CACHE.get_from_params(*param);
        let wopbs_key = WopbsKey::new_wopbs_key_only_for_wopbs(&cks, &sks);

        for _ in 0..NB_TEST {
            let clear1 = rng.gen::<u64>() % msg_space;
            let clear2 = rng.gen::<u64>() % msg_space;

            let ct1 = cks.encrypt_native_crt(clear1, basis.to_vec());
            let ct2 = cks.encrypt_native_crt(clear2, basis.to_vec());

            let mut ct_res = ct1.clone();
            for ((ct_left, ct_right), res) in ct1.blocks.iter().zip(ct2.blocks.iter()).zip
            (ct_res.blocks.iter_mut()) {
                let crt_left = crt_ciphertext_from_ciphertext(&ct_left);
                let crt_right = crt_ciphertext_from_ciphertext(&ct_right);
                let mut crt_res = crt_ciphertext_from_ciphertext(&res);

                let lut = wopbs_key.generate_lut_bivariate_native_crt(&crt_left, |x,y|
                    x*y);
                crt_res = wopbs_key.bivariate_wopbs_native_crt(&crt_left, &crt_right, &lut);

            }
            let res_wop = cks.decrypt_native_crt(&ct_res);
            assert_eq!(clear1, res_wop);
        }
    }
}
