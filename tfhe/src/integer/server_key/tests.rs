use crate::integer::keycache::{KEY_CACHE, KEY_CACHE_WOPBS};
use rand::Rng;
use crate::integer::ciphertext::crt_ciphertext_from_ciphertext;
use crate::integer::{CrtCiphertext, IntegerCiphertext, RadixCiphertext};
use crate::integer::parameters::PARAM_4_BITS_5_BLOCKS;
use crate::integer::parameters::parameters_benches_joc::*;
use crate::integer::wopbs::WopbsKey;
use crate::shortint::prelude::{CarryModulus, MessageModulus};

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
        ID_1_RADIX_16_BITS_16_BLOCKS,
                          ID_2_RADIX_16_BITS_8_BLOCKS,
                           ID_4_RADIX_32_BITS_32_BLOCKS, // DOES NOT WORK
                           ID_5_RADIX_32_BITS_16_BLOCKS,
                          ID_6_RADIX_32_BITS_8_BLOCKS
    ];
    let nb_blocks_vec = vec![
         16,
                             8,
                              32,
                             16,
                             8
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
            let mut ct_res = sks.unchecked_mul(&mut ct_0, &mut ct_1);

            // let mut ct_res = sks.unchecked_add(&mut ct_0.clone(), &mut ct_0);
            // sks.full_propagate(&mut ct_res);

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
        ID_1_RADIX_16_BITS_16_BLOCKS,
                         ID_2_RADIX_16_BITS_8_BLOCKS,
                         ID_4_RADIX_32_BITS_32_BLOCKS,
                         ID_5_RADIX_32_BITS_16_BLOCKS,
                         ID_6_RADIX_32_BITS_8_BLOCKS
    ];
    let nb_blocks_vec = vec![
        16,
                             8,
                             32,
                             16,
                             8,
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
        8,
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
pub fn joc_native_crt_add() {
    let param_vec = vec![
        ID_10_NATIF_CRT_16_BITS_5_BLOCKS_WOPBS,
        ID_11_NATIF_CRT_32_BITS_6_BLOCKS_WOPBS
    ];

    // Define CRT basis, and global modulus
    let basis_16bits = vec![7,8,9,11,13];
    let basis_32bits = vec![43,47,37,49,29,41];

    let basis_vec = [
        basis_16bits,
        basis_32bits,
    ];

    for (param, basis)  in param_vec.iter().zip(basis_vec.iter()) {
        let mut rng = rand::thread_rng();
        let msg_space = basis.iter().product::<u64>();

        let (cks, sks) = KEY_CACHE.get_from_params(*param);

        for _ in 0..NB_TEST {
            let clear1 = rng.gen::<u64>() % msg_space;
            let clear0 = rng.gen::<u64>() % msg_space;
            let ct1 = cks.encrypt_native_crt(clear1, basis.to_vec());
            let ct0 = cks.encrypt_native_crt(clear0, basis.to_vec());

            let ct_res = sks.unchecked_crt_add(&ct1, &ct0);

            let res = cks.decrypt_native_crt(&ct_res);
            assert_eq!((clear0 + clear1) % msg_space, res);
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






#[test]
pub fn joc_hybrid_32_bits() {
    let param = ID_12_HYBRID_CRT_32_bits;
    //let param = ID_6_CRT_32_BITS_6_BLOCKS;

    // basis = 2^5 * 3^5* 5^4 * 7^4
    let basis_32bits = vec![
         32,
        243,
        625,
        2401
    ];

    let modulus_vec = [
         8,
        3,
        5,
        7,
    ];

    let nb_blocks_vec = [
         4,
         5,
         4,
        4,
    ];

    let message_carry_mod_vec = [
         (MessageModulus(8), CarryModulus(8)),
         (MessageModulus(8), CarryModulus(8)),
         (MessageModulus(8), CarryModulus(8)),
        (MessageModulus(8), CarryModulus(8)),
    ];


    //println!("Chosen Parameter Set: {param:?}");
    for _ in 0..10 {
        let mut i= 0;
        for (block_modulus, nb_blocks) in modulus_vec.iter().zip(nb_blocks_vec.iter
        ()) {
            let (mut cks, mut sks) = KEY_CACHE.get_from_params(param);
            // sks.key.message_modulus = MessageModulus(*block_modulus);
            // sks.key.carry_modulus = CarryModulus(*block_modulus);

            cks.key.parameters.message_modulus = message_carry_mod_vec[i].0;
            cks.key.parameters.carry_modulus = message_carry_mod_vec[i].1;
            sks.key.message_modulus = message_carry_mod_vec[i].0;
            sks.key.carry_modulus = message_carry_mod_vec[i].1;

            let mut msg_space = basis_32bits[i];
            i = i+1;
            // println!("block_modulus = {block_modulus}");
            // println!("msg_space = {msg_space}");
            //
            // let mut rng = rand::thread_rng();
            // let clear_0 = rng.gen::<u64>() % msg_space;
            // let mut cpy_clear_0 = clear_0;
            // let mut blocks_crt_0 = vec![];
            // for _ in 0..*nb_blocks{
            //     let tmp = cpy_clear_0 % block_modulus;
            //     blocks_crt_0.push((cks.encrypt_crt(tmp, vec![*block_modulus])).blocks[0].clone());
            //     cpy_clear_0 = (cpy_clear_0 - tmp)/ block_modulus;
            // }
            // let clear_1 = rng.gen::<u64>() % msg_space;
            // let mut cpy_clear_1 = clear_1;
            // let mut blocks_crt_1 = vec![];
            // for _ in 0..*nb_blocks{
            //     let tmp = cpy_clear_1 % block_modulus;
            //     blocks_crt_1.push((cks.encrypt_crt(tmp, vec![*block_modulus])).blocks[0].clone());
            //     cpy_clear_1 = (cpy_clear_1 - tmp)/ block_modulus;
            // }

            let mut rng = rand::thread_rng();
            let clear_0 =  rng.gen::<u64>() % msg_space;
            let clear_1 = rng.gen::<u64>() % msg_space;

            println!("clear 0 {:?}", clear_0);
            println!("clear 1 {:?}", clear_1);



            // TEST_ADD //

            let mut ct_zero_rad = cks.encrypt_radix_with_message_modulus(clear_0, *nb_blocks,
                                                                         MessageModulus
                                                                             (*block_modulus));

            let mut ct_one_rad = cks.encrypt_radix_with_message_modulus(clear_1, *nb_blocks,
                                                                         MessageModulus
                                                                             (*block_modulus));

            // for (ct0_i, ct1_i) in ct_zero_rad.blocks.iter_mut().zip(ct_one_rad.blocks.iter_mut()) {
            //     ct0_i.carry_modulus = CarryModulus(ct0_i.message_modulus.0);
            //     ct1_i.carry_modulus = CarryModulus(ct0_i.message_modulus.0);
            //
            // }

            println!("CT0 Msg modulus = {}, CT0 carry modulus = {}", ct_zero_rad.blocks[0]
                .message_modulus
                .0.clone(), ct_zero_rad.blocks[0]
                .carry_modulus.0);

            println!("CT1 Msg modulus = {}, CT1 carry modulus = {}", ct_one_rad.blocks[0]
                .message_modulus
                .0.clone(), ct_one_rad.blocks[0]
                         .carry_modulus.0);


            //

            let result = cks.decrypt_radix_with_message_modulus(&ct_zero_rad);
            assert_eq!(result % msg_space, (clear_0) % msg_space);

            let result = cks.decrypt_radix_with_message_modulus(&ct_one_rad);
            assert_eq!(result % msg_space, (clear_1) % msg_space);


            //TEST ADD
            let mut ct_res = sks.unchecked_add(&ct_zero_rad, &ct_one_rad);
            let mut result = 0_u64;
            let mut shift = 1_u64;

            let result = cks.decrypt_radix_with_message_modulus(&ct_res);



            println!("add");
            println!("dec add        {:?}", result);
            println!("dec add mod    {:?}", result% msg_space);
            println!("expected    {:?}", (clear_0 + clear_1) % msg_space);
            assert_eq!(result % msg_space, (clear_0 + clear_1) % msg_space);
            println!("-----");

            // TEST_CARRY_PROPAGATE //

            sks.full_propagate(&mut ct_res);



            let result = cks.decrypt_radix_with_message_modulus(&ct_res);
            println!("propagate");
            println!("dec propagate        {:?}", result);
            println!("dec propagate mod    {:?}", result% msg_space);
            assert_eq!(result % msg_space , (clear_0 + clear_1) % msg_space);
            println!("expected    {:?}", (clear_0 + clear_1) % msg_space);
            println!("-----");


            let mut ct_res = sks.unchecked_mul(&mut ct_one_rad, &mut ct_zero_rad);

            let result = cks.decrypt_radix_with_message_modulus(&ct_res);




            println!("mul");
            println!("dec mul        {:?}", result);
            println!("dec mul mod    {:?}", result % msg_space);
            println!("clear mul      {:?}", (clear_0 * clear_1));
            println!("clear mul mod  {:?}", (clear_0 * clear_1) % msg_space);
            println!("info deg: {:?}", ct_res.blocks[0].degree);
            println!("info mm : {:?}", ct_res.blocks[0].message_modulus);
            println!("info cm : {:?}", ct_res.blocks[0].carry_modulus);
            println!("expected    {:?}", (clear_0 * clear_1) % msg_space);
            assert_eq!(result % msg_space , (clear_0 * clear_1) % msg_space);
            println!("-----");
        }
    }
    //println!("it's OK");
    panic!()
}



#[test]
pub fn EXPERIMETAL_hybride_32_bits() {
    let param = ID_6_CRT_32_BITS_6_BLOCKS;

    // basis = 2^5 * 3^5* 5^4 * 7^4
    let basis_32bits = vec![
        32,
        243,
        625,
        2420
    ];

    let modulus_vec = [
        2,
        3,
        5,
        7,
    ];

    let nb_blocks_vec = [
        5,
        5,
        4,
        4,
    ];


    //println!("Chosen Parameter Set: {param:?}");
    for _ in 0..2 {
        let i= 0;
        for (block_modulus, nb_blocks) in modulus_vec.iter().zip(nb_blocks_vec.iter
        ()) {
            let (mut cks, mut sks) = KEY_CACHE.get_from_params(param);

            // let mut msg_space = *block_modulus;
            // for _ in 1..*nb_blocks {
            //     msg_space *= *block_modulus;
            // }

            let mut msg_space = basis_32bits[i];

            println!("block_modulus = {block_modulus}");
            println!("msg_space = {msg_space}");

            let mut rng = rand::thread_rng();
            let clear_0 = rng.gen::<u64>() % msg_space;
            let mut cpy_clear_0 = clear_0;
            let mut blocks_crt_0 = vec![];
            for _ in 0..*nb_blocks{
                let tmp = cpy_clear_0 % block_modulus;
                blocks_crt_0.push((cks.encrypt_crt(tmp, vec![*block_modulus])).blocks[0].clone());
                cpy_clear_0 = (cpy_clear_0 - tmp)/ block_modulus;
            }
            let clear_1 = rng.gen::<u64>() % msg_space;
            let mut cpy_clear_1 = clear_1;
            let mut blocks_crt_1 = vec![];
            for _ in 0..*nb_blocks{
                let tmp = cpy_clear_1 % block_modulus;
                blocks_crt_1.push((cks.encrypt_crt(tmp, vec![*block_modulus])).blocks[0].clone());
                cpy_clear_1 = (cpy_clear_1 - tmp)/ block_modulus;
            }
            println!("clear 0 {:?}", clear_0);
            println!("clear 1 {:?}", clear_1);
            println!("add     {:?}", clear_0 + clear_1);
            println!("add mod {:?}", (clear_1 + clear_0) %msg_space );

            // TEST_ADD //

            let mut ct_zero_rad = RadixCiphertext::from_blocks(blocks_crt_0);
            let mut ct_one_rad = RadixCiphertext::from_blocks(blocks_crt_1);

            let mut ct_res = sks.unchecked_add(&ct_zero_rad, &ct_one_rad);
            let mut result = 0_u64;
            let mut shift = 1_u64;

            for c_i in ct_res.blocks().iter() {
                // decrypt the component i of the integer and multiply it by the radix product
                let block_value = cks.key.decrypt_message_and_carry(c_i);
                // update the result
                result = result.wrapping_add(block_value.wrapping_mul(shift));

                // update the shift for the next iteration
                shift = shift.wrapping_mul(*block_modulus);
            }

            println!("add");
            println!("dec add        {:?}", result);
            println!("dec add mod    {:?}", result% msg_space);
            assert_eq!(result % msg_space, (clear_0 + clear_1) % msg_space);
            println!("-----");

            // TEST_CARRY_PROPAGATE //

            sks.full_propagate(&mut ct_res);
            let mut result = 0_u64;
            let mut shift = 1_u64;
            for c_i in ct_res.blocks().iter() {
                // decrypt the component i of the integer and multiply it by the radix product
                let block_value = cks.key.decrypt_message_and_carry(c_i);
                // update the result
                result = result.wrapping_add(block_value.wrapping_mul(shift));

                // update the shift for the next iteration
                shift = shift.wrapping_mul(*block_modulus);
            }
            println!("propagate");
            println!("dec propagate        {:?}", result);
            println!("dec propagate mod    {:?}", result% msg_space);
            assert_eq!(result % msg_space , (clear_0 + clear_1) % msg_space);
            println!("-----");

            // TEST_MUL //

            ct_one_rad.blocks[0].message_modulus.0 =  ct_one_rad.blocks[0].message_modulus.0 *2;
            ct_one_rad.blocks[0].carry_modulus.0 =  ct_one_rad.blocks[0].carry_modulus.0 /2;
            ct_zero_rad.blocks[0].message_modulus.0 =  ct_zero_rad.blocks[0].message_modulus.0 *2;
            ct_zero_rad.blocks[0].carry_modulus.0 =  ct_zero_rad.blocks[0].carry_modulus.0 /2;

            sks.key.message_modulus.0 =  sks.key.message_modulus.0*2;
            sks.key.carry_modulus.0 =  sks.key.carry_modulus.0/2;
            //cks.parameters().carry_modulus.0 =  cks.parameters().carry_modulus.0/2;
            //cks.parameters().message_modulus.0 =  cks.parameters().message_modulus.0/2;
            ct_res = sks.unchecked_mul(&mut ct_one_rad, &mut ct_zero_rad);
            //sks.full_propagate(&mut ct_res);
            let mut result = 0_u64;
            let mut shift = 1_u64;
            for c_i in ct_res.blocks().iter() {
                // decrypt the component i of the integer and multiply it by the radix product
                let block_value = cks.key.decrypt_message_and_carry(c_i);
                // update the result
                result = result.wrapping_add(block_value.wrapping_mul(shift));

                // update the shift for the next iteration
                shift = shift.wrapping_mul(*block_modulus);
            }
            println!("mul");
            println!("dec mul        {:?}", result);
            println!("dec mul mod    {:?}", result % msg_space);
            println!("clear mul      {:?}", (clear_0 * clear_1));
            println!("clear mul mod  {:?}", (clear_0 * clear_1) % msg_space);
            println!("info deg: {:?}", ct_res.blocks[0].degree);
            println!("info mm : {:?}", ct_res.blocks[0].message_modulus);
            println!("info cm : {:?}", ct_res.blocks[0].carry_modulus);
            assert_eq!(result % msg_space , (clear_0 * clear_1) % msg_space);
            println!("-----");
        }
    }
    println!("it's OK");
    panic!()
}

/*
#[test]
pub fn joc_hybride_32_bits() {
    let param = ID_5_RADIX_32_BITS_16_BLOCKS;

    // basis = 2^5 * 3^5* 5^4 * 7^4
    let basis_32bits = vec![32, 243, 625, 2420];

    let modulus_vec = [
        2,
        3,
        5,
        7,
    ];

    let nb_blocks_vec = [
        5,
        5,
        4,
        4,
    ];


    println!("Chosen Parameter Set: {param:?}");
    for _ in 0..NB_TEST {
        for (block_modulus, nb_blocks) in modulus_vec.iter().zip(nb_blocks_vec.iter()) {
            let (cks, sks) = KEY_CACHE.get_from_params(param);

            let mut msg_space = *block_modulus;
            for _ in 1..*nb_blocks {
                msg_space *= *block_modulus;
            }

            println!("block_modulus = {block_modulus}");
            println!("msg_space = {msg_space}");

            let mut rng = rand::thread_rng();
            let clear_0 = rng.gen::<u64>() % msg_space;

            println!("Expected Result = {}", (clear_0*clear_0) % msg_space);

            // encryption of an integer using CRT hacking
            let mut ct_zero = cks.encrypt_crt(clear_0, vec![*block_modulus; *nb_blocks]);
            let mut ct_one = cks.encrypt_crt(clear_0, vec![*block_modulus; *nb_blocks]);

            let mut ct_zero_rad = RadixCiphertext::from_blocks(ct_zero.blocks().to_vec());
            let ct_one_rad = RadixCiphertext::from_blocks(ct_one.blocks().to_vec());

            // Test carry progration`

            let mut ct_tmp = sks.unchecked_add(&ct_one_rad, &ct_zero_rad);

            let mut result = 0_u64;
            let mut shift = 1_u64;
            let modulus = ct_one_rad.blocks[0].message_modulus.0 as u64;

            for c_i in ct_one_rad.blocks.iter() {
                // decrypt the component i of the integer and multiply it by the radix product
                let block_value = cks.key.decrypt_message_and_carry(c_i).wrapping_mul(shift);

                // update the result
                result = result.wrapping_add(block_value);

                // update the shift for the next iteration
                shift = shift.wrapping_mul(modulus);
            }

            let dec_res = cks.decrypt_radix(&ct_zero_rad);
            println!("FIRST ADD");
            assert_eq!(dec_res, (clear_0) % msg_space);
            //
            // sks.full_propagate(&mut ct_tmp);
            //
            // /// DECRYPT //
            // let mut result = 0_u64;
            // let mut shift = 1_u64;
            // let modulus = ct_one_rad.blocks[0].message_modulus.0 as u64;
            //
            // for c_i in ct_tmp.blocks.iter() {
            //     // decrypt the component i of the integer and multiply it by the radix product
            //     let block_value = cks.key.decrypt_message_and_carry(c_i).wrapping_mul(shift);
            //
            //     // update the result
            //     result = result.wrapping_add(block_value);
            //
            //     // update the shift for the next iteration
            //     shift = shift.wrapping_mul(modulus);
            // }
            //
            // let dec_res = result % msg_space;
            // println!("FULL PROP");
            // assert_eq!(dec_res, (clear_0 + clear_0) % msg_space);
            //
            //
            // ////END TEST CARRY /////////
            //
            // let ct_res = sks.unchecked_mul(&ct_zero_rad, &ct_one_rad);
            //
            // /// DECRYPT //
            // let mut result = 0_u64;
            // let mut shift = 1_u64;
            // let modulus = ct_one_rad.blocks[0].message_modulus.0 as u64;
            //
            // for c_i in ct_res.blocks.iter() {
            //     // decrypt the component i of the integer and multiply it by the radix product
            //     let block_value = cks.key.decrypt_message_and_carry(c_i).wrapping_mul(shift);
            //
            //     // update the result
            //     result = result.wrapping_add(block_value);
            //
            //     // update the shift for the next iteration
            //     shift = shift.wrapping_mul(modulus);
            // }
            //
            // let dec_res = result % msg_space;
            // println!("MUL");
            // assert_eq!(dec_res, (clear_0 * clear_0) % msg_space);
        }
    }
}
 */