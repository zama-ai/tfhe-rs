#![allow(dead_code)]
use std::cmp::{max, min};
use rand::Rng;
use tfhe::shortint;

#[allow(unused_imports)]
use crate::parameters::{PARAM_SAM_32, WOP_PARAM_SAM_32, PARAM_MESSAGE_2_CARRY_2_32,
                        PARAM_MESSAGE_2_CARRY_2_64, WOP_PARAM_MESSAGE_2_CARRY_2_32,
                        WOP_PARAM_MESSAGE_2_CARRY_2_64, FINAL_WOP_PARAM_2_2_32, FINAL_PARAM_2_2_32,
                        FINAL_WOP_PARAM_8, FINAL_PARAM_8, FINAL_PARAM_15,
                        FINAL_WOP_PARAM_15, FINAL_PARAM_16, FINAL_WOP_PARAM_16, FINAL_PARAM_32,
                        FINAL_WOP_PARAM_32, FINAL_PARAM_64, FINAL_WOP_PARAM_64,
                        FINAL_PARAM_64_BIS, FINAL_WOP_PARAM_64_BIS,
                        FINAL_PARAM_32_BIS, FINAL_WOP_PARAM_32_BIS, FINAL_PARAM_16_BIS,
                        FINAL_WOP_PARAM_16_BIS, FINAL_PARAM_15_BIS, FINAL_WOP_PARAM_15_BIS,
                        FINAL_PARAM_8_BIS, FINAL_WOP_PARAM_8_BIS, FINAL_PARAM_32_TCHESS, FINAL_WOP_PARAM_32_TCHESS
};
use crate::server_key::*;
use crate::{gen_keys, ClientKey};

const NB_OPE: i32 = 50;
const LEN_MAN: usize = 13; //13;
const LEN_EXP: usize = 4; //4;


const LEN_MAN8: usize = 2;
const LEN_EXP8: usize = 2;

const LEN_MAN16: usize = 6;
const LEN_EXP16: usize = 3;

const LEN_MAN32: usize = 13;
const LEN_EXP32: usize = 4;

const LEN_MAN64: usize = 27;
const LEN_EXP64: usize = 5;

macro_rules! named_param {
    ($param:ident) => {
        (stringify!($param), $param)
    };
}

struct Parameters {
    pbsparameters: shortint::ClassicPBSParameters,
    wopbsparameters: shortint::WopbsParameters,
    len_man: usize,
    len_exp: usize,
}

const PARAM_FP_64_BITS: Parameters = Parameters {
    pbsparameters: FINAL_PARAM_64_BIS,
    wopbsparameters: FINAL_WOP_PARAM_64_BIS,
    len_man: LEN_MAN64,
    len_exp: LEN_EXP64,
};

const PARAM_FP_32_BITS: Parameters = Parameters {
    pbsparameters: FINAL_PARAM_32_BIS,
    wopbsparameters: FINAL_WOP_PARAM_32_BIS,
    len_man: LEN_MAN32,
    len_exp: LEN_EXP32,
};

const PARAM_FP_16_BITS: Parameters = Parameters {
    pbsparameters: FINAL_PARAM_16_BIS,
    wopbsparameters: FINAL_WOP_PARAM_16_BIS,
    len_man: LEN_MAN16,
    len_exp: LEN_EXP16,
};

const PARAM_FP_8_BITS: Parameters = Parameters {
    pbsparameters: FINAL_PARAM_8_BIS,
    wopbsparameters: FINAL_WOP_PARAM_8_BIS,
    len_man: LEN_MAN8,
    len_exp: LEN_EXP8,
};

const PARAMS: [(&str, Parameters); 1] =
    [
        //named_param!(PARAM_FP_64_BITS),
        named_param!(PARAM_FP_32_BITS),
        //named_param!(PARAM_FP_16_BITS),
        //named_param!(PARAM_FP_8_BITS),
    ];


#[test]
fn test_float_encrypt() {
    for (_, param) in PARAMS {
        let (cks, sks) = gen_keys(
            param.pbsparameters,
            param.wopbsparameters,
            param.len_man,
            param.len_exp,
        );

        print_info(&cks);
        println!("parameters :: {:?}", cks.key.parameters);
        let msg = 1.;

        // Encryption of one message:
        let mut ct = cks.encrypt(msg);
        print_res(&cks, &ct, "decrypt", msg as f32, msg);
        sks.clean_degree(&mut ct);
        print_res(&cks, &ct, "decrypt", msg as f32, msg);
        let res = cks.decrypt(&ct);

        assert_eq!(res, msg);
    }
}

#[test]
pub fn test_float_mul() {
    let mut rng = rand::thread_rng();
    for (name_parameters, param) in PARAMS {
        let (cks, sks) = gen_keys(
            param.pbsparameters,
            param.wopbsparameters,
            param.len_man,
            param.len_exp,
        );
        let msg1 = rng.gen::<f32>() as f64;
        let msg2 = rng.gen::<f32>() as f64;

        let ct1 = cks.encrypt(msg1);
        let ct2 = cks.encrypt(msg2);

        println!("--------------------------");
        println!("---- {name_parameters} ----");
        println!("--------------------------");

        print_res(&cks, &ct1, "ct 1", msg1 as f32, msg1);
        print_res(&cks, &ct2, "ct 2", msg2 as f32, msg2);

        let res = sks.mul_total_parallelized(&mut ct1.clone(), &mut ct2.clone());
        print_res(&cks, &res, "Multiplication", (msg2 * msg1) as f32, msg2 * msg1);

        let res = cks.decrypt(&res);
        assert!(res.abs() < ((msg1 * msg2) * 1.01).abs());
        assert!(res.abs() > ((msg1 * msg2) * 0.99).abs());
    }
}

#[test]
pub fn test_float_div() {
    let mut rng = rand::thread_rng();
    for (name_parameters, param) in PARAMS {
        let (cks, sks) = gen_keys(
            param.pbsparameters,
            param.wopbsparameters,
            param.len_man,
            param.len_exp,
        );

        let msg2 = rng.gen::<f32>() as f64;
        let msg1 = -rng.gen::<f32>() as f64;

        let ct1 = cks.encrypt(msg1);
        let ct2 = cks.encrypt(msg2);

        println!("--------------------------");
        println!("---- {name_parameters} ----");
        println!("--------------------------");

        print_res(&cks, &ct1, "ct1", (msg1) as f32, msg1);
        print_res(&cks, &ct2, "ct2", (msg2) as f32, msg2);

        let mut res = sks.division(&ct1, &ct2);
        print_res(&cks, &res, "Division", (msg1 / msg2) as f32, msg1 / msg2);
        sks.clean_degree(&mut res);
        let res = cks.decrypt(&res);

        assert!(res.abs() < ((msg1 / msg2) * 1.01).abs());
        assert!(res.abs() > ((msg1 / msg2) * 0.99).abs());
    }
}

#[test]
pub fn float_cos() {
    let mut rng = rand::thread_rng();
    for (name_parameters, param) in PARAMS {
        let (cks, sks) = gen_keys(
            param.pbsparameters,
            param.wopbsparameters,
            param.len_man,
            param.len_exp,
        );

        println!("--------------------------");
        println!("---- {name_parameters} ----");
        println!("--------------------------");
        let msg1 = rng.gen::<f32>() as f64;
        let ct1 = cks.encrypt(msg1);

        let one = cks.encrypt(1.); //should be in trivial encrypt
        let one_div_by_2 = cks.encrypt(1. / 2.); //should be in trivial encrypt
        let one_div_by_24 = cks.encrypt(1. / 24.); //should be in trivial encrypt

        print_res(&cks, &one, "one", 1 as f32, 1.);
        print_res(&cks, &one_div_by_2, "oneDivBy2", (1. / 2.) as f32, 1. / 2.);
        print_res(&cks, &one_div_by_24, "oneDivBy24", (1. / 24.) as f32, 1. / 24.);
        print_res(&cks, &ct1, "ct1", msg1 as f32, msg1);


        let ct1_square = sks.mul_total_parallelized(&ct1, &ct1);
        print_res(&cks, &ct1_square, "ct1_square", (msg1 * msg1) as f32, msg1 * msg1);

        let ct1_square_square = sks.mul_total_parallelized(&ct1_square, &ct1_square);
        print_res(&cks, &ct1_square_square, "ct1_square_square", (msg1 * msg1 * msg1 * msg1) as f32, msg1 * msg1 * msg1 * msg1);

        let ct1_square_time_one_div_by_2 = sks.mul_total_parallelized(&ct1_square, &one_div_by_2);
        print_res(&cks, &ct1_square_time_one_div_by_2, "ct1_square_time_1DivBy2", (msg1 * msg1 / 2.) as f32, msg1 * msg1 / 2.);

        let ct1_square_square_time_one_div_by_24 = sks.mul_total_parallelized(&ct1_square_square, &one_div_by_24);
        print_res(&cks, &ct1_square_square_time_one_div_by_24, "ct1_square_square_time_1DivBy24", (msg1 * msg1 * msg1 * msg1 / 24.) as f32, msg1 * msg1 * msg1 * msg1 / 24.);

        let res = sks.add_total_parallelized(&one, &ct1_square_square_time_one_div_by_24);
        print_res(&cks, &res, "first res", (1. + msg1 * msg1 * msg1 * msg1 / 24.) as f32, 1. + msg1 * msg1 * msg1 * msg1 / 24.);


        let res = sks.sub_total_parallelized(&res, &ct1_square_time_one_div_by_2);
        println!("Cosine, exact result  : {:?}", msg1.cos());
        print_res(&cks, &res, "Cosine approximation", (1. + msg1 * msg1 * msg1 * msg1 / 24. - msg1 * msg1 / 2.) as f32, 1. + msg1 * msg1 * msg1 * msg1 / 24. - msg1 * msg1 / 2.);

        let res = cks.decrypt(&res);
        assert!(res < (msg1.cos() * 1.01).abs());
        assert!(res > (msg1.cos() * 0.99).abs());
    }
}

#[test]
pub fn float_sin() {
    let mut rng = rand::thread_rng();
    for (name_parameters, param) in PARAMS {
        let (cks, sks) = gen_keys(
            param.pbsparameters,
            param.wopbsparameters,
            param.len_man,
            param.len_exp,
        );

        println!("--------------------------");
        println!("---- {name_parameters} ----");
        println!("--------------------------");

        let msg1 = rng.gen::<f32>() as f64;
        let ct1 = cks.encrypt(msg1);

        print_res(&cks, &ct1, "ct1", msg1 as f32, msg1);

        let one_div_by_6 = cks.encrypt(1. / 6.); //should be in trivial encrypt
        let one_div_by_120 = cks.encrypt(1. / 120.); //should be in trivial encrypt

        let ct1_square = sks.mul_total_parallelized(&ct1, &ct1);
        print_res(&cks, &ct1_square, "ct1_square", (msg1 * msg1) as f32, msg1 * msg1);

        let ct1_cube = sks.mul_total_parallelized(&ct1_square, &ct1);
        print_res(&cks, &ct1_cube, "ct1_cube", (msg1 * msg1 * msg1) as f32, msg1 * msg1 * msg1);

        let ct1_power_five = sks.mul_total_parallelized(&ct1_square, &ct1_cube);
        print_res(&cks, &ct1_power_five, "ct1_power_five", (msg1 * msg1 * msg1 * msg1 * msg1) as f32, msg1 * msg1 * msg1 * msg1 * msg1);


        let ct1_cube_time_one_div_by_6 = sks.mul_total_parallelized(&ct1_cube, &one_div_by_6);
        print_res(&cks, &ct1_cube_time_one_div_by_6, "ct1_cube_time_one_div_by_6", (msg1 * msg1 * msg1 / 6.) as f32, msg1 * msg1 * msg1 / 6.);

        let ct1_power_five_time_one_div_by_120 = sks.mul_total_parallelized(&ct1_power_five, &one_div_by_120);
        print_res(&cks, &ct1_power_five_time_one_div_by_120, "ct1_power_five_time_one_div_by_120", (msg1 * msg1 * msg1 * msg1 * msg1 / 120.) as f32, msg1 * msg1 * msg1 * msg1 * msg1 / 120.);


        let res = sks.add_total_parallelized(&ct1, &ct1_power_five_time_one_div_by_120);
        print_res(&cks, &ct1_power_five_time_one_div_by_120, "res_1", (msg1 * msg1 * msg1 * msg1 * msg1 / 120.) as f32, msg1 * msg1 * msg1 * msg1 * msg1 / 120.);

        let res = sks.sub_total_parallelized(&res, &ct1_cube_time_one_div_by_6);

        println!("Sine, exact result  : {:?}", msg1.sin());
        print_res(&cks, &res, "Sine approximation", ((msg1 + (msg1 * msg1 * msg1 * msg1 * msg1 / 120.)) - (msg1 * msg1 * msg1 / 6.)) as f32, msg1 + msg1 * msg1 * msg1 * msg1 * msg1 / 120. - msg1 * msg1 * msg1 / 6.);

        let res = cks.decrypt(&res);
        assert!(res < (msg1.sin() * 1.01).abs());
        assert!(res > (msg1.sin() * 0.99).abs());
    }
}

#[test]
pub fn test_float_add() {
    let mut rng = rand::thread_rng();
    for (name_parameters, param) in PARAMS {
        let (cks, sks) = gen_keys(
            param.pbsparameters,
            param.wopbsparameters,
            param.len_man,
            param.len_exp,
        );

        println!("--------------------------");
        println!("---- {name_parameters} ----");
        println!("--------------------------");

        let msg2 = rng.gen::<f32>() as f64;
        let msg1 = rng.gen::<f32>() as f64;

        let ct1 = cks.encrypt(msg1);
        let ct2 = cks.encrypt(msg2);

        print_res(&cks, &ct1, "ct 1", msg1 as f32, msg1);
        print_res(&cks, &ct2, "ct 2", msg2 as f32, msg2);

        let res = sks.add_total_parallelized(&ct1, &ct2);

        print_res(&cks, &res, "Addition", (msg1 + msg2) as f32, msg1 + msg2);

        let res = cks.decrypt(&res);
        assert!(res.abs() < ((msg1 + msg2) * 1.01).abs());
        assert!(res.abs() > ((msg1 + msg2) * 0.99).abs());
    }
}

#[test]
pub fn test_float_sub() {
    let mut rng = rand::thread_rng();
    for (name_parameters, param) in PARAMS {
        let (cks, sks) = gen_keys(
            param.pbsparameters,
            param.wopbsparameters,
            param.len_man,
            param.len_exp,
        );

        println!("--------------------------");
        println!("---- {name_parameters} ----");
        println!("--------------------------");


        let msg1 = rng.gen::<f32>() as f64;
        let msg2 = rng.gen::<f32>() as f64;

        let ct1 = cks.encrypt(msg1);
        let ct2 = cks.encrypt(msg2);


        print_res(&cks, &ct1, "ct 1", msg1 as f32, msg1);
        print_res(&cks, &ct2, "ct 2", msg2 as f32, msg2);
        let res = sks.sub_total_parallelized(&ct1, &ct2);

        print_res(&cks, &res, "Subtraction", (msg1 - msg2) as f32, msg1 - msg2);

        let res = cks.decrypt(&res);
        assert!(res.abs() < ((msg1 - msg2) * 1.01).abs());
        assert!(res.abs() > ((msg1 - msg2) * 0.99).abs());
    }
}

#[test]
pub fn float_long_run_details_parallelized() {
    let mut rng = rand::thread_rng();
    for (name_parameters, param) in PARAMS {
        let (cks, sks) = gen_keys(
            param.pbsparameters,
            param.wopbsparameters,
            param.len_man,
            param.len_exp,
        );

        println!("--------------------------");
        println!("---- {name_parameters} ----");
        println!("--------------------------");

        let max_i = 1_000.;

        let mut vec_float_32 = vec![];
        let mut vec_float_64 = vec![];
        let mut vec_hom_float = vec![];
        let mut vec_deep = vec![];
        let mut vec_nb_operation = vec![];

        let len_vec = 3 as u16;
        for i in 0..len_vec {
            let msg = rng.gen::<f32>() as f64;
            println!("msg_{:?}: {:?}", i, msg);
            let ct = cks.encrypt(msg);
            print_res(&cks, &ct, "encrypt/decrypt", msg as f32, msg);

            vec_float_64.push(msg);
            vec_float_32.push(msg as f32);
            vec_hom_float.push(ct);
            vec_deep.push(0);
            vec_nb_operation.push(0);
        }

        for i in 0..NB_OPE {
            println!("\n----Round {:?}----", i);
            let r_ope = rng.gen::<u16>() % 3;
            let r_value_1 = (rng.gen::<u16>() % len_vec) as usize;
            let mut r_value_2 = (rng.gen::<u16>() % len_vec) as usize;
            let mut r_place = (rng.gen::<u16>() % 2) as usize;
            while r_value_1 == r_value_2 {
                r_value_2 = (rng.gen::<u16>() % len_vec) as usize;
            }
            if r_place == 0 {
                r_place = r_value_1
            } else {
                r_place = r_value_2
            }

            vec_deep[r_place] = min(vec_deep[r_value_1], vec_deep[r_value_2]) + 1;
            vec_nb_operation[r_place] =
                max(vec_nb_operation[r_value_1], vec_nb_operation[r_value_2]) + 1;
            if r_ope == 0 {
                println!(
                    "block {:?} * block {:?} -> block{:?}\n",
                    r_value_1, r_value_2, r_place
                );
                println!(
                    "expected: {:?} * {:?} = {:?}",
                    vec_float_64[r_value_1],
                    vec_float_64[r_value_2],
                    vec_float_64[r_value_1] * vec_float_64[r_value_2]
                );
                vec_hom_float[r_place] = sks.mul_total_parallelized(
                    &mut vec_hom_float[r_value_1].clone(),
                    &mut vec_hom_float[r_value_2].clone(),
                );
                vec_float_32[r_place] = vec_float_32[r_value_1] * vec_float_32[r_value_2];
                vec_float_64[r_place] = vec_float_64[r_value_1] * vec_float_64[r_value_2];

                print_res(
                    &cks,
                    &vec_hom_float[r_place],
                    "res mul",
                    vec_float_32[r_place],
                    vec_float_64[r_place],
                );
            } else if r_ope == 1 {
                println!(
                    "block {:?} + block {:?} -> block{:?}\n",
                    r_value_1, r_value_2, r_place
                );
                println!(
                    "expected: {:?} + {:?} = {:?}",
                    vec_float_64[r_value_1],
                    vec_float_64[r_value_2],
                    vec_float_64[r_value_1] + vec_float_64[r_value_2]
                );

                vec_hom_float[r_place] =
                    sks.add_total_parallelized(&vec_hom_float[r_value_1], &vec_hom_float[r_value_2]);
                vec_float_32[r_place] = vec_float_32[r_value_1] + vec_float_32[r_value_2];
                vec_float_64[r_place] = vec_float_64[r_value_1] + vec_float_64[r_value_2];
                print_res(
                    &cks,
                    &vec_hom_float[r_place],
                    "res add",
                    vec_float_32[r_place],
                    vec_float_64[r_place],
                );
            } else {
                println!(
                    "block {:?} - block {:?} -> block{:?}\n",
                    r_value_1, r_value_2, r_place
                );
                println!(
                    "expected: {:?} - {:?} = {:?}",
                    vec_float_64[r_value_1],
                    vec_float_64[r_value_2],
                    vec_float_64[r_value_1] - vec_float_64[r_value_2]
                );

                vec_hom_float[r_place] =
                    sks.sub_total_parallelized(&vec_hom_float[r_value_1], &vec_hom_float[r_value_2]);
                vec_float_32[r_place] = vec_float_32[r_value_1] - vec_float_32[r_value_2];
                vec_float_64[r_place] = vec_float_64[r_value_1] - vec_float_64[r_value_2];
                print_res(
                    &cks,
                    &vec_hom_float[r_place],
                    "res sub",
                    vec_float_32[r_place],
                    vec_float_64[r_place],
                );
            }
            if vec_float_64[r_value_1].abs() > max_i {
                let msg_tmp = (1. / max_i) * rng.gen::<f32>() as f64; // 1. / (vec_float_64[r_value_1].abs() + vec_float_64[r_value_2].clone().abs() );
                let mut ct_tmp = cks.encrypt(msg_tmp);

                println!(
                    "block {:?} * {:?} -> block{:?}\n",
                    r_value_1, msg_tmp, r_value_1
                );
                println!(
                    "expected: {:?} * {:?} = {:?}",
                    vec_float_64[r_value_1],
                    msg_tmp,
                    vec_float_64[r_value_1] * msg_tmp
                );

                vec_hom_float[r_place] =
                    sks.mul_total_parallelized(&mut vec_hom_float[r_value_1].clone(), &mut ct_tmp);
                vec_float_32[r_value_1] = vec_float_32[r_value_1] * msg_tmp as f32;
                vec_float_64[r_value_1] = vec_float_64[r_value_1] * msg_tmp;
                vec_nb_operation[r_value_1] += 1;

                print_res(
                    &cks,
                    &vec_hom_float[r_place],
                    "res mul",
                    vec_float_32[r_place],
                    vec_float_64[r_place],
                );
            }
            if vec_float_64[r_value_2].abs() > max_i {
                let msg_tmp = (1. / max_i) * rng.gen::<f32>() as f64; // 1. / (vec_float_64[r_value_1].abs() + vec_float_64[r_value_2].clone().abs() );
                let mut ct_tmp = cks.encrypt(msg_tmp);

                println!(
                    "block {:?} * {:?} -> block{:?}\n",
                    r_value_2, msg_tmp, r_value_2
                );
                println!(
                    "expected: {:?} * {:?} = {:?}",
                    vec_float_64[r_value_1],
                    msg_tmp,
                    vec_float_64[r_value_1] * msg_tmp
                );

                vec_hom_float[r_value_2] =
                    sks.mul_total_parallelized(&mut vec_hom_float[r_value_2].clone(), &mut ct_tmp);
                vec_float_32[r_value_2] = vec_float_32[r_value_2] * msg_tmp as f32;
                vec_float_64[r_value_2] = vec_float_64[r_value_2] * msg_tmp;
                vec_nb_operation[r_value_2] += 1;

                print_res(
                    &cks,
                    &vec_hom_float[r_place],
                    "res mul",
                    vec_float_32[r_place],
                    vec_float_64[r_place],
                );
            }

            if vec_float_64[r_value_1].abs() < 1. / max_i {
                let msg_tmp = max_i * rng.gen::<f32>() as f64; // 1. / (vec_float_64[r_value_1].abs() + vec_float_64[r_value_2].clone().abs() );
                let mut ct_tmp = cks.encrypt(msg_tmp);

                println!(
                    "block {:?} * {:?} -> block{:?}\n",
                    r_value_1, msg_tmp, r_value_1
                );
                println!(
                    "expected: {:?} * {:?} = {:?}",
                    vec_float_64[r_value_1],
                    msg_tmp,
                    vec_float_64[r_value_1] * msg_tmp
                );

                vec_hom_float[r_value_1] =
                    sks.mul_total_parallelized(&mut vec_hom_float[r_value_1].clone(), &mut ct_tmp);
                vec_float_32[r_value_1] = vec_float_32[r_value_1] * msg_tmp as f32;
                vec_float_64[r_value_1] = vec_float_64[r_value_1] * msg_tmp;
                vec_nb_operation[r_value_1] += 1;

                print_res(
                    &cks,
                    &vec_hom_float[r_place],
                    "res mul",
                    vec_float_32[r_place],
                    vec_float_64[r_place],
                );
            }
            if vec_float_64[r_value_2].abs() < 1. / max_i {
                let msg_tmp = max_i * rng.gen::<f32>() as f64; // 1. / (vec_float_64[r_value_1].abs() + vec_float_64[r_value_2].clone().abs() );
                let mut ct_tmp = cks.encrypt(msg_tmp);

                println!(
                    "block {:?} * {:?} -> block{:?}\n",
                    r_value_2, msg_tmp, r_value_2
                );
                println!(
                    "expected: {:?} * {:?} = {:?}",
                    vec_float_64[r_value_1],
                    msg_tmp,
                    vec_float_64[r_value_1] * msg_tmp
                );

                vec_hom_float[r_value_2] =
                    sks.mul_total_parallelized(&mut vec_hom_float[r_value_2].clone(), &mut ct_tmp);
                vec_float_32[r_value_2] = vec_float_32[r_value_2] * msg_tmp as f32;
                vec_float_64[r_value_2] = vec_float_64[r_value_2] * msg_tmp;
                vec_nb_operation[r_value_2] += 1;

                print_res(
                    &cks,
                    &vec_hom_float[r_place],
                    "res mul",
                    vec_float_32[r_place],
                    vec_float_64[r_place],
                );
            }
            println!("----End Round {:?}----", i);
            println!("--------------------");
            println!("--------------------");
            println!("--------------------");
        }

        for i in 0..len_vec as usize {
            println!("------");
            print_res(
                &cks,
                &vec_hom_float[i],
                "Final result",
                vec_float_32[i],
                vec_float_64[i],
            );
            //println!("Deep : {:?}", vec_deep[i]);
            //println!("Ope  : {:?}", vec_nb_operation[i]);

            let res = cks.decrypt(&vec_hom_float[i]);
            assert!(res.abs() < (vec_float_64[i] * 1.01).abs());
            assert!(res.abs() > (vec_float_64[i] * 0.99).abs());
            //println!("------");
        }
        //println!("Info :");
        //println!("len mantissa      : {:?}", LEN_MAN);
        //println!("len exponent      : {:?}", LEN_EXP);
        //println!("number operations : {:?}", NB_OPE);
    }
}

#[test]
pub fn float_same_as_ls_22_32() {
    let (cks, sks) = gen_keys(
        PARAM_MESSAGE_2_CARRY_2_32,
        WOP_PARAM_MESSAGE_2_CARRY_2_32,
        LEN_MAN32,
        LEN_EXP32,
    );
    print_info(&cks);
    let msg1 = -2.7914999921796382_e-15;
    let ct1 = cks.encrypt(msg1);
    print_res(&cks, &ct1, "Encrypt/Decrypt", msg1 as f32, msg1);

    let msg2 = 8.3867001884896375_e-12;
    let ct2 = cks.encrypt(msg2);
    print_res(&cks, &ct2, "Encrypt/Decrypt", msg2 as f32, msg2);

    let msg3 = 1.82634005135360_e14;
    let ct3 = cks.encrypt(msg3);
    print_res(&cks, &ct3, "Encrypt/Decrypt", msg3 as f32, msg3);

    let msg4 = -6.278269952_e9;
    let ct4 = cks.encrypt(msg4);
    print_res(&cks, &ct4, "Encrypt/Decrypt", msg4 as f32, msg4);

    let res_1 =  sks.add_total_parallelized(&ct1, &ct2);
    print_res(
        &cks,
        &res_1,
        "res add",
        msg1 as f32 + msg2 as f32,
        msg1 + msg2,
    );

    let res_2 = sks.sub_total_parallelized(&ct3, &ct4);
    print_res(
        &cks,
        &res_2,
        "res add",
        msg3 as f32 - msg4 as f32,
        msg3 - msg4,
    );

    let mut witness32 = (msg3 as f32 - msg4 as f32) * (msg1 as f32 + msg2 as f32);
    let mut witness64 = (msg3 - msg4) * (msg1 + msg2);
    let res = sks.mul_total_parallelized(&res_1, &res_2);
    print_res(&cks, &res, "res mul", witness32, witness64);

    let res = sks.mul_total_parallelized(&res, &res);
    witness32 *= witness32;
    witness64 *= witness64;
    print_res(&cks, &res, "res mul", witness32, witness64);
    let res = cks.decrypt(&res);

    assert!(res.abs() < ((witness32 * 1.01 as f32) as f64).abs());
    assert!(res.abs() > ((witness32 * 0.99 as f32) as f64).abs());
}

#[test]
pub fn float_same_as_ls_22_64() {
    let (cks, sks) = gen_keys(
        PARAM_MESSAGE_2_CARRY_2_64,
        WOP_PARAM_MESSAGE_2_CARRY_2_64,
        LEN_MAN64,
        LEN_EXP64,
    );

    print_info(&cks);
    let msg1 = -9.1763514236254290_e-32;
    let ct1 = cks.encrypt(msg1);
    print_res(&cks, &ct1, "Encrypt/Decrypt", msg1 as f32, msg1);

    let msg2 = 6.2467247246375865_e-24;
    let ct2 = cks.encrypt(msg2);
    print_res(&cks, &ct2, "Encrypt/Decrypt", msg2 as f32, msg2);

    let msg3 = 2.4523526872362373_e22;
    let ct3 = cks.encrypt(msg3);
    print_res(&cks, &ct3, "Encrypt/Decrypt", msg3 as f32, msg3);

    let msg4 = -5.4324663335297274_e17;
    let ct4 = cks.encrypt(msg4);
    print_res(&cks, &ct4, "Encrypt/Decrypt", msg4 as f32, msg4);

    let res_1 = sks.add_total_parallelized(&ct1, &ct2);
    print_res(
        &cks,
        &res_1,
        "res add",
        msg1 as f32 + msg2 as f32,
        msg1 + msg2,
    );

    let res_2 = sks.sub_total_parallelized(&ct3, &ct4);
    print_res(
        &cks,
        &res_2,
        "res add",
        msg3 as f32 - msg4 as f32,
        msg3 - msg4,
    );

    let mut witness32 = (msg3 as f32 - msg4 as f32) * (msg1 as f32 + msg2 as f32);
    let mut witness64 = (msg3 - msg4) * (msg1 + msg2);
    let res = sks.mul_total_parallelized(&res_1, &res_2);
    print_res(&cks, &res, "res mul", witness32, witness64);

    let res = sks.mul_total_parallelized(&res, &res);
    witness32 *= witness32;
    witness64 *= witness64;
    print_res(&cks, &res, "res mul", witness32, witness64);
    let res = cks.decrypt(&res);

    assert!(res.abs() < (witness64 * 1.01).abs());
    assert!(res.abs() > (witness64 * 0.99).abs());
}

#[test]
pub fn test_float_relu() {
    let mut rng = rand::thread_rng();
    for (name_parameters, param) in PARAMS {
        let (cks, sks) = gen_keys(
            param.pbsparameters,
            param.wopbsparameters,
            param.len_man,
            param.len_exp,
        );

        println!("--------------------------");
        println!("---- {name_parameters} ----");
        println!("--------------------------");

        let msg = rng.gen::<f32>() as f64 - rng.gen::<f32>() as f64;
        let ct = cks.encrypt(msg);
        print_res(&cks, &ct, "decrypt", msg as f32, msg);
        let res = sks.relu(&ct);
        print_res(&cks, &res, "relu", 0.0_f32.max(msg as f32), msg.max(0.));
        let res = cks.decrypt(&res);
        assert_eq!(res, msg.max(0.));
    }

}

#[test]
pub fn test_float_sigmoid() {
    let mut rng = rand::thread_rng();
    for (name_parameters, param) in PARAMS {
        let (cks, sks) = gen_keys(
            param.pbsparameters,
            param.wopbsparameters,
            param.len_man,
            param.len_exp,
        );

        println!("--------------------------");
        println!("---- {name_parameters} ----");
        println!("--------------------------");


        let msg = (rng.gen::<f32>() as f64 + 0.4).abs();
        let ct = cks.encrypt(msg);
        print_res(&cks, &ct, "ct", msg as f32, msg);
        let res = sks.sigmoid(&ct);
        print_res(&cks, &res, "approx sigmoid", 1.0_f32.min(msg as f32), msg.min(1.));
        let res = cks.decrypt(&res);

        assert!(res > msg.min(1.) * 0.9);
        assert!(res < msg.min(1.) * 1.1);
    }
}

pub fn print_res(
    cks: &ClientKey,
    ct: &Ciphertext,
    operation: &str,
    witness32: f32,
    witness64: f64,
) {
    println!("\n--------------------",);
    println!("{:?}:\n", operation);
    println!("Result       : {:?}", cks.decrypt(&ct));
    println!("Clear 32-bits: {:?}", witness32);
    println!("Clear 64-bits: {:?}\n", witness64);
    println!("--------------------");
}

pub fn print_info(cks: &ClientKey) {
    println!("\n-----Info-----");
    println!("length exp {:?}", cks.vector_length_exponent);
    println!("length man {:?}", cks.vector_length_mantissa);
    let msg_modulus = cks.parameters().message_modulus().0;
    let car_modulus = cks.parameters().carry_modulus().0;
    println!("msg modulus       {:?}, 0b{:b}", msg_modulus, msg_modulus);
    println!("car modulus       {:?}, 0b{:b}", car_modulus, car_modulus);
    println!(
        "total space       {:?}, 0b{:b}",
        car_modulus * msg_modulus,
        car_modulus * msg_modulus
    );
    let log_msg_modulus = f64::log2(msg_modulus as f64) as usize;
    let bias = -((1 << (cks.vector_length_exponent.0 * log_msg_modulus - 1)) as i64)
        - (cks.vector_length_mantissa.0 as i64 - 1);
    println!("Bias              {:?}", bias);
    println!("--------------\n");
}
