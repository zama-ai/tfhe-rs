#![allow(dead_code)]

use concrete_float::gen_keys;
use criterion::{criterion_group, criterion_main, Criterion};
use rand::Rng;

// Previous Parameters
#[allow(unused_imports)]
use concrete_float::parameters::{FINAL_PARAM_16,
                                 FINAL_PARAM_2_2_32, FINAL_PARAM_32,
                                 FINAL_PARAM_64, FINAL_PARAM_8,
                                 FINAL_WOP_PARAM_15, FINAL_WOP_PARAM_16,
                                 FINAL_WOP_PARAM_2_2_32, FINAL_WOP_PARAM_32,
                                 FINAL_WOP_PARAM_64, FINAL_WOP_PARAM_8,
                                 FINAL_PARAM_64_TCHESS, FINAL_PARAM_32_TCHESS,
                                 FINAL_WOP_PARAM_64_TCHESS, FINAL_WOP_PARAM_32_TCHESS};

use concrete_float::parameters::{FINAL_PARAM_16_BIS, FINAL_PARAM_32_BIS,
                                 FINAL_PARAM_64_BIS, FINAL_PARAM_8_BIS,
                                 FINAL_WOP_PARAM_16_BIS, FINAL_WOP_PARAM_32_BIS,
                                 FINAL_WOP_PARAM_64_BIS, FINAL_WOP_PARAM_8_BIS};
use tfhe::shortint;

macro_rules! named_param {
    ($param:ident) => {
        (stringify!($param), $param)
    };
}

criterion_main!(float_parallelized, float);

struct Parameters {
    pbsparameters: shortint::ClassicPBSParameters,
    wopbsparameters: shortint::WopbsParameters,
    len_man: usize,
    len_exp: usize,
}

//Parameter for a Floating point 64-bits equivalent
const PARAM_64: Parameters = Parameters {
    pbsparameters: FINAL_PARAM_64_BIS,
    wopbsparameters: FINAL_WOP_PARAM_64_BIS,
    len_man: 27,
    len_exp: 5,
};


//Parameter for a Floating point 32-bits equivalent
const PARAM_32: Parameters = Parameters {
    pbsparameters: FINAL_PARAM_32_BIS,
    wopbsparameters: FINAL_WOP_PARAM_32_BIS,
    len_man: 13,
    len_exp: 4,
};


//Parameter for a Floating point 16-bits equivalent
const PARAM_16: Parameters = Parameters {
    pbsparameters: FINAL_PARAM_16_BIS,
    wopbsparameters: FINAL_WOP_PARAM_16_BIS,
    len_man: 6,
    len_exp: 3,
};


//Parameter for a Floating point 8-bits equivalent
const PARAM_8: Parameters = Parameters {
    pbsparameters: FINAL_PARAM_8_BIS,
    wopbsparameters: FINAL_WOP_PARAM_8_BIS,
    len_man: 3,
    len_exp: 2,
};


//Parameter for a Floating point 64-bits equivalent
//With failure probability smaller than PARAM_64
const PARAM_TCHESS_64: Parameters = Parameters {
    pbsparameters: FINAL_PARAM_64_TCHESS,
    wopbsparameters: FINAL_WOP_PARAM_64_TCHESS,
    len_man: 27,
    len_exp: 5,
};


//Parameter for a Floating point 32-bits equivalent
//With failure probability smaller than PARAM_32
const PARAM_TCHESS_32: Parameters = Parameters {
    pbsparameters: FINAL_PARAM_32_TCHESS,
    wopbsparameters: FINAL_WOP_PARAM_32_TCHESS,
    len_man: 13,
    len_exp: 4,
};


const SERVER_KEY_BENCH_PARAMS: [(&str, Parameters);6] =
    [
        named_param!(PARAM_8),
        named_param!(PARAM_16),
        named_param!(PARAM_32),
        named_param!(PARAM_64),
        named_param!(PARAM_TCHESS_32),
        named_param!(PARAM_TCHESS_64),
    ];

criterion_group!(
    float,
    add,
    mul,
    relu,
    sigmoid,
);

criterion_group!(
    float_parallelized,
    add_parallelized,
    mul_parallelized,
    div_parallelized,,
);


fn relu(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("operation");
    let mut rng = rand::thread_rng();

    for (param_name, param) in SERVER_KEY_BENCH_PARAMS {
        let (cks, sks) = gen_keys(
            param.pbsparameters,
            param.wopbsparameters,
            param.len_man,
            param.len_exp,
        );

        let msg = rng.gen::<f32>() as f64;
        let ct = cks.encrypt(msg);

        let bench_id = format!("{}::{}", "Relu", param_name);
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                sks.relu(&ct);
            })
        });
    }
    bench_group.finish()
}

fn sigmoid(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("operation");
    let mut rng = rand::thread_rng();

    for (param_name, param) in SERVER_KEY_BENCH_PARAMS {
        let (cks, sks) = gen_keys(
            param.pbsparameters,
            param.wopbsparameters,
            param.len_man,
            param.len_exp,
        );

        let msg = rng.gen::<f32>() as f64;
        let ct = cks.encrypt(msg);

        let bench_id = format!("{}::{}", "sigmoid", param_name);
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                sks.sigmoid(&ct);
            })
        });
    }
    bench_group.finish()
}

fn mul(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("operation");
    let mut rng = rand::thread_rng();

    for (param_name, param) in SERVER_KEY_BENCH_PARAMS {
        let (cks, sks) = gen_keys(
            param.pbsparameters,
            param.wopbsparameters,
            param.len_man,
            param.len_exp,
        );

        let msg = rng.gen::<f32>() as f64;
        let ct1 = cks.encrypt(msg);
        let msg = rng.gen::<f32>() as f64;
        let ct2 = cks.encrypt(msg);

        let bench_id = format!("{}::{}", "mul", param_name);
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                sks.mul_total(&ct1, &ct2);
            })
        });
    }
    bench_group.finish()
}

fn mul_parallelized(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("operation");
    let mut rng = rand::thread_rng();

    for (param_name, param) in SERVER_KEY_BENCH_PARAMS {
        let (cks, sks) = gen_keys(
            param.pbsparameters,
            param.wopbsparameters,
            param.len_man,
            param.len_exp,
        );

        let msg = rng.gen::<f32>() as f64;
        let ct1 = cks.encrypt(msg);
        let msg = rng.gen::<f32>() as f64;
        let ct2 = cks.encrypt(msg);

        let bench_id = format!("{}::{}", "mul parallelized", param_name);
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                sks.mul_total_parallelized(&ct1, &ct2);
            })
        });
    }
    bench_group.finish()
}

fn div_parallelized(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("operation");
    let mut rng = rand::thread_rng();

    for (param_name, param) in SERVER_KEY_BENCH_PARAMS {
        let (cks, sks) = gen_keys(
            param.pbsparameters,
            param.wopbsparameters,
            param.len_man,
            param.len_exp,
        );

        let msg = rng.gen::<f32>() as f64;
        let ct1 = cks.encrypt(msg);
        let msg = rng.gen::<f32>() as f64;
        let ct2 = cks.encrypt(msg);

        let bench_id = format!("{}::{}", "div parallelized", param_name);
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                sks.division(&ct1, &ct2);
            })
        });
    }
    bench_group.finish()
}

fn add(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("operation");
    let mut rng = rand::thread_rng();

    for (param_name, param) in SERVER_KEY_BENCH_PARAMS {
        let (cks, sks) = gen_keys(
            param.pbsparameters,
            param.wopbsparameters,
            param.len_man,
            param.len_exp,
        );

        let msg = rng.gen::<f32>() as f64;
        let ct1 = cks.encrypt(msg);
        let msg = rng.gen::<f32>() as f64;
        let ct2 = cks.encrypt(msg);

        let bench_id = format!("{}::{}", "add", param_name);
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                sks.add_total(&ct1, &ct2);
            })
        });
    }
    bench_group.finish()
}

fn add_parallelized(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("operation");
    let mut rng = rand::thread_rng();

    for (param_name, param) in SERVER_KEY_BENCH_PARAMS {
        let (cks, sks) = gen_keys(
            param.pbsparameters,
            param.wopbsparameters,
            param.len_man,
            param.len_exp,
        );

        let msg = rng.gen::<f32>() as f64;
        let ct1 = cks.encrypt(msg);
        let msg = rng.gen::<f32>() as f64;
        let ct2 = cks.encrypt(msg);

        let bench_id = format!("{}::{}", "add parallelized", param_name);
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                sks.add_total_parallelized(&ct1, &ct2);
            })
        });
    }
    bench_group.finish()
}
