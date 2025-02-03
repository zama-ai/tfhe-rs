#![allow(dead_code)]

use criterion::{criterion_group, criterion_main, Criterion};
use tfhe::float_wopbs::gen_keys;

#[allow(unused_imports)]
use tfhe::float_wopbs::parameters::{
    PARAM_MESSAGE_2_16_BITS, PARAM_MESSAGE_4_16_BITS, PARAM_MESSAGE_8_16_BITS,
};
use tfhe::float_wopbs::parameters::{ PARAM_MESSAGE_2_4_8_BITS_BIV, PARAM_MESSAGE_4_2_8_BITS_BIV};
use tfhe::shortint::WopbsParameters;

macro_rules! named_param {
    ($param:ident) => {
        (stringify!($param), $param)
    };
}

struct Parameters {
    parameters: WopbsParameters,
    bit_mantissa: usize,
    bit_exponent: usize,
}


const PARAM_4_BIT_LWE_8_BITS: Parameters = Parameters {
    parameters: PARAM_MESSAGE_2_4_8_BITS_BIV,
    bit_mantissa: 4,
    bit_exponent: 3,
};

const PARAM_2_BIT_LWE_8_BITS: Parameters = Parameters {
    parameters: PARAM_MESSAGE_4_2_8_BITS_BIV,
    bit_mantissa: 4,
    bit_exponent: 3,
};


const SERVER_KEY_BENCH_PARAMS: [(&str, Parameters); 2] =
    [ named_param!(PARAM_4_BIT_LWE_8_BITS),
        named_param!(PARAM_2_BIT_LWE_8_BITS)];

criterion_main!(float);

criterion_group!(float, float_wopbs_bivariate);

pub fn float_wopbs_mut_eval(c: &mut Criterion) {
    for name_param in SERVER_KEY_BENCH_PARAMS {
        let (cks, sks) = gen_keys(name_param.1.parameters);
        let bit_mantissa = &name_param.1.bit_mantissa;
        let bit_exponent = &name_param.1.bit_exponent;
        let e_min = -2;
        let msg_1 = 0.375;

        // Encryption:
        let mut ct_1 = cks.encrypt(msg_1, e_min, *bit_mantissa, *bit_exponent);

        let lut = sks.create_lut(&mut ct_1, |x| x);
        let bench_id = format!("8-bit floats WoP-PBS lut eval::{}", name_param.0);
        c.bench_function(&bench_id, |b| {
            b.iter(|| {
                sks.wop_pbs(&sks, &mut ct_1, &lut);
            })
        });
    }
}

pub fn float_wopbs_bivariate(c: &mut Criterion) {
    for name_param in SERVER_KEY_BENCH_PARAMS {
        let (cks, sks) = gen_keys(name_param.1.parameters);
        let bit_mantissa = &name_param.1.bit_mantissa;
        let bit_exponent = &name_param.1.bit_exponent;

        let e_min = -2;
        let msg_1 = 0.375;

        // Encryption:
        let mut ct_1 = cks.encrypt(msg_1, e_min, *bit_mantissa, *bit_exponent);
        let msg_2 = -44.;
        let mut ct_2 = cks.encrypt(msg_2, e_min, *bit_mantissa, *bit_exponent);

        let lut = sks.create_bivariate_lut(&mut ct_1, |x, y| y * x);
        let bench_id = format!("8-bit floats WoP-PBS bivariate::{}", name_param.0);
        c.bench_function(&bench_id, |b| {
            b.iter(|| {
                sks.wop_pbs_bivariate(&sks, &mut ct_1, &mut ct_2, &lut);
            })
        });
    }
}
