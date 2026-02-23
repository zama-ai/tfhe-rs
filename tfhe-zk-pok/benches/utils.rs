#![allow(non_snake_case)]

use std::fs;
use std::path::PathBuf;

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use serde::Serialize;
use tfhe_zk_pok::proofs::pke::{commit, crs_gen, PrivateCommit, PublicCommit, PublicParams};

use tfhe_zk_pok::proofs::pke_v2::{
    commit as commitv2, crs_gen_cs as crs_genv2_cs, crs_gen_ghl as crs_genv2_ghl, Bound,
    PrivateCommit as PrivateCommitv2, PublicCommit as PublicCommitv2,
    PublicParams as PublicParamsv2,
};

// One of our usecases uses 320 bits of additional metadata
pub const METADATA_LEN: usize = (320 / u8::BITS) as usize;

pub fn polymul_rev(a: &[i64], b: &[i64]) -> Vec<i64> {
    assert_eq!(a.len(), b.len());
    let d = a.len();
    let mut c = vec![0i64; d];

    for i in 0..d {
        for j in 0..d {
            if i + j < d {
                c[i + j] = c[i + j].wrapping_add(a[i].wrapping_mul(b[d - j - 1]));
            } else {
                c[i + j - d] = c[i + j - d].wrapping_sub(a[i].wrapping_mul(b[d - j - 1]));
            }
        }
    }

    c
}

#[derive(Clone, Copy, Default, Serialize)]
pub struct CryptoParametersRecord {
    pub lwe_dimension: usize,
    #[serde(serialize_with = "CryptoParametersRecord::serialize_distribution")]
    pub lwe_noise_distribution: u64,
    pub message_modulus: u64,
    pub carry_modulus: u64,
    pub ciphertext_modulus: u64,
}

impl CryptoParametersRecord {
    pub fn noise_distribution_as_string(bound: u64) -> String {
        format!("TUniform({})", bound.ilog2())
    }

    pub fn serialize_distribution<S>(
        noise_distribution: &u64,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&Self::noise_distribution_as_string(*noise_distribution))
    }
}

#[derive(Serialize)]
enum PolynomialMultiplication {
    Fft,
    // Ntt,
}

#[derive(Serialize)]
enum IntegerRepresentation {
    Radix,
    // Crt,
    // Hybrid,
}

#[derive(Serialize)]
enum ExecutionType {
    Sequential,
    Parallel,
}

#[derive(Serialize)]
enum KeySetType {
    Single,
    // Multi,
}

#[derive(Serialize)]
enum OperandType {
    CipherText,
    PlainText,
}

#[derive(Clone, Serialize)]
pub enum OperatorType {
    Atomic,
    // AtomicPattern,
}

#[derive(Serialize)]
struct BenchmarkParametersRecord {
    display_name: String,
    crypto_parameters_alias: String,
    crypto_parameters: CryptoParametersRecord,
    message_modulus: Option<usize>,
    carry_modulus: Option<usize>,
    ciphertext_modulus: usize,
    bit_size: u32,
    polynomial_multiplication: PolynomialMultiplication,
    precision: u32,
    error_probability: f64,
    integer_representation: IntegerRepresentation,
    decomposition_basis: Vec<u32>,
    pbs_algorithm: Option<String>,
    execution_type: ExecutionType,
    key_set_type: KeySetType,
    operand_type: OperandType,
    operator_type: OperatorType,
}

/// Writes benchmarks parameters to disk in JSON format.
pub fn write_to_json<T: Into<CryptoParametersRecord>>(
    bench_id: &str,
    params: T,
    params_alias: impl Into<String>,
    display_name: impl Into<String>,
) {
    let params = params.into();

    let execution_type = match bench_id.contains("parallelized") {
        true => ExecutionType::Parallel,
        false => ExecutionType::Sequential,
    };
    let operand_type = match bench_id.contains("scalar") {
        true => OperandType::PlainText,
        false => OperandType::CipherText,
    };

    let record = BenchmarkParametersRecord {
        display_name: display_name.into(),
        crypto_parameters_alias: params_alias.into(),
        crypto_parameters: params,
        message_modulus: Some(params.message_modulus as usize),
        carry_modulus: Some(params.carry_modulus as usize),
        ciphertext_modulus: 64,
        bit_size: params.message_modulus as u32,
        polynomial_multiplication: PolynomialMultiplication::Fft,
        precision: (params.message_modulus as u32).ilog2(),
        error_probability: 2f64.powf(-41.0),
        integer_representation: IntegerRepresentation::Radix,
        decomposition_basis: Vec::new(),
        pbs_algorithm: None, // To be added in future version
        execution_type,
        key_set_type: KeySetType::Single,
        operand_type,
        operator_type: OperatorType::Atomic,
    };

    let mut params_directory = ["benchmarks_parameters", bench_id]
        .iter()
        .collect::<PathBuf>();
    fs::create_dir_all(&params_directory).unwrap();
    params_directory.push("parameters.json");

    fs::write(params_directory, serde_json::to_string(&record).unwrap()).unwrap();
}

impl From<PkeTestParameters> for CryptoParametersRecord {
    fn from(value: PkeTestParameters) -> Self {
        let effective = value.t / 2; // Remove padding bit
        let (message_modulus, carry_modulus) = match effective.ilog2() {
            2 => (2, 2),
            4 => (4, 4),
            6 => (8, 8),
            8 => (16, 16),
            _ => panic!("Unsupported parameters for tfhe-zk-pok bench"),
        };

        Self {
            lwe_dimension: value.d,
            lwe_noise_distribution: value.B,
            message_modulus,
            carry_modulus,
            ciphertext_modulus: value.q,
        }
    }
}

/// parameters needed for a PKE zk proof test
#[derive(Copy, Clone)]
pub struct PkeTestParameters {
    pub d: usize,
    pub k: usize,
    pub B: u64,
    pub q: u64,
    pub t: u64,
    pub msbs_zero_padding_bit_count: u64,
}

/// An encrypted PKE ciphertext
pub struct PkeTestCiphertext {
    pub c1: Vec<i64>,
    pub c2: Vec<i64>,
}

/// A randomly generated testcase of pke encryption
pub struct PkeTestcase {
    pub a: Vec<i64>,
    pub e1: Vec<i64>,
    pub e2: Vec<i64>,
    pub r: Vec<i64>,
    pub m: Vec<i64>,
    pub b: Vec<i64>,
    pub metadata: [u8; METADATA_LEN],
    s: Vec<i64>,
}

impl PkeTestcase {
    pub fn gen(rng: &mut StdRng, params: PkeTestParameters) -> Self {
        let PkeTestParameters {
            d,
            k,
            B,
            q: _q,
            t,
            msbs_zero_padding_bit_count,
        } = params;

        let effective_cleartext_t = t >> msbs_zero_padding_bit_count;

        let a = (0..d).map(|_| rng.random::<i64>()).collect::<Vec<_>>();

        let s = (0..d)
            .map(|_| (rng.random::<u64>() % 2) as i64)
            .collect::<Vec<_>>();

        let e = (0..d)
            .map(|_| (rng.random::<u64>() % (2 * B)) as i64 - B as i64)
            .collect::<Vec<_>>();
        let e1 = (0..d)
            .map(|_| (rng.random::<u64>() % (2 * B)) as i64 - B as i64)
            .collect::<Vec<_>>();
        let e2 = (0..k)
            .map(|_| (rng.random::<u64>() % (2 * B)) as i64 - B as i64)
            .collect::<Vec<_>>();

        let r = (0..d)
            .map(|_| (rng.random::<u64>() % 2) as i64)
            .collect::<Vec<_>>();
        let m = (0..k)
            .map(|_| (rng.random::<u64>() % effective_cleartext_t) as i64)
            .collect::<Vec<_>>();
        let b = polymul_rev(&a, &s)
            .into_iter()
            .zip(e.iter())
            .map(|(x, e)| x.wrapping_add(*e))
            .collect::<Vec<_>>();

        let mut metadata = [0u8; METADATA_LEN];
        metadata.fill_with(|| rng.random::<u8>());

        Self {
            a,
            e1,
            e2,
            r,
            m,
            b,
            metadata,
            s,
        }
    }

    /// Encrypt using compact pke
    pub fn encrypt(&self, params: PkeTestParameters) -> PkeTestCiphertext {
        let PkeTestParameters {
            d,
            k,
            B: _B,
            q,
            t,
            msbs_zero_padding_bit_count: _msbs_zero_padding_bit_count,
        } = params;

        let delta = {
            let q = if q == 0 { 1i128 << 64 } else { q as i128 };
            // delta takes the encoding with the padding bit
            (q / t as i128) as u64
        };

        let c1 = polymul_rev(&self.a, &self.r)
            .into_iter()
            .zip(self.e1.iter())
            .map(|(x, e1)| x.wrapping_add(*e1))
            .collect::<Vec<_>>();

        let mut c2 = vec![0i64; k];

        for (i, c2) in c2.iter_mut().enumerate() {
            let mut dot = 0i64;
            for j in 0..d {
                let b = if i + j < d {
                    self.b[d - j - i - 1]
                } else {
                    self.b[2 * d - j - i - 1].wrapping_neg()
                };

                dot = dot.wrapping_add(self.r[d - j - 1].wrapping_mul(b));
            }

            *c2 = dot
                .wrapping_add(self.e2[i])
                .wrapping_add((delta * self.m[i] as u64) as i64);
        }

        // Check decryption
        let mut m_roundtrip = vec![0i64; k];
        for i in 0..k {
            let mut dot = 0i128;
            for j in 0..d {
                let c = if i + j < d {
                    c1[d - j - i - 1]
                } else {
                    c1[2 * d - j - i - 1].wrapping_neg()
                };

                dot += self.s[d - j - 1] as i128 * c as i128;
            }

            let q = if q == 0 { 1i128 << 64 } else { q as i128 };
            let val = ((c2[i] as i128).wrapping_sub(dot)) * t as i128;
            let div = val.div_euclid(q);
            let rem = val.rem_euclid(q);
            let result = div as i64 + (rem > (q / 2)) as i64;
            let result = result.rem_euclid(params.t as i64);
            m_roundtrip[i] = result;
        }

        assert_eq!(self.m, m_roundtrip);

        PkeTestCiphertext { c1, c2 }
    }
}

/// Compact key params used with pkev2
pub const PKEV2_TEST_PARAMS: PkeTestParameters = PkeTestParameters {
    d: 2048,
    k: 1024,
    B: 131072, // 2**17
    q: 0,
    t: 32, // 2b msg, 2b carry, 1b padding
    msbs_zero_padding_bit_count: 1,
};

/// Compact key params used with pkev1
pub const PKEV1_TEST_PARAMS: PkeTestParameters = PkeTestParameters {
    d: 1024,
    k: 1024,
    B: 4398046511104, // 2**42
    q: 0,
    t: 32, // 2b msg, 2b carry, 1b padding
    msbs_zero_padding_bit_count: 1,
};

type Curve = tfhe_zk_pok::curve_api::Bls12_446;

#[allow(unused)]
pub fn init_params_v1(
    test_params: PkeTestParameters,
) -> (
    PublicParams<Curve>,
    PublicCommit<Curve>,
    PrivateCommit<Curve>,
    [u8; METADATA_LEN],
) {
    let PkeTestParameters {
        d,
        k,
        B,
        q,
        t,
        msbs_zero_padding_bit_count,
    } = test_params;

    let rng = &mut StdRng::seed_from_u64(0);

    let testcase = PkeTestcase::gen(rng, test_params);

    let ct = testcase.encrypt(test_params);

    let public_param = crs_gen::<Curve>(d, k, B, q, t, msbs_zero_padding_bit_count, rng);

    let (public_commit, private_commit) = commit(
        testcase.a.clone(),
        testcase.b.clone(),
        ct.c1.clone(),
        ct.c2.clone(),
        testcase.r.clone(),
        testcase.e1.clone(),
        testcase.m.clone(),
        testcase.e2.clone(),
        &public_param,
    );

    (
        public_param,
        public_commit,
        private_commit,
        testcase.metadata,
    )
}

#[allow(unused)]
pub fn init_params_v2(
    test_params: PkeTestParameters,
    bound: Bound,
) -> (
    PublicParamsv2<Curve>,
    PublicCommitv2<Curve>,
    PrivateCommitv2<Curve>,
    [u8; METADATA_LEN],
) {
    let PkeTestParameters {
        d,
        k,
        B,
        q,
        t,
        msbs_zero_padding_bit_count,
    } = test_params;

    let rng = &mut StdRng::seed_from_u64(0);

    let testcase = PkeTestcase::gen(rng, test_params);

    let ct = testcase.encrypt(test_params);

    let public_param = match bound {
        Bound::GHL => crs_genv2_ghl::<Curve>(d, k, B, q, t, msbs_zero_padding_bit_count, rng),
        Bound::CS => crs_genv2_cs::<Curve>(d, k, B, q, t, msbs_zero_padding_bit_count, rng),
    };

    let (public_commit, private_commit) = commitv2(
        testcase.a.clone(),
        testcase.b.clone(),
        ct.c1.clone(),
        ct.c2.clone(),
        testcase.r.clone(),
        testcase.e1.clone(),
        testcase.m.clone(),
        testcase.e2.clone(),
        &public_param,
    );

    (
        public_param,
        public_commit,
        private_commit,
        testcase.metadata,
    )
}
