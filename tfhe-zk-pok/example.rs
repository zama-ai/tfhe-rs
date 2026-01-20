use rand::rngs::StdRng;
use rand::{thread_rng, Rng, SeedableRng};
use tfhe_zk_pok::proofs::pke_v2::*;
use tfhe_zk_pok::proofs::*;

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

type CurveMy = tfhe_zk_pok::curve_api::Bls12_446;

/// q (modulus) is encoded on 64b, with 0 meaning 2^64. This converts the encoded q to its effective
/// value for modular operations.
fn decode_q(q: u64) -> u128 {
    if q == 0 {
        1u128 << 64
    } else {
        q as u128
    }
}

// One of our usecases uses 320 bits of additional metadata
pub const METADATA_LEN: usize = (64 / u8::BITS) as usize;

pub struct PkeTestCiphertext {
    pub c1: Vec<i64>,
    pub c2: Vec<i64>,
}

pub struct PkeTestParameters {
    pub d: usize,
    pub k: usize,
    pub B: u64,
    pub q: u64,
    pub t: u64,
    pub msbs_zero_padding_bit_count: u64,
}

pub const PKEV2_TEST_PARAMS: PkeTestParameters = PkeTestParameters {
    d: 2048,
    k: 32,
    B: 131072, // 2**17
    q: 0,
    t: 32, // 2b msg, 2b carry, 1b padding
    msbs_zero_padding_bit_count: 1,
};

/// A randomly generated testcase of pke encryption
#[derive(Clone)]
pub struct PkeTestcase {
    pub a: Vec<i64>,
    pub e1: Vec<i64>,
    pub e2: Vec<i64>,
    pub r: Vec<i64>,
    pub m: Vec<i64>,
    pub b: Vec<i64>,
    pub metadata: [u8; METADATA_LEN],
    pub s: Vec<i64>,
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

        let a = (0..d).map(|_| rng.gen::<i64>()).collect::<Vec<_>>();

        let s = (0..d)
            .map(|_| (rng.gen::<u64>() % 2) as i64)
            .collect::<Vec<_>>();

        let e = (0..d)
            .map(|_| (rng.gen::<u64>() % (2 * B)) as i64 - B as i64)
            .collect::<Vec<_>>();
        let e1 = (0..d)
            .map(|_| (rng.gen::<u64>() % (2 * B)) as i64 - B as i64)
            .collect::<Vec<_>>();
        let e2 = (0..k)
            .map(|_| (rng.gen::<u64>() % (2 * B)) as i64 - B as i64)
            .collect::<Vec<_>>();

        let r = (0..d)
            .map(|_| (rng.gen::<u64>() % 2) as i64)
            .collect::<Vec<_>>();
        let m = (0..k)
            .map(|_| (rng.gen::<u64>() % effective_cleartext_t) as i64)
            .collect::<Vec<_>>();
        let b = polymul_rev(&a, &s)
            .into_iter()
            .zip(e.iter())
            .map(|(x, e)| x.wrapping_add(*e))
            .collect::<Vec<_>>();

        let mut metadata = [0u8; METADATA_LEN];
        metadata.fill_with(|| rng.gen::<u8>());

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

    /// Encrypt using compact pke, the encryption is validated by doing a decryption
    pub fn encrypt(&self, params: PkeTestParameters) -> PkeTestCiphertext {
        let ct = self.encrypt_unchecked(params);

        ct
    }

    pub fn encrypt_unchecked(&self, params: PkeTestParameters) -> PkeTestCiphertext {
        let PkeTestParameters {
            d,
            k,
            B: _B,
            q,
            t,
            msbs_zero_padding_bit_count: _msbs_zero_padding_bit_count,
        } = params;

        let delta = {
            let q = decode_q(q) as i128;
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

        PkeTestCiphertext { c1, c2 }
    }
}

fn main() {
    let PkeTestParameters {
        d,
        k,
        B,
        q,
        t,
        msbs_zero_padding_bit_count,
    } = PKEV2_TEST_PARAMS;

    // let d = 2048;
    // let k = 32;
    // let B = 131072; // 2**17
    // let q = 0; // 2^64
    // let t = 32; // 2b msg, 2b carry, 1b padding
    // let msbs_zero_padding_bit_count = 1;

    let effective_cleartext_t = t >> msbs_zero_padding_bit_count;

    let seed = thread_rng().gen();
    println!("pkev2 seed: {seed:x}");
    let rng = &mut StdRng::seed_from_u64(seed);

    let testcase = PkeTestcase::gen(rng, PKEV2_TEST_PARAMS);
    let ct = testcase.encrypt(PKEV2_TEST_PARAMS);

    let crs_k = d / (t >> msbs_zero_padding_bit_count) as usize;

    let public_param = crs_gen::<CurveMy>(d, crs_k, B, q, t, msbs_zero_padding_bit_count, rng);

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

    for load in [ComputeLoad::Verify] {
        proof_loop(
            (&public_param, &public_commit),
            &private_commit,
            &testcase.metadata,
            load,
            seed,
            &testcase,
        );
    }
}

#[inline(never)]
fn proof_loop(
    (public_param, public_commit): (&PublicParams<CurveMy>, &PublicCommit<CurveMy>),
    private_commit: &PrivateCommit<CurveMy>,
    metadata: &[u8],
    load: ComputeLoad,
    seed: u64,
    testcase: &PkeTestcase,
) {
    let test_runs = 10;
    let start = std::time::Instant::now();
    for _ in 0..test_runs {
        let proof = prove(
            (public_param, public_commit),
            private_commit,
            &testcase.metadata,
            load,
            &seed.to_le_bytes(),
        );
    }
    let elapsed = start.elapsed();
    println!("total: {elapsed:#?}");
    println!("per run avg: {:#?}", elapsed / test_runs);
}
