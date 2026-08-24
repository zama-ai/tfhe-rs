use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey};
use crate::shortint::parameters::TestParameters;
use std::sync::Arc;

// Plaintext model of the apps/princev2 FHE circuit (shortints as u8),
// self-validated against the [BEK+20] KATs so it cannot silently agree with
// a GPU bug

const PV2_S: [u8; 16] = [
    0xb, 0xf, 0x3, 0x2, 0xa, 0xc, 0x9, 0x1, 0x6, 0x7, 0x8, 0x0, 0xe, 0x5, 0xd, 0x4,
];
const PV2_IS: [u8; 16] = [
    0xb, 0x7, 0x3, 0x2, 0xf, 0xd, 0x8, 0x9, 0xa, 0x6, 0x4, 0x0, 0x5, 0xe, 0xc, 0x1,
];

const PRINCE_NRND: usize = 12;
#[rustfmt::skip]
const RC_V2: [u64; PRINCE_NRND] = [
    0x0000000000000000, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89,
    0x452821e638d01377, 0xbe5466cf34e90c6c, 0x7ef84f78fd955cb1, 0x7aacf4538d971a60,
    0xc882d32f25323c54, 0x9b8ded979cd838c7, 0xd3b5a399ca0c2399, 0x3f84d5b5b5470917,
];
#[rustfmt::skip]
const RC_V2_IP_IM: [u64; PRINCE_NRND] = [ // iM . iP (RC) [from sage script]
    0x0000000000000000, 0x90ecdeb7cb7fc1ce, 0x81b2cb20a82a2928, 0x480cdfa91d749037,
    0xcb1a13467044d772, 0x9e8995b07a988c08, 0xe70338c395311a6a, 0x60dc22bf6e681c08,
    0x318672daf2dd0655, 0x2a74fad9b606e252, 0xe96673c424d657ac, 0xabc631f91e2ccb7a,
];
const RC_BETA_IM: u64 = 0x42f93b79daa0eea5; // iM (RC_BETA) [from sage script]

const fn u64_to_vec_u4(u: u64) -> [u8; 16] {
    let mut i: usize = 0;
    let mut v: [u8; 16] = [0; 16];
    while i < 16 {
        v[16 - i - 1] = ((u >> (4 * i)) & 0xf) as u8;
        i += 1;
    }
    v
}

const fn u64_to_vec_u2(u: u64) -> [u8; 32] {
    let mut i: usize = 0;
    let mut v: [u8; 32] = [0; 32];
    while i < 32 {
        v[32 - i - 1] = ((u >> (2 * i)) & 0x3) as u8;
        i += 1;
    }
    v
}

const fn vec_u2_to_u64(v: [u8; 32]) -> u64 {
    let mut i: usize = 0;
    let mut u: u64 = 0;
    while i < 32 {
        u += (v[i] as u64) << (62 - 2 * i);
        i += 1;
    }
    u
}

type ZLut = [[u8; 16]; 16];

// zlut[w][x] = sbox[x ^ xor_inner[w]] ^ xor_outer[w]
const fn build_zlut_xsy(sbox: [u8; 16], xor_inner: [u8; 16], xor_outer: [u8; 16]) -> ZLut {
    let mut zlut: ZLut = [[0; 16]; 16];
    let mut w: usize = 0;
    while w < 16 {
        let mut x: usize = 0;
        while x < 16 {
            zlut[w][x] = sbox[((x as u8) ^ xor_inner[w]) as usize] ^ xor_outer[w];
            x += 1;
        }
        w += 1;
    }
    zlut
}

const ZERO_U4: [u8; 16] = [0; 16];

const PV2_0_S_0: ZLut = build_zlut_xsy(PV2_S, ZERO_U4, ZERO_U4);
const PV2_1_S_2: ZLut = build_zlut_xsy(
    PV2_S,
    u64_to_vec_u4(RC_V2[1]),
    u64_to_vec_u4(RC_V2_IP_IM[2]),
);
const PV2_3_S_4: ZLut = build_zlut_xsy(
    PV2_S,
    u64_to_vec_u4(RC_V2[3]),
    u64_to_vec_u4(RC_V2_IP_IM[4]),
);
const PV2_5_S_M: ZLut = build_zlut_xsy(PV2_S, u64_to_vec_u4(RC_V2[5]), u64_to_vec_u4(RC_BETA_IM));
const PV2_0_IS_0: ZLut = build_zlut_xsy(PV2_IS, ZERO_U4, ZERO_U4);
const PV2_6_IS_7: ZLut = build_zlut_xsy(
    PV2_IS,
    u64_to_vec_u4(RC_V2_IP_IM[6]),
    u64_to_vec_u4(RC_V2[7]),
);
const PV2_8_IS_9: ZLut = build_zlut_xsy(
    PV2_IS,
    u64_to_vec_u4(RC_V2_IP_IM[8]),
    u64_to_vec_u4(RC_V2[9]),
);
const PV2_A_IS_B: ZLut = build_zlut_xsy(
    PV2_IS,
    u64_to_vec_u4(RC_V2_IP_IM[10]),
    u64_to_vec_u4(RC_V2[11]),
);
const PV2_B_S_A: ZLut = build_zlut_xsy(
    PV2_S,
    u64_to_vec_u4(RC_V2[11]),
    u64_to_vec_u4(RC_V2_IP_IM[10]),
);
const PV2_9_S_8: ZLut = build_zlut_xsy(
    PV2_S,
    u64_to_vec_u4(RC_V2[9]),
    u64_to_vec_u4(RC_V2_IP_IM[8]),
);
const PV2_7_S_6: ZLut = build_zlut_xsy(
    PV2_S,
    u64_to_vec_u4(RC_V2[7]),
    u64_to_vec_u4(RC_V2_IP_IM[6]),
);
const PV2_M_IS_5: ZLut = build_zlut_xsy(PV2_IS, u64_to_vec_u4(RC_BETA_IM), u64_to_vec_u4(RC_V2[5]));
const PV2_4_IS_3: ZLut = build_zlut_xsy(
    PV2_IS,
    u64_to_vec_u4(RC_V2_IP_IM[4]),
    u64_to_vec_u4(RC_V2[3]),
);
const PV2_2_IS_1: ZLut = build_zlut_xsy(
    PV2_IS,
    u64_to_vec_u4(RC_V2_IP_IM[2]),
    u64_to_vec_u4(RC_V2[1]),
);

// e-xor(x, b) = xor of all bits of nibble x except bit b (bits msb 0123 lsb)
const fn u4_exor(x: u8, b: u8) -> u8 {
    let ex_mask: u8 = 0xf - (1 << (3 - b));
    let mut c: u8 = x & ex_mask;
    c = (c & 0x3) ^ (c >> 2);
    c = (c & 0x1) ^ (c >> 1);
    c
}

// EXOR_LUTS[to_b][b][x] = u4_exor(x, b) << to_b
const fn build_exor_luts() -> [[[u8; 16]; 4]; 4] {
    let mut luts = [[[0u8; 16]; 4]; 4];
    let mut to_b: usize = 0;
    while to_b < 4 {
        let mut b: usize = 0;
        while b < 4 {
            let mut x: usize = 0;
            while x < 16 {
                luts[to_b][b][x] = u4_exor(x as u8, b as u8) << to_b;
                x += 1;
            }
            b += 1;
        }
        to_b += 1;
    }
    luts
}
const EXOR_LUTS: [[[u8; 16]; 4]; 4] = build_exor_luts();

const fn build_xor_to_low() -> [u8; 16] {
    let mut t = [0u8; 16];
    let mut x: usize = 0;
    while x < 16 {
        t[x] = ((x & 3) ^ (x >> 2)) as u8;
        x += 1;
    }
    t
}
const XOR_TO_LOW: [u8; 16] = build_xor_to_low();

// XOR_B[sel][b_pos][x]: sel 0 extracts the high bit of the 2-bit xor,
// sel 1 the low bit; the bit is placed at position (3 - b_pos)
const fn build_xor_b_luts() -> [[[u8; 16]; 4]; 2] {
    let mut luts = [[[0u8; 16]; 4]; 2];
    let mut sel: usize = 0;
    while sel < 2 {
        let hl = if sel == 0 { 1 } else { 0 };
        let mut b: usize = 0;
        while b < 4 {
            let mut x: usize = 0;
            while x < 16 {
                luts[sel][b][x] = ((XOR_TO_LOW[x] >> hl) & 0x1) << (3 - b);
                x += 1;
            }
            b += 1;
        }
        sel += 1;
    }
    luts
}
const XOR_B_LUTS: [[[u8; 16]; 4]; 2] = build_xor_b_luts();

const PERM: [usize; 16] = [
    0x0, 0x5, 0xa, 0xf, 0x4, 0x9, 0xe, 0x3, 0x8, 0xd, 0x2, 0x7, 0xc, 0x1, 0x6, 0xb,
];
const IPERM: [usize; 16] = [
    0x0, 0xd, 0xa, 0x7, 0x4, 0x1, 0xe, 0xb, 0x8, 0x5, 0x2, 0xf, 0xc, 0x9, 0x6, 0x3,
];
const FHE_M0_PERM: [usize; 16] = [
    0x0, 0x5, 0xa, 0xf, 0x3, 0x4, 0x9, 0xe, 0x2, 0x7, 0x8, 0xd, 0x1, 0x6, 0xb, 0xc,
];
const FHE_M1_PERM: [usize; 16] = [
    0x3, 0x4, 0x9, 0xe, 0x2, 0x7, 0x8, 0xd, 0x1, 0x6, 0xb, 0xc, 0x0, 0x5, 0xa, 0xf,
];

// Combined bit permutation for M' = diag(M0, M1, M1, M0)
const FHE_M_PERM: [usize; 64] = {
    let mut n: usize = 0;
    let mut m_perm: [usize; 64] = [0; 64];
    while n < 4 {
        let mut p: usize = 0;
        while p < 16 {
            m_perm[p + n * 16] = n * 16
                + if n == 0 || n == 3 {
                    FHE_M0_PERM[p]
                } else {
                    FHE_M1_PERM[p]
                };
            p += 1;
        }
        n += 1;
    }
    m_perm
};

// M' fused with the forward nibble permutation layer
const FHE_MP_PERM_FW: [usize; 64] = {
    let mut b: usize = 0;
    let mut m_perm: [usize; 64] = [0; 64];
    while b < 64 {
        m_perm[b] = FHE_M_PERM[(PERM[b >> 2] << 2) + (b & 0x3)];
        b += 1;
    }
    m_perm
};

// Gather semantics: new[i] = old[order[i]]
fn gather64(list: &[u8; 64], order: &[usize; 64]) -> [u8; 64] {
    std::array::from_fn(|i| list[order[i]])
}

fn clear_xor_to_u4(in_u2q: &[u8; 32], k: &[u8; 32]) -> [u8; 16] {
    let hl: [u8; 32] = std::array::from_fn(|n| {
        if n & 1 == 0 {
            XOR_TO_LOW[(in_u2q[n] + k[n]) as usize] << 2
        } else {
            XOR_TO_LOW[(in_u2q[n] + k[n]) as usize]
        }
    });
    std::array::from_fn(|w| hl[2 * w] + hl[2 * w + 1])
}

fn clear_xor_to_b(in_u2q: &[u8; 32], k: &[u8; 32]) -> [u8; 64] {
    let hl: [u8; 32] = std::array::from_fn(|n| in_u2q[n] + k[n]);
    std::array::from_fn(|idx| {
        let n = idx >> 1;
        let w = idx >> 2;
        let b_pos = w & 0x3;
        XOR_B_LUTS[idx & 1][b_pos][hl[n] as usize]
    })
}

fn clear_xor_to_u2(in_u2q: &[u8; 32], k: &[u8; 32]) -> [u8; 32] {
    std::array::from_fn(|n| XOR_TO_LOW[(in_u2q[n] + k[n]) as usize])
}

fn clear_fw_round(in_u4: &[u8; 16], zlut: &ZLut) -> [u8; 32] {
    let bits: [u8; 64] = std::array::from_fn(|idx| {
        let w = idx >> 2;
        let b = idx & 0x3;
        ((zlut[w][in_u4[w] as usize] >> (3 - b)) & 0x1) << (3 - (w % 4))
    });
    let u4: [u8; 16] = std::array::from_fn(|w| {
        let oo = 16 * (w / 4) + (w % 4);
        bits[oo] + bits[oo + 4] + bits[oo + 8] + bits[oo + 12]
    });
    let e: [u8; 64] = std::array::from_fn(|idx| {
        let w = idx >> 2;
        let b = idx & 0x3;
        EXOR_LUTS[3 - (w % 2)][b][u4[w] as usize]
    });
    let e = gather64(&e, &FHE_MP_PERM_FW);
    std::array::from_fn(|n| e[2 * n] + e[2 * n + 1])
}

fn clear_mid_round(
    in_u4: &[u8; 16],
    k_fst: &[u8; 32],
    k_scd: &[u8; 32],
    zlut_fst: &ZLut,
    zlut_scd: &ZLut,
) -> [u8; 32] {
    let u2q: [u8; 32] = std::array::from_fn(|n| {
        let w = n >> 1;
        let b = n & 0x1;
        ((zlut_fst[w][in_u4[w] as usize] >> (2 - 2 * b)) & 0x3) << 2
    });
    let bits = clear_xor_to_b(&u2q, k_fst);
    let u4: [u8; 16] = std::array::from_fn(|w| {
        let oo = 16 * (w / 4) + (w % 4);
        bits[oo] + bits[oo + 4] + bits[oo + 8] + bits[oo + 12]
    });
    let e: [u8; 64] = std::array::from_fn(|idx| {
        let w = idx >> 2;
        let b = idx & 0x3;
        EXOR_LUTS[3 - (w % 2)][b][u4[w] as usize]
    });
    let e = gather64(&e, &FHE_M_PERM);
    let u2q: [u8; 32] = std::array::from_fn(|n| e[2 * n] + e[2 * n + 1]);
    let u4 = clear_xor_to_u4(&u2q, k_scd);
    std::array::from_fn(|n| {
        let w = n >> 1;
        let b = n & 0x1;
        ((zlut_scd[w][u4[w] as usize] >> (2 - 2 * b)) & 0x3) << 2
    })
}

fn clear_bw_round(in_b: &[u8; 64], zlut: &ZLut) -> [u8; 32] {
    let u4: [u8; 16] = std::array::from_fn(|w| {
        (0..4)
            .map(|b| in_b[(w & 0x3) + 4 * IPERM[4 * (w >> 2) + b]])
            .sum()
    });
    let e: [u8; 64] = std::array::from_fn(|idx| {
        let w = idx >> 2;
        let b = idx & 0x3;
        EXOR_LUTS[3 - (w % 4)][b][u4[w] as usize]
    });
    let e = gather64(&e, &FHE_M_PERM);
    let u4: [u8; 16] =
        std::array::from_fn(|w| e[4 * w] + e[4 * w + 1] + e[4 * w + 2] + e[4 * w + 3]);
    std::array::from_fn(|n| {
        let w = n >> 1;
        let b = n & 0x1;
        ((zlut[w][u4[w] as usize] >> (2 - 2 * b)) & 0x3) << 2
    })
}

fn clear_prince_transform(input: u64, k0: u64, k1: u64, decrypt: bool) -> u64 {
    let (fw_tables, mid_tables, bw_tables): ([&ZLut; 5], (&ZLut, &ZLut), [&ZLut; 5]) = if decrypt {
        (
            [&PV2_B_S_A, &PV2_0_S_0, &PV2_9_S_8, &PV2_0_S_0, &PV2_7_S_6],
            (&PV2_0_S_0, &PV2_M_IS_5),
            [
                &PV2_0_IS_0,
                &PV2_4_IS_3,
                &PV2_0_IS_0,
                &PV2_2_IS_1,
                &PV2_0_IS_0,
            ],
        )
    } else {
        (
            [&PV2_0_S_0, &PV2_1_S_2, &PV2_0_S_0, &PV2_3_S_4, &PV2_0_S_0],
            (&PV2_5_S_M, &PV2_0_IS_0),
            [
                &PV2_6_IS_7,
                &PV2_0_IS_0,
                &PV2_8_IS_9,
                &PV2_0_IS_0,
                &PV2_A_IS_B,
            ],
        )
    };
    let (k_first, k_second) = if decrypt {
        (u64_to_vec_u2(k1), u64_to_vec_u2(k0))
    } else {
        (u64_to_vec_u2(k0), u64_to_vec_u2(k1))
    };

    let m = u64_to_vec_u2(input);
    let mut u2q: [u8; 32] = std::array::from_fn(|n| m[n] * 4);

    let mut u4 = clear_xor_to_u4(&u2q, &k_first);
    for (r, fw_table) in fw_tables.iter().enumerate() {
        u2q = clear_fw_round(&u4, fw_table);
        u4 = clear_xor_to_u4(&u2q, if r % 2 == 0 { &k_second } else { &k_first });
    }
    u2q = clear_mid_round(&u4, &k_first, &k_second, mid_tables.0, mid_tables.1);
    for (r, bw_table) in bw_tables.iter().enumerate() {
        let bits = clear_xor_to_b(&u2q, if r % 2 == 0 { &k_first } else { &k_second });
        u2q = clear_bw_round(&bits, bw_table);
    }
    vec_u2_to_u64(clear_xor_to_u2(&u2q, &k_second))
}

pub(crate) fn clear_prince_encrypt(m: u64, k0: u64, k1: u64) -> u64 {
    clear_prince_transform(m, k0, k1, false)
}

pub(crate) fn clear_prince_decrypt(c: u64, k0: u64, k1: u64) -> u64 {
    clear_prince_transform(c, k0, k1, true)
}

/// PRINCEv2 known-answer tests from [BEK+20, Appendix B]: (ptxt, k0, k1, ctxt)
const PRINCE_KATS: [(u64, u64, u64, u64); 5] = [
    (
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
        0x0125fc7359441690,
    ),
    (
        0xffffffffffffffff,
        0x0000000000000000,
        0x0000000000000000,
        0x832bd46f108e7857,
    ),
    (
        0x0000000000000000,
        0xffffffffffffffff,
        0x0000000000000000,
        0xee873b2ec447944d,
    ),
    (
        0x0000000000000000,
        0x0000000000000000,
        0xffffffffffffffff,
        0x0ac6f9cd6e6f275d,
    ),
    (
        0x0123456789abcdef,
        0x0123456789abcdef,
        0xfedcba9876543210,
        0x603cd95fa72a8704,
    ),
];

// Self-validation of the plaintext reference model (runs on CPU)
#[test]
fn test_prince_clear_model_kats() {
    for (ptxt, k0, k1, ctxt) in PRINCE_KATS {
        assert_eq!(
            clear_prince_encrypt(ptxt, k0, k1),
            ctxt,
            "clear model encrypt failed for KAT ptxt={ptxt:016x}"
        );
        assert_eq!(
            clear_prince_decrypt(ctxt, k0, k1),
            ptxt,
            "clear model decrypt failed for KAT ctxt={ctxt:016x}"
        );
    }
}

// KATs grouped by shared key pair to exercise batching (KATs 0 and 1 share
// the all-zero keys, KAT 4 is duplicated into a 2-input batch)
fn internal_prince_kat_test<P, E>(param: P, mut executor: E, decrypt: bool)
where
    P: Into<TestParameters>,
    E: for<'a> FunctionExecutor<
        (
            &'a RadixCiphertext,
            &'a RadixCiphertext,
            &'a RadixCiphertext,
            usize,
        ),
        RadixCiphertext,
    >,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, 1));
    let sks = Arc::new(sks);
    executor.setup(&cks, sks);

    let batches: [(&[usize], usize); 4] = [(&[0, 1], 2), (&[2], 1), (&[3], 1), (&[4, 4], 2)];

    for (kat_indexes, num_prince_inputs) in batches {
        let (_, k0, k1, _) = PRINCE_KATS[kat_indexes[0]];
        let inputs: Vec<u64> = kat_indexes
            .iter()
            .map(|&i| {
                let (ptxt, _, _, ctxt) = PRINCE_KATS[i];
                if decrypt {
                    ctxt
                } else {
                    ptxt
                }
            })
            .collect();
        let expected: Vec<u64> = kat_indexes
            .iter()
            .map(|&i| {
                let (ptxt, _, _, ctxt) = PRINCE_KATS[i];
                if decrypt {
                    ptxt
                } else {
                    ctxt
                }
            })
            .collect();

        let ctxt_input = cks.encrypt_u64s_for_prince(&inputs);
        let ctxt_k0 = cks.encrypt_u64_for_prince(k0);
        let ctxt_k1 = cks.encrypt_u64_for_prince(k1);

        let encrypted_result =
            executor.execute((&ctxt_input, &ctxt_k0, &ctxt_k1, num_prince_inputs));
        let results = cks.decrypt_u64_from_prince(&encrypted_result, num_prince_inputs);
        assert_eq!(
            results, expected,
            "PRINCE KAT batch {kat_indexes:?} failed (decrypt = {decrypt})"
        );
    }
}

pub fn prince_encrypt_kat_test<P, E>(param: P, executor: E)
where
    P: Into<TestParameters>,
    E: for<'a> FunctionExecutor<
        (
            &'a RadixCiphertext,
            &'a RadixCiphertext,
            &'a RadixCiphertext,
            usize,
        ),
        RadixCiphertext,
    >,
{
    internal_prince_kat_test(param, executor, false);
}

pub fn prince_decrypt_kat_test<P, E>(param: P, executor: E)
where
    P: Into<TestParameters>,
    E: for<'a> FunctionExecutor<
        (
            &'a RadixCiphertext,
            &'a RadixCiphertext,
            &'a RadixCiphertext,
            usize,
        ),
        RadixCiphertext,
    >,
{
    internal_prince_kat_test(param, executor, true);
}

// Random inputs on an odd, non-power-of-two batch against the plaintext
// model, then a decrypt(encrypt(m)) == m round trip that also checks the
// outputs come out fresh
pub fn prince_encrypt_decrypt_random_test<P, E1, E2>(
    param: P,
    mut encrypt_executor: E1,
    mut decrypt_executor: E2,
) where
    P: Into<TestParameters>,
    E1: for<'a> FunctionExecutor<
        (
            &'a RadixCiphertext,
            &'a RadixCiphertext,
            &'a RadixCiphertext,
            usize,
        ),
        RadixCiphertext,
    >,
    E2: for<'a> FunctionExecutor<
        (
            &'a RadixCiphertext,
            &'a RadixCiphertext,
            &'a RadixCiphertext,
            usize,
        ),
        RadixCiphertext,
    >,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, 1));
    let sks = Arc::new(sks);
    encrypt_executor.setup(&cks, sks.clone());
    decrypt_executor.setup(&cks, sks);

    let num_prince_inputs = 7;
    let messages: Vec<u64> = (0..num_prince_inputs).map(|_| rand::random()).collect();
    let k0: u64 = rand::random();
    let k1: u64 = rand::random();

    let expected: Vec<u64> = messages
        .iter()
        .map(|&m| clear_prince_encrypt(m, k0, k1))
        .collect();

    let ctxt_input = cks.encrypt_u64s_for_prince(&messages);
    let ctxt_k0 = cks.encrypt_u64_for_prince(k0);
    let ctxt_k1 = cks.encrypt_u64_for_prince(k1);

    let encrypted = encrypt_executor.execute((&ctxt_input, &ctxt_k0, &ctxt_k1, num_prince_inputs));
    let results = cks.decrypt_u64_from_prince(&encrypted, num_prince_inputs);
    assert_eq!(
        results, expected,
        "PRINCE encryption does not match the plaintext model"
    );

    let decrypted = decrypt_executor.execute((&encrypted, &ctxt_k0, &ctxt_k1, num_prince_inputs));
    let results = cks.decrypt_u64_from_prince(&decrypted, num_prince_inputs);
    assert_eq!(
        results, messages,
        "PRINCE decrypt(encrypt(m)) does not give back m"
    );
}
