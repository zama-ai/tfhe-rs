use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey};
use crate::shortint::parameters::TestParameters;
use std::sync::Arc;

// Reference PRINCEv2 [BEK+20], written from the specification: nibble S-box,
// the M' bit matrix, ShiftRows, round constants. It shares no structure with
// the GPU circuit, which evaluates a bit-sliced form with the constants fused
// into per-word S-box tables, so the two agree only if both are right.

const PV2_SBOX: [u8; 16] = [
    0xb, 0xf, 0x3, 0x2, 0xa, 0xc, 0x9, 0x1, 0x6, 0x7, 0x8, 0x0, 0xe, 0x5, 0xd, 0x4,
];
const PV2_INV_SBOX: [u8; 16] = [
    0xb, 0x7, 0x3, 0x2, 0xf, 0xd, 0x8, 0x9, 0xa, 0x6, 0x4, 0x0, 0x5, 0xe, 0xc, 0x1,
];
#[rustfmt::skip]
const PV2_RC: [u64; 12] = [
    0x0000000000000000, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89,
    0x452821e638d01377, 0xbe5466cf34e90c6c, 0x7ef84f78fd955cb1, 0x7aacf4538d971a60,
    0xc882d32f25323c54, 0x9b8ded979cd838c7, 0xd3b5a399ca0c2399, 0x3f84d5b5b5470917,
];
/// Constant folded into the reflective middle layer.
const PV2_BETA: u64 = 0x3f84d5b5b5470917;
#[rustfmt::skip]
const PV2_SHIFT_ROWS: [usize; 16] = [
    0x0, 0x5, 0xa, 0xf, 0x4, 0x9, 0xe, 0x3, 0x8, 0xd, 0x2, 0x7, 0xc, 0x1, 0x6, 0xb,
];

/// State bits are numbered MSB first, so bit `p` is bit `63 - p` of the `u64`
/// and nibble `w` occupies bits `4w..4w + 4`.
fn sub_nibbles(state: u64, sbox: &[u8; 16]) -> u64 {
    (0..16).fold(0, |acc, w| {
        let nibble = ((state >> (60 - 4 * w)) & 0xf) as usize;
        acc | ((sbox[nibble] as u64) << (60 - 4 * w))
    })
}

/// `M' = diag(M0, M1, M1, M0)`, each `Mk` built from the 4x4 blocks
/// `m_i = I4` with diagonal entry `i` cleared, laid out so that block `(r, c)`
/// of `Mk` is `m_{(r + c + k) mod 4}`. Every output bit is therefore the XOR of
/// three same-position bits of its 16-bit group, skipping one nibble. `M'` is
/// an involution.
fn m_prime(state: u64) -> u64 {
    let bit = |p: usize| (state >> (63 - p)) & 1;
    let mut out = 0u64;
    for group in 0..4 {
        let k = usize::from(group == 1 || group == 2);
        for r in 0..4 {
            for j in 0..4 {
                let skipped = (j + 4 - (r + k) % 4) % 4;
                let value = (0..4)
                    .filter(|c| *c != skipped)
                    .fold(0, |acc, c| acc ^ bit(group * 16 + 4 * c + j));
                out |= value << (63 - (group * 16 + 4 * r + j));
            }
        }
    }
    out
}

fn shift_rows(state: u64) -> u64 {
    (0..16).fold(0, |acc, w| {
        acc | (((state >> (60 - 4 * PV2_SHIFT_ROWS[w])) & 0xf) << (60 - 4 * w))
    })
}

fn inv_shift_rows(state: u64) -> u64 {
    (0..16).fold(0, |acc, w| {
        acc | (((state >> (60 - 4 * w)) & 0xf) << (60 - 4 * PV2_SHIFT_ROWS[w]))
    })
}

fn m_layer(state: u64) -> u64 {
    shift_rows(m_prime(state))
}

fn inv_m_layer(state: u64) -> u64 {
    m_prime(inv_shift_rows(state))
}

/// PRINCEv2 alternates the two key halves across the rounds, which is what
/// lets decryption reuse the circuit with `k0` and `k1` swapped.
fn round_key(round: usize, k0: u64, k1: u64) -> u64 {
    if round % 2 == 1 {
        k1
    } else {
        k0
    }
}

pub(crate) fn clear_prince_encrypt(m: u64, k0: u64, k1: u64) -> u64 {
    let mut state = m ^ k0;
    for round in 1..=5 {
        state = m_layer(sub_nibbles(state, &PV2_SBOX)) ^ PV2_RC[round] ^ round_key(round, k0, k1);
    }
    // Reflective middle layer: S, add k0, M', add beta and k1, S^-1
    state = m_prime(sub_nibbles(state, &PV2_SBOX) ^ k0) ^ PV2_BETA ^ k1;
    state = sub_nibbles(state, &PV2_INV_SBOX);
    for round in 6..=10 {
        state = sub_nibbles(
            inv_m_layer(state ^ PV2_RC[round] ^ round_key(round, k0, k1)),
            &PV2_INV_SBOX,
        );
    }
    state ^ PV2_RC[11] ^ k1
}

/// The exact inverse of [`clear_prince_encrypt`], step by step. Deliberately
/// not derived from the alpha-reflection, so that a round-trip test does not
/// assume the property the GPU decryption tables are built on.
pub(crate) fn clear_prince_decrypt(c: u64, k0: u64, k1: u64) -> u64 {
    let mut state = c ^ PV2_RC[11] ^ k1;
    for round in (6..=10).rev() {
        state = m_layer(sub_nibbles(state, &PV2_SBOX)) ^ PV2_RC[round] ^ round_key(round, k0, k1);
    }
    state = m_prime(sub_nibbles(state, &PV2_SBOX) ^ PV2_BETA ^ k1) ^ k0;
    state = sub_nibbles(state, &PV2_INV_SBOX);
    for round in (1..=5).rev() {
        state = sub_nibbles(
            inv_m_layer(state ^ PV2_RC[round] ^ round_key(round, k0, k1)),
            &PV2_INV_SBOX,
        );
    }
    state ^ k0
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
