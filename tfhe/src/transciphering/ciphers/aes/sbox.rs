//! AES S-box as a Boyar-Peralta boolean circuit (~32 ANDs, depth-4
//! multiplicative, ~83 XORs). See <https://eprint.iacr.org/2011/332.pdf>.
use crate::shortint::server_key::LookupTable;
use crate::shortint::{Ciphertext, ServerKey};
use rayon::join;
use rayon::prelude::*;

/// XOR two ciphertexts and flush the result back to noise 1.
fn flush_xor(
    sks: &ServerKey,
    flush_lut: &LookupTable<Vec<u64>>,
    lhs: &Ciphertext,
    rhs: &Ciphertext,
) -> Ciphertext {
    sks.apply_lookup_table(&sks.unchecked_add(lhs, rhs), flush_lut)
}

fn flush_xor_batch<const N: usize>(
    sks: &ServerKey,
    flush_lut: &LookupTable<Vec<u64>>,
    pairs: [(&Ciphertext, &Ciphertext); N],
) -> [Ciphertext; N] {
    pairs
        .into_par_iter()
        .map(|(l, r)| flush_xor(sks, flush_lut, l, r))
        .collect::<Vec<_>>()
        .try_into()
        .expect("flush_xor_batch output length matches input")
}

/// Logical NOT on a clean bit, flushed.
fn flush_not(sks: &ServerKey, flush_lut: &LookupTable<Vec<u64>>, bit: &Ciphertext) -> Ciphertext {
    sks.apply_lookup_table(&sks.unchecked_scalar_add(bit, 1), flush_lut)
}

/// References to the 8 bits of the input byte in BP order (`u0` is the byte
/// MSB = BP `U0`). [`SboxByte::from_state`] is the bridge between our LSB-first
/// array layout and the BP MSB-first internal naming.
#[derive(Clone, Copy)]
struct SboxByte<'a> {
    u0: &'a Ciphertext,
    u1: &'a Ciphertext,
    u2: &'a Ciphertext,
    u3: &'a Ciphertext,
    u4: &'a Ciphertext,
    u5: &'a Ciphertext,
    u6: &'a Ciphertext,
    u7: &'a Ciphertext,
}

impl<'a> SboxByte<'a> {
    fn from_state(state: &'a [Ciphertext]) -> Self {
        debug_assert_eq!(state.len(), 8);
        Self {
            u0: &state[7],
            u1: &state[6],
            u2: &state[5],
            u3: &state[4],
            u4: &state[3],
            u5: &state[2],
            u6: &state[1],
            u7: &state[0],
        }
    }
}

/// Outputs of the BP top linear layer: the 21 `T_i` consumed by the middle.
///
/// `T5`, `T7`, `T11`, `T12`, `T18`, `T21` are pure internal scratch values
/// that are folded into other terms as they are produced, so they are never
/// materialized as fields here (e.g. `T7 = U1 + U2` lives only as a local in
/// [`top_sbox`] before being consumed by `T9`, `T10`, `T16`).
struct SboxTop {
    t1: Ciphertext,
    t2: Ciphertext,
    t3: Ciphertext,
    t4: Ciphertext,
    t6: Ciphertext,
    t8: Ciphertext,
    t9: Ciphertext,
    t10: Ciphertext,
    t13: Ciphertext,
    t14: Ciphertext,
    t15: Ciphertext,
    t16: Ciphertext,
    t17: Ciphertext,
    t19: Ciphertext,
    t20: Ciphertext,
    t22: Ciphertext,
    t23: Ciphertext,
    t24: Ciphertext,
    t25: Ciphertext,
    t26: Ciphertext,
    t27: Ciphertext,
}

/// Outputs of the BP middle non-linear layer: the 18 final ANDs `M46..M63`.
struct SboxMiddle {
    m46: Ciphertext,
    m47: Ciphertext,
    m48: Ciphertext,
    m49: Ciphertext,
    m50: Ciphertext,
    m51: Ciphertext,
    m52: Ciphertext,
    m53: Ciphertext,
    m54: Ciphertext,
    m55: Ciphertext,
    m56: Ciphertext,
    m57: Ciphertext,
    m58: Ciphertext,
    m59: Ciphertext,
    m60: Ciphertext,
    m61: Ciphertext,
    m62: Ciphertext,
    m63: Ciphertext,
}

/// Final sbox outputs (`S0` is the byte MSB, `S7` the LSB).
struct SboxBottom {
    s0: Ciphertext,
    s1: Ciphertext,
    s2: Ciphertext,
    s3: Ciphertext,
    s4: Ciphertext,
    s5: Ciphertext,
    s6: Ciphertext,
    s7: Ciphertext,
}

/// Top linear layer: produces the 21 BP `T_i` from the 8 input bits.
///
/// Independent flush_xor calls are grouped into `rayon::join` clusters to
/// fan PBS calls out across cores when blocks are scarce.
fn top_sbox(sks: &ServerKey, flush_lut: &LookupTable<Vec<u64>>, byte: SboxByte) -> SboxTop {
    let SboxByte {
        u0,
        u1,
        u2,
        u3,
        u4,
        u5,
        u6,
        u7,
    } = byte;

    let t7 = sks.unchecked_add(u1, u2);

    let [t1, t2, t3, t4, t9] = flush_xor_batch(
        sks,
        flush_lut,
        [(u0, u3), (u0, u5), (u0, u6), (u3, u5), (&t7, u7)],
    );

    let [t13, t19, t20, t22] = flush_xor_batch(
        sks,
        flush_lut,
        [(&t3, &t4), (&t9, u3), (&t9, u0), (&t9, u6)],
    );

    let t6_pre = sks.unchecked_add(u4, &t13);
    let [t6, t14, t23] =
        flush_xor_batch(sks, flush_lut, [(&t6_pre, u5), (&t6_pre, u1), (&t22, &t2)]);

    let [t8, t10, t15] = flush_xor_batch(sks, flush_lut, [(&t6, u7), (&t6, &t7), (&t14, &t1)]);

    let [t16, t17, t24, t27] = flush_xor_batch(
        sks,
        flush_lut,
        [(&t7, &t15), (u7, &t15), (&t10, &t2), (&t10, &t15)],
    );

    let (t25, t26) = join(
        || flush_xor(sks, flush_lut, u0, &t16),
        || flush_xor(sks, flush_lut, &t3, &t16),
    );

    SboxTop {
        t1,
        t2,
        t3,
        t4,
        t6,
        t8,
        t9,
        t10,
        t13,
        t14,
        t15,
        t16,
        t17,
        t19,
        t20,
        t22,
        t23,
        t24,
        t25,
        t26,
        t27,
    }
}

/// Middle non-linear layer: 32 ANDs producing `M46..M63`.
///
/// `d` is the BP `D` input: for the forward direction this is the LSB of the
/// input byte (`U7`, our `byte.u7`). The middle layer plugs it into two ANDs
/// directly (`M4 = T19 x D` and `M48 = M39 x D`).
///
/// Naming: variables that equal a paper `M_i` carry the same index. The
/// paper's `M3, M8, M16-M18, M31-M36` are not materialized (they would each
/// cost an extra PBS), so the values computed in their place are named
/// `aux1..aux10`. `M38` and `M40` are produced via GF(2) algebraic identities
/// rather than the paper's literal `M32+M33` / `M35+M36` formulas.
fn middle_sbox(
    sks: &ServerKey,
    flush_lut: &LookupTable<Vec<u64>>,
    top: SboxTop,
    d: &Ciphertext,
) -> SboxMiddle {
    let SboxTop {
        t1,
        t2,
        t3,
        t4,
        t6,
        t8,
        t9,
        t10,
        t13,
        t14,
        t15,
        t16,
        t17,
        t19,
        t20,
        t22,
        t23,
        t24,
        t25,
        t26,
        t27,
    } = top;

    let and_inputs: [(&Ciphertext, &Ciphertext); 9] = [
        (&t6, &t13),
        (&t23, &t8),
        (d, &t19),
        (&t3, &t16),
        (&t9, &t22),
        (&t20, &t17),
        (&t1, &t15),
        (&t4, &t27),
        (&t2, &t10),
    ];
    let [m1, m2, m4, m6, m7, m9, m11, m12, m14]: [Ciphertext; 9] = and_inputs
        .into_par_iter()
        .map(|(l, r)| sks.unchecked_bitand(l, r))
        .collect::<Vec<_>>()
        .try_into()
        .expect("9 ANDs");

    let aux1 = sks.unchecked_add(&m2, &m1);
    let m5 = sks.unchecked_add(&m4, &m1);
    let aux2 = sks.unchecked_add(&m7, &m6);
    let m10 = sks.unchecked_add(&m9, &m6);
    let m13 = sks.unchecked_add(&m12, &m11);
    let m15 = sks.unchecked_add(&m14, &m11);
    let aux3 = sks.unchecked_add(&aux1, &m13);
    let aux4 = sks.unchecked_add(&m5, &m15);
    let aux5 = sks.unchecked_add(&aux2, &m13);
    let m19 = sks.unchecked_add(&m10, &m15);

    let [m20, m21, m22, m23] = flush_xor_batch(
        sks,
        flush_lut,
        [(&aux3, &t14), (&aux4, &t24), (&aux5, &t26), (&m19, &t25)],
    );

    let (m24, (m25, m27)) = join(
        || flush_xor(sks, flush_lut, &m22, &m23),
        || {
            join(
                || sks.unchecked_bitand(&m22, &m20),
                || flush_xor(sks, flush_lut, &m20, &m21),
            )
        },
    );

    let (m26, m28) = join(
        || flush_xor(sks, flush_lut, &m21, &m25),
        || flush_xor(sks, flush_lut, &m23, &m25),
    );

    let (m29, m30) = join(
        || sks.unchecked_bitand(&m28, &m27),
        || sks.unchecked_bitand(&m26, &m24),
    );

    let (m37, m39) = join(
        || flush_xor(sks, flush_lut, &m29, &m21),
        || flush_xor(sks, flush_lut, &m30, &m23),
    );

    let aux6 = sks.unchecked_add(&m22, &m39);
    let aux7 = flush_xor(sks, flush_lut, &m28, &m39);
    let aux8 = sks.unchecked_bitand(&m23, &aux7);
    let (m40, aux9) = join(
        || flush_xor(sks, flush_lut, &aux8, &aux6),
        || flush_xor(sks, flush_lut, &m28, &aux8),
    );
    let aux10 = sks.unchecked_bitand(&aux9, &m37);
    let m38 = flush_xor(sks, flush_lut, &m27, &aux10);

    let [m41, m42, m43, m44] = flush_xor_batch(
        sks,
        flush_lut,
        [(&m38, &m40), (&m37, &m39), (&m37, &m38), (&m39, &m40)],
    );
    let m45 = flush_xor(sks, flush_lut, &m42, &m41);

    let final_inputs: [(&Ciphertext, &Ciphertext); 18] = [
        (&t6, &m44),
        (&t8, &m40),
        (&m39, d),
        (&t16, &m43),
        (&t9, &m38),
        (&m37, &t17),
        (&m42, &t15),
        (&t27, &m45),
        (&t10, &m41),
        (&t13, &m44),
        (&t23, &m40),
        (&m39, &t19),
        (&t3, &m43),
        (&t22, &m38),
        (&m37, &t20),
        (&m42, &t1),
        (&m45, &t4),
        (&m41, &t2),
    ];
    let [m46, m47, m48, m49, m50, m51, m52, m53, m54, m55, m56, m57, m58, m59, m60, m61, m62, m63]: [Ciphertext; 18] =
        final_inputs
            .into_par_iter()
            .map(|(l, r)| sks.unchecked_bitand(l, r))
            .collect::<Vec<_>>()
            .try_into()
            .expect("18 ANDs");

    SboxMiddle {
        m46,
        m47,
        m48,
        m49,
        m50,
        m51,
        m52,
        m53,
        m54,
        m55,
        m56,
        m57,
        m58,
        m59,
        m60,
        m61,
        m62,
        m63,
    }
}

/// Bottom linear layer: combine the 18 `M_i` into the 8 sbox bits `S0..S7`.
fn bottom_sbox(sks: &ServerKey, flush_lut: &LookupTable<Vec<u64>>, mid: SboxMiddle) -> SboxBottom {
    let SboxMiddle {
        m46,
        m47,
        m48,
        m49,
        m50,
        m51,
        m52,
        m53,
        m54,
        m55,
        m56,
        m57,
        m58,
        m59,
        m60,
        m61,
        m62,
        m63,
    } = mid;

    let l46 = sks.unchecked_add(&m61, &m62);
    let l47 = sks.unchecked_add(&m56, &m57);
    let l48 = sks.unchecked_add(&m51, &m59);
    let l49 = sks.unchecked_add(&m55, &m56);
    let l50 = sks.unchecked_add(&m48, &m58);
    let l51 = sks.unchecked_add(&m48, &m51);
    let l52 = sks.unchecked_add(&m53, &m54);
    let l53 = sks.unchecked_add(&m46, &m49);
    let l54 = sks.unchecked_add(&m52, &m53);
    let l55 = sks.unchecked_add(&m62, &m63);
    let l56 = sks.unchecked_add(&m58, &l48);
    let l58 = sks.unchecked_add(&m50, &l46);
    let l59 = sks.unchecked_add(&m49, &l54);

    let [l57, l62, l63, l64] = flush_xor_batch(
        sks,
        flush_lut,
        [(&l50, &l53), (&l52, &l58), (&l49, &l58), (&m50, &l59)],
    );

    let l60 = sks.unchecked_add(&l46, &l57);
    let l61 = sks.unchecked_add(&m60, &l57);

    let ((l65, l66), l60_not) = join(
        || {
            join(
                || flush_xor(sks, flush_lut, &l61, &l62),
                || flush_xor(sks, flush_lut, &m47, &l63),
            )
        },
        || flush_not(sks, flush_lut, &l60),
    );

    let s0 = sks.unchecked_add(&l59, &l63);

    let mut s6 = sks.unchecked_scalar_add(&l62, 1);
    sks.unchecked_add_assign(&mut s6, &l56);

    let s7 = sks.unchecked_add(&l48, &l60_not);

    let l67 = sks.unchecked_add(&l64, &l65);
    let s3 = sks.unchecked_add(&l53, &l66);
    let s4 = sks.unchecked_add(&l51, &l66);
    let s5 = sks.unchecked_add(&l47, &l65);

    let s3_not = sks.unchecked_scalar_add(&s3, 1);
    let s1 = sks.unchecked_add(&l64, &s3_not);

    let mut s2 = sks.unchecked_scalar_add(&l67, 1);
    sks.unchecked_add_assign(&mut s2, &l55);

    SboxBottom {
        s0,
        s1,
        s2,
        s3,
        s4,
        s5,
        s6,
        s7,
    }
}

pub(super) fn sbox(sks: &ServerKey, flush_lut: &LookupTable<Vec<u64>>, x: &mut [Ciphertext]) {
    let byte = SboxByte::from_state(x);
    let top = top_sbox(sks, flush_lut, byte);
    let mid = middle_sbox(sks, flush_lut, top, byte.u7);
    let bot = bottom_sbox(sks, flush_lut, mid);

    x[7] = bot.s0;
    x[6] = bot.s1;
    x[5] = bot.s2;
    x[4] = bot.s3;
    x[3] = bot.s4;
    x[2] = bot.s5;
    x[1] = bot.s6;
    x[0] = bot.s7;
}
