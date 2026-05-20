//! AES S-box as a Boyar–Peralta boolean circuit (~32 ANDs, depth-4
//! multiplicative, ~83 XORs). See <https://eprint.iacr.org/2011/332.pdf>.
use crate::shortint::server_key::{BivariateLookupTableOwned, LookupTable};
use crate::shortint::{Ciphertext, ServerKey};
use rayon::join;
use rayon::prelude::*;

/// Homomorphic AND on two 1-bit ciphertexts via a bivariate PBS.
///
/// The bivariate API packs `l * message_modulus + r` (= `4·l + r` in `2_2`)
/// then applies the `|a, b| a & b` LUT. Both inputs must be at noise level 1:
/// the scaling pushes the packed noise to `4·noise(l) + noise(r)`, which only
/// fits in `max_noise_level = 5` when both inputs are clean.
pub(super) fn and(
    l: &Ciphertext,
    r: &Ciphertext,
    and_lut: &BivariateLookupTableOwned,
    sks: &ServerKey,
) -> Ciphertext {
    sks.unchecked_apply_lookup_table_bivariate(l, r, and_lut)
}

/// XOR two ciphertexts and flush the result back to noise 1.
fn flush_xor(
    sks: &ServerKey,
    flush_lut: &LookupTable<Vec<u64>>,
    lhs: &Ciphertext,
    rhs: &Ciphertext,
) -> Ciphertext {
    sks.apply_lookup_table(&sks.unchecked_add(lhs, rhs), flush_lut)
}

/// Logical NOT on a clean bit, flushed.
fn flush_not(sks: &ServerKey, flush_lut: &LookupTable<Vec<u64>>, bit: &Ciphertext) -> Ciphertext {
    sks.apply_lookup_table(&sks.unchecked_scalar_add(bit, 1), flush_lut)
}

/// References to the 8 bits of the input byte in BP order (`x0` is the byte
/// MSB = `U0`). [`SboxByte::from_state`] is the bridge between our LSB-first
/// array layout and the BP MSB-first internal naming.
#[derive(Clone, Copy)]
struct SboxByte<'a> {
    x0: &'a Ciphertext,
    x1: &'a Ciphertext,
    x2: &'a Ciphertext,
    x3: &'a Ciphertext,
    x4: &'a Ciphertext,
    x5: &'a Ciphertext,
    x6: &'a Ciphertext,
    x7: &'a Ciphertext,
}

impl<'a> SboxByte<'a> {
    fn from_state(state: &'a [Ciphertext]) -> Self {
        debug_assert_eq!(state.len(), 8);
        Self {
            x0: &state[7],
            x1: &state[6],
            x2: &state[5],
            x3: &state[4],
            x4: &state[3],
            x5: &state[2],
            x6: &state[1],
            x7: &state[0],
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
        x0,
        x1,
        x2,
        x3,
        x4,
        x5,
        x6,
        x7,
    } = byte;

    let ((t4, t3), (t1, t2)) = join(
        || {
            join(
                || flush_xor(sks, flush_lut, x3, x5), // T4 = U3 + U5
                || flush_xor(sks, flush_lut, x0, x6), // T3 = U0 + U6
            )
        },
        || {
            join(
                || flush_xor(sks, flush_lut, x0, x3), // T1 = U0 + U3
                || flush_xor(sks, flush_lut, x0, x5), // T2 = U0 + U5
            )
        },
    );

    // T7 = U1 + U2, unflushed: consumed only by T9, T10, and T16 below, each
    // of which folds it into a flush_xor.
    let t7 = sks.unchecked_add(x1, x2);
    let t9 = flush_xor(sks, flush_lut, &t7, x7); // T9 = U7 + T7

    let ((t19, t13), (t20, t22)) = join(
        || {
            join(
                || flush_xor(sks, flush_lut, &t9, x3), // T19 = T7 + T18 = T9 + U3
                || flush_xor(sks, flush_lut, &t3, &t4), // T13 = T3 + T4
            )
        },
        || {
            join(
                || flush_xor(sks, flush_lut, &t9, x0), // T20 = T1 + T19 = T9 + U0
                || flush_xor(sks, flush_lut, &t9, x6), // T22 = T7 + T21 = T9 + U6
            )
        },
    );

    let t23 = flush_xor(sks, flush_lut, &t22, &t2); // T23 = T2 + T22

    // `t6_pre = U4 + T13` is unflushed; T6 and T14 each XOR a single fresh
    // input bit on top, keeping noise ≤ 2 before the flush.
    let t6_pre = sks.unchecked_add(x4, &t13);
    let (t6, t14) = join(
        || flush_xor(sks, flush_lut, &t6_pre, x5), // T6  = T1 + T5
        || flush_xor(sks, flush_lut, &t6_pre, x1), // T14 = T6 + T11
    );

    let (t8, t10) = join(
        || flush_xor(sks, flush_lut, &t6, x7),  // T8  = U7 + T6
        || flush_xor(sks, flush_lut, &t6, &t7), // T10 = T6 + T7
    );

    let t15 = flush_xor(sks, flush_lut, &t14, &t1); // T15 = T5 + T11

    let ((t17, t27), (t24, t16)) = join(
        || {
            join(
                || flush_xor(sks, flush_lut, x7, &t15),   // T17 = T9 + T16
                || flush_xor(sks, flush_lut, &t10, &t15), // T27 = T1 + T12
            )
        },
        || {
            join(
                || flush_xor(sks, flush_lut, &t10, &t2), // T24 = T2 + T10
                || flush_xor(sks, flush_lut, &t7, &t15), // T16 = T5 + T12
            )
        },
    );

    let (t26, t25) = join(
        || flush_xor(sks, flush_lut, &t3, &t16), // T26 = T3 + T16
        || flush_xor(sks, flush_lut, x0, &t16),  // T25 = T20 + T17
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
/// `d` is the BP `D` input — for the forward direction this is the LSB of the
/// input byte (`U7`, our `byte.x7`). The middle layer plugs it into two ANDs
/// directly (`M4 = T19 x D` and `M48 = M39 x D`).
///
/// Naming: variables that equal a paper `M_i` carry the same index. The
/// paper's `M3, M8, M16-M18, M31-M36` are not materialized — they would each
/// cost an extra PBS — so the values computed in their place are named
/// `aux1..aux10`. `M38` and `M40` are produced via GF(2) algebraic identities
/// rather than the paper's literal `M32+M33` / `M35+M36` formulas.
fn middle_sbox(
    sks: &ServerKey,
    flush_lut: &LookupTable<Vec<u64>>,
    and_lut: &BivariateLookupTableOwned,
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

    // First AND batch: the 9 mutually independent products M1, M2, M4, M6,
    // M7, M9, M11, M12, M14 fanned out in one parallel batch.
    let and_inputs: [(&Ciphertext, &Ciphertext); 9] = [
        (&t6, &t13),  // M1  = T13 x T6
        (&t23, &t8),  // M2  = T23 x T8
        (d, &t19),    // M4  = T19 x D
        (&t3, &t16),  // M6  = T3 x T16
        (&t9, &t22),  // M7  = T22 x T9
        (&t20, &t17), // M9  = T20 x T17
        (&t1, &t15),  // M11 = T1 x T15
        (&t4, &t27),  // M12 = T4 x T27
        (&t2, &t10),  // M14 = T2 x T10
    ];
    let [m1, m2, m4, m6, m7, m9, m11, m12, m14]: [Ciphertext; 9] = and_inputs
        .into_par_iter()
        .map(|(l, r)| and(l, r, and_lut, sks))
        .collect::<Vec<_>>()
        .try_into()
        .expect("9 ANDs");

    // `aux1 = M1+M2` and `aux2 = M6+M7` stand in for the paper's `M3 = T14+M1`
    // and `M8 = T26+M6`: we delay folding in `T14`/`T26` until the `M20`/`M22`
    // flushes below, saving two PBS.
    let aux1 = sks.unchecked_add(&m2, &m1);
    let m5 = sks.unchecked_add(&m4, &m1);
    let aux2 = sks.unchecked_add(&m7, &m6);
    let m10 = sks.unchecked_add(&m9, &m6);
    let m13 = sks.unchecked_add(&m12, &m11);
    let m15 = sks.unchecked_add(&m14, &m11);
    // `aux3..aux5` are the impl-specific bound sums whose flushes land on
    // `M20..M22` (paper computes `M16..M18` then XORs `M13` and `T_i`).
    let aux3 = sks.unchecked_add(&aux1, &m13);
    let aux4 = sks.unchecked_add(&m5, &m15);
    let aux5 = sks.unchecked_add(&aux2, &m13);
    let m19 = sks.unchecked_add(&m10, &m15);

    let ((m20, m21), (m22, m23)) = join(
        || {
            join(
                || flush_xor(sks, flush_lut, &aux3, &t14),
                || flush_xor(sks, flush_lut, &aux4, &t24),
            )
        },
        || {
            join(
                || flush_xor(sks, flush_lut, &aux5, &t26),
                || flush_xor(sks, flush_lut, &m19, &t25),
            )
        },
    );

    let ((m27, m25), m24) = join(
        || {
            join(
                || flush_xor(sks, flush_lut, &m20, &m21), // M27 = M20 + M21
                || and(&m20, &m22, and_lut, sks),         // M25 = M22 x M20
            )
        },
        || flush_xor(sks, flush_lut, &m22, &m23), // M24 = M22 + M23
    );

    let (m28, m26) = join(
        || flush_xor(sks, flush_lut, &m23, &m25), // M28 = M23 + M25
        || flush_xor(sks, flush_lut, &m21, &m25), // M26 = M21 + M25
    );

    let (m29, m30) = join(
        || and(&m27, &m28, and_lut, sks), // M29 = M28 x M27
        || and(&m24, &m26, and_lut, sks), // M30 = M26 x M24
    );

    let (m37, m39) = join(
        || flush_xor(sks, flush_lut, &m29, &m21), // M37 = M21 + M29
        || flush_xor(sks, flush_lut, &m30, &m23), // M39 = M23 + M30
    );

    // `aux6..aux10` bridge to `M40` and `M38` without materializing the
    // paper's `M31..M36`. Identity: `(M23+1)·M23·(M21+M25) = 0` in GF(2)
    // collapses our 3-AND path to the same Boolean function as the paper's
    // 5-AND chain. `aux6` is unflushed; the next flush_xor folds it in
    // (noise budget `2+1 = 3 ≤ 5`).
    let aux6 = sks.unchecked_add(&m22, &m39);
    let aux7 = flush_xor(sks, flush_lut, &m28, &m39);
    let aux8 = and(&m23, &aux7, and_lut, sks);
    // {M40, aux9} both consume aux8 (and an independent second input) — parallel.
    let (m40, aux9) = join(
        || flush_xor(sks, flush_lut, &aux8, &aux6), // M40 (via GF(2) identity)
        || flush_xor(sks, flush_lut, &m28, &aux8),
    );
    let aux10 = and(&aux9, &m37, and_lut, sks);
    let m38 = flush_xor(sks, flush_lut, &m27, &aux10); // M38 (via GF(2) identity)

    // M41..M44: four independent XORs of {M37..M40}, then M45 chains on M41/M42.
    let ((m41, m42), (m43, m44)) = join(
        || {
            join(
                || flush_xor(sks, flush_lut, &m38, &m40), // M41 = M38 + M40
                || flush_xor(sks, flush_lut, &m37, &m39), // M42 = M37 + M39
            )
        },
        || {
            join(
                || flush_xor(sks, flush_lut, &m37, &m38), // M43 = M37 + M38
                || flush_xor(sks, flush_lut, &m39, &m40), // M44 = M39 + M40
            )
        },
    );
    let m45 = flush_xor(sks, flush_lut, &m42, &m41); // M45 = M42 + M41

    // Final batch of 18 mutually independent ANDs (`M46..M63`). Largest
    // fan-out point in the sbox: scheduling these in parallel keeps the PBS
    // engine busy when there are spare cores beyond the outer block-level
    // parallelism.
    let final_inputs: [(&Ciphertext, &Ciphertext); 18] = [
        (&t6, &m44),  // M46 = M44 x T6
        (&t8, &m40),  // M47 = M40 x T8
        (&m39, d),    // M48 = M39 x D
        (&t16, &m43), // M49 = M43 x T16
        (&t9, &m38),  // M50 = M38 x T9
        (&m37, &t17), // M51 = M37 x T17
        (&m42, &t15), // M52 = M42 x T15
        (&t27, &m45), // M53 = M45 x T27
        (&t10, &m41), // M54 = M41 x T10
        (&t13, &m44), // M55 = M44 x T13
        (&t23, &m40), // M56 = M40 x T23
        (&m39, &t19), // M57 = M39 x T19
        (&t3, &m43),  // M58 = M43 x T3
        (&t22, &m38), // M59 = M38 x T22
        (&m37, &t20), // M60 = M37 x T20
        (&m42, &t1),  // M61 = M42 x T1
        (&m45, &t4),  // M62 = M45 x T4
        (&m41, &t2),  // M63 = M41 x T2
    ];
    let [m46, m47, m48, m49, m50, m51, m52, m53, m54, m55, m56, m57, m58, m59, m60, m61, m62, m63]: [Ciphertext; 18] =
        final_inputs
            .into_par_iter()
            .map(|(l, r)| and(l, r, and_lut, sks))
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
///
/// Internal scratches use the `l_i` prefix following the BP paper's bottom
/// layer convention; the numbering follows our SLP order.
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

    let ((l57, l62), (l63, l64)) = join(
        || {
            join(
                || flush_xor(sks, flush_lut, &l50, &l53),
                || flush_xor(sks, flush_lut, &l52, &l58),
            )
        },
        || {
            join(
                || flush_xor(sks, flush_lut, &l49, &l58),
                || flush_xor(sks, flush_lut, &m50, &l59),
            )
        },
    );

    let l60 = sks.unchecked_add(&l46, &l57);
    // `l61` is consumed only by `flush_xor(l61, l62)`, where its internal
    // unchecked_add tolerates `noise(l61) + noise(l62) = 2 + 1 = 3 ≤ 5`.
    // Leaving it unflushed saves one PBS.
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

    // S6 = l56 xor NOT(l62) = l56 xor (l62 + 1) mod 2. `scalar_add` preserves
    // noise, saving a PBS vs `flush_not`. Same trick for S2 below.
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

pub(super) fn sbox(
    sks: &ServerKey,
    flush_lut: &LookupTable<Vec<u64>>,
    and_lut: &BivariateLookupTableOwned,
    x: &mut [Ciphertext],
) {
    let byte = SboxByte::from_state(x);
    let top = top_sbox(sks, flush_lut, byte);
    let mid = middle_sbox(sks, flush_lut, and_lut, top, byte.x7);
    let bot = bottom_sbox(sks, flush_lut, mid);

    // BP outputs S0..S7 are MSB-to-LSB; reverse to land in our LSB-first array.
    x[7] = bot.s0;
    x[6] = bot.s1;
    x[5] = bot.s2;
    x[4] = bot.s3;
    x[3] = bot.s4;
    x[2] = bot.s5;
    x[1] = bot.s6;
    x[0] = bot.s7;
}
