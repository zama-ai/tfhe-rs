//! TFHE implementation of the Kreyvium Algorithm

use crate::shortint::{Ciphertext, ServerKey};
use crate::transciphering::ciphers::shift_register::ShiftRegister;
use crate::transciphering::{FheKeyStream, Transcipherer};

use super::{
    KreyviumIV, KreyviumRound, KreyviumRoundInput, KreyviumRoundOutput, KreyviumState,
    KreyviumStream,
};

/// A kreyvium key encrypted in LWE, one ciphertext per bit
pub struct KreyviumFheKey {
    cts: [Ciphertext; 128],
}

impl From<[Ciphertext; 128]> for KreyviumFheKey {
    fn from(cts: [Ciphertext; 128]) -> Self {
        Self { cts }
    }
}

pub type KreyviumFheStream = KreyviumStream<Ciphertext>;

impl KreyviumFheStream {
    /// Constructor for KreyviumFheStream: arguments are the secret key, the input vector,
    /// and a ServerKey reference. Outputs a KreyviumFheStream object already initialized (1152
    /// steps have been run before returning).
    pub fn new(key: KreyviumFheKey, iv: impl Into<KreyviumIV>, sk: &ServerKey) -> Self {
        let mut state = KreyviumFheState::new(key, iv.into(), sk);
        state.warmup(sk);

        Self { state }
    }
}

impl Transcipherer for KreyviumFheStream {
    fn next_keystream_bits(&mut self, sks: &ServerKey, n_bits: usize) -> FheKeyStream {
        FheKeyStream(self.state.next_n(sks, n_bits))
    }

    fn skip(&mut self, sks: &ServerKey, n_bits: usize) {
        self.state.next_n(sks, n_bits);
    }

    fn current_counter(&self) -> u64 {
        self.state.counter
    }
}

type KreyviumFheState = KreyviumState<Ciphertext>;

impl KreyviumFheState {
    pub fn new(key: KreyviumFheKey, iv: KreyviumIV, sk: &ServerKey) -> Self {
        let mut key = key.cts;
        let mut iv = iv.expand().map(|b| b as u64);

        // Initialization of Kreyvium registers: a has the secret key, b the beginning of the IV,
        // c the end of the iv and padding 1s.
        let mut a_register: [Ciphertext; 93] = [0; 93].map(|x| sk.create_trivial(x));
        let mut b_register: [Ciphertext; 84] = [0; 84].map(|x| sk.create_trivial(x));
        let mut c_register: [Ciphertext; 111] = [0; 111].map(|x| sk.create_trivial(x));

        for i in 0..93 {
            a_register[i].clone_from(&key[128 - 93 + i]);
        }
        for i in 0..84 {
            b_register[i] = sk.create_trivial(iv[128 - 84 + i]);
        }
        for i in 0..44 {
            c_register[111 - 44 + i] = sk.create_trivial(iv[i]);
        }
        for i in 0..66 {
            c_register[i + 1] = sk.create_trivial(1);
        }

        key.reverse();
        iv.reverse();
        let iv = iv.map(|x| sk.create_trivial(x));

        Self {
            a: ShiftRegister::new(a_register),
            b: ShiftRegister::new(b_register),
            c: ShiftRegister::new(c_register),
            k: ShiftRegister::new(key),
            iv: ShiftRegister::new(iv),
            counter: 0,
        }
    }
}

type KreyviumFheRoundInput<'a> = KreyviumRoundInput<'a, Ciphertext>;

impl KreyviumRound for KreyviumFheRoundInput<'_> {
    type AuxData = ServerKey;
    type Bit = Ciphertext;

    /// Kreyvium round. Output keystream bit is a clean single-bit ciphertext
    /// (degree 1, value in {0, 1}).
    fn round(self, sk: &Self::AuxData) -> KreyviumRoundOutput<Self::Bit> {
        if sk.message_modulus.0 == 4 && sk.carry_modulus.0 == 4 {
            round_2_2(&self, sk)
        } else {
            round_naive(&self, sk)
        }
    }
}

/// Kreyvium round optimized for MESSAGE_2_CARRY_2.
fn round_2_2(input: &KreyviumFheRoundInput<'_>, sk: &ServerKey) -> KreyviumRoundOutput<Ciphertext> {
    // Peak noise of the algo is 4 (new_b).
    // Regarding degree: `unchecked_bitand` in the next round is a bivariate PBS and requires
    // carry-empty operands, so register updates end with `message_extract`.
    // We don't need anything stricter (e.g. masking to a single bit): the
    // cipher reads only the low bit of each cell, so the high message bit is
    // free to hold whatever `message_extract` leaves there.
    assert!(
        sk.max_noise_level.get() >= 4,
        "round_2_2 needs max_noise_level >= 4, got {}",
        sk.max_noise_level.get(),
    );

    let KreyviumRoundInput {
        a: (a1, a2, a3, a4, a5),
        b: (b1, b2, b3, b4, b5),
        c: (c1, c2, c3, c4, c5),
        k,
        iv,
    } = input;

    for ct in [a3, a4, b3, b4, c3, c4] {
        assert!(
            ct.carry_is_empty(),
            "bivariate bitand operand carry not empty: degree {}, message_modulus {}",
            ct.degree.get(),
            sk.message_modulus.0,
        );
    }

    let temp_a = sk.unchecked_add(a1, a2);
    let temp_b = sk.unchecked_add(b1, b2);
    let mut temp_c = sk.unchecked_add(c1, c2);
    sk.unchecked_add_assign(&mut temp_c, k);

    let ((a, b), (c, output)) = rayon::join(
        || {
            rayon::join(
                || {
                    let mut new_a = sk.unchecked_bitand(c3, c4);
                    sk.unchecked_add_assign(&mut new_a, a5);
                    sk.unchecked_add_assign(&mut new_a, &temp_c);
                    sk.message_extract_assign(&mut new_a);
                    new_a
                },
                || {
                    let mut new_b = sk.unchecked_bitand(a3, a4);
                    sk.unchecked_add_assign(&mut new_b, b5);
                    sk.unchecked_add_assign(&mut new_b, &temp_a);
                    sk.unchecked_add_assign(&mut new_b, iv);
                    sk.message_extract_assign(&mut new_b);
                    new_b
                },
            )
        },
        || {
            rayon::join(
                || {
                    let mut new_c = sk.unchecked_bitand(b3, b4);
                    sk.unchecked_add_assign(&mut new_c, c5);
                    sk.unchecked_add_assign(&mut new_c, &temp_b);
                    sk.message_extract_assign(&mut new_c);
                    new_c
                },
                || {
                    let lhs = sk.unchecked_add(&temp_a, &temp_b);
                    let xor_low_bit = sk.generate_lookup_table_bivariate(|x, y| (x ^ y) & 1);
                    sk.apply_lookup_table_bivariate(&lhs, &temp_c, &xor_low_bit)
                },
            )
        },
    );
    KreyviumRoundOutput { output, a, b, c }
}

/// Param-agnostic fallback round, assuming tight params
/// (e.g. 1_1: `max_noise_level = 3`, `MSG_MOD*CARRY_MOD = 4`)
/// Costs 3 extra PBS per round versus `round_2_2`.
fn round_naive(
    input: &KreyviumFheRoundInput<'_>,
    sk: &ServerKey,
) -> KreyviumRoundOutput<Ciphertext> {
    // Peak noise of the algo is 3 (temp_c and new_b).
    // Regarding degree: `unchecked_bitand` in the next round is a bivariate PBS and requires
    // carry-empty operands, so register updates end with `message_extract`.
    // We don't need anything stricter (e.g. masking to a single bit): the
    // cipher reads only the low bit of each cell, so the high message bit is
    // free to hold whatever `message_extract` leaves there.
    assert!(
        sk.max_noise_level.get() >= 3,
        "round_naive needs max_noise_level >= 3, got {}",
        sk.max_noise_level.get(),
    );

    let KreyviumRoundInput {
        a: (a1, a2, a3, a4, a5),
        b: (b1, b2, b3, b4, b5),
        c: (c1, c2, c3, c4, c5),
        k,
        iv,
    } = input;

    for ct in [a3, a4, b3, b4, c3, c4] {
        assert!(
            ct.carry_is_empty(),
            "bivariate bitand operand carry not empty: degree {}, message_modulus {}",
            ct.degree.get(),
            sk.message_modulus.0,
        );
    }

    let (temp_a, (temp_b, temp_c)) = rayon::join(
        || {
            let mut t = sk.unchecked_add(a1, a2);
            sk.message_extract_assign(&mut t);
            t
        },
        || {
            rayon::join(
                || {
                    let mut t = sk.unchecked_add(b1, b2);
                    sk.message_extract_assign(&mut t);
                    t
                },
                || {
                    let mut t = sk.unchecked_add(c1, c2);
                    sk.unchecked_add_assign(&mut t, k);
                    sk.message_extract_assign(&mut t);
                    t
                },
            )
        },
    );

    let ((a, b), (c, output)) = rayon::join(
        || {
            rayon::join(
                || {
                    let mut new_a = sk.unchecked_bitand(c3, c4);
                    sk.unchecked_add_assign(&mut new_a, a5);
                    sk.add_assign(&mut new_a, &temp_c);
                    new_a
                },
                || {
                    let mut new_b = sk.unchecked_bitand(a3, a4);
                    sk.unchecked_add_assign(&mut new_b, b5);
                    sk.unchecked_add_assign(&mut new_b, &temp_a);
                    sk.add_assign(&mut new_b, iv);
                    new_b
                },
            )
        },
        || {
            rayon::join(
                || {
                    let mut new_c = sk.unchecked_bitand(b3, b4);
                    sk.unchecked_add_assign(&mut new_c, c5);
                    sk.add_assign(&mut new_c, &temp_b);
                    new_c
                },
                || sk.bitxor(&sk.unchecked_add(&temp_a, &temp_b), &temp_c),
            )
        },
    );
    KreyviumRoundOutput { output, a, b, c }
}
