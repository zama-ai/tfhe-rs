//! TFHE implementation of the Kreyvium Algorithm

use crate::core_crypto::commons::traits::Container;
use crate::shortint::ciphertext::NoiseLevel;
use crate::shortint::oprf::GenericOprfServerKey;
use crate::shortint::{Ciphertext, ClientKey, ServerKey};
use crate::transciphering::ciphers::shift_register::ShiftRegister;
use crate::transciphering::{FheKeyStream, KreyviumPlainKey, StreamCipherKind, Transcipherer};
use crate::OprfSeed;
use tfhe_fft::c64;

use super::{
    collect_boxed_array, KreyviumBackwardRoundOutput, KreyviumIV, KreyviumRound,
    KreyviumRoundInput, KreyviumRoundOutput, KreyviumState,
};

/// A kreyvium key encrypted in LWE, one ciphertext per bit
pub struct KreyviumFheKey {
    cts: Box<[Ciphertext; 128]>,
}

impl KreyviumFheKey {
    pub(super) fn new(cts: Box<[Ciphertext; 128]>) -> Self {
        for (i, ct) in cts.iter().enumerate() {
            assert!(
                ct.degree.get() <= 1,
                "kreyvium key ciphertext {i} is not a single bit (degree {})",
                ct.degree.get(),
            );
            assert!(
                ct.noise_level() <= NoiseLevel::NOMINAL,
                "kreyvium key ciphertext {i} exceeds nominal noise (level {:?})",
                ct.noise_level(),
            );
        }
        Self { cts }
    }

    pub fn random<C>(
        seed: impl OprfSeed,
        oprf_key: &GenericOprfServerKey<C>,
        sks: &ServerKey,
    ) -> Self
    where
        C: Container<Element = c64> + Sync,
    {
        let encrypted_bits = oprf_key.generate_random_boolean_sequence(seed, 128, sks);
        // Unwrap should not happen because the vec has 128 elements
        let boxed: Box<[Ciphertext; 128]> = encrypted_bits.into_boxed_slice().try_into().unwrap();

        Self::new(boxed)
    }

    pub fn init_state(self, iv: KreyviumIV, sk: &ServerKey) -> KreyviumFheState {
        KreyviumFheState::new(self, iv, sk)
    }

    /// Decrypt the key bits
    pub fn decrypt(&self, client_key: &ClientKey) -> KreyviumPlainKey {
        let mut decrypted_bits = [false; 128];
        for (ct, out) in self.cts.iter().zip(decrypted_bits.iter_mut()) {
            *out = client_key.decrypt(ct) != 0;
        }
        KreyviumPlainKey::from(decrypted_bits)
    }

    /// Borrow the underlying 128 single-bit shortint ciphertexts, MSB-first
    /// within each byte of the packed key (see [`super::KreyviumPlainKey`]).
    pub fn ciphertexts(&self) -> &[Ciphertext; 128] {
        &self.cts
    }
}

pub type KreyviumFheState = KreyviumState<Ciphertext>;

impl KreyviumFheState {
    /// Constructor for `KreyviumFheState`: arguments are the secret key, the input vector,
    /// and a `ServerKey` reference. Outputs a state object already initialized
    /// (1152 steps have been run before returning).
    pub fn new(key: KreyviumFheKey, iv: impl Into<KreyviumIV>, sk: &ServerKey) -> Self {
        let mut key = key.cts;
        let mut iv = iv.into().expand().map(|b| b as u64);

        // Initialization of Kreyvium registers: a has the secret key, b the beginning of the IV,
        // c the end of the iv and padding 1s.
        let mut a_register: Box<[Ciphertext; 93]> =
            collect_boxed_array((0..93).map(|_| sk.create_trivial(0)))
                .expect("array and iter size match");
        let mut b_register: Box<[Ciphertext; 84]> =
            collect_boxed_array((0..84).map(|_| sk.create_trivial(0)))
                .expect("array and iter size match");
        let mut c_register: Box<[Ciphertext; 111]> =
            collect_boxed_array((0..111).map(|_| sk.create_trivial(0)))
                .expect("array and iter size match");

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
        let iv: Box<[Ciphertext; 128]> =
            collect_boxed_array(iv.iter().map(|&x| sk.create_trivial(x)))
                .expect("array and iter size match");

        let mut state = Self {
            a: ShiftRegister::new(a_register),
            b: ShiftRegister::new(b_register),
            c: ShiftRegister::new(c_register),
            k: ShiftRegister::new(key),
            iv: ShiftRegister::new(iv),
            counter: 0,
        };
        state.warmup(sk);
        state
    }
}

impl Transcipherer for KreyviumFheState {
    fn kind(&self) -> StreamCipherKind {
        StreamCipherKind::Kreyvium
    }

    fn next_keystream_bits(&mut self, sks: &ServerKey, n_bits: usize) -> FheKeyStream {
        FheKeyStream(self.next_n(sks, n_bits))
    }

    fn seek(&mut self, sks: &ServerKey, target_counter: u64) {
        self.seek_to(sks, target_counter)
    }

    fn current_counter(&self) -> u64 {
        self.counter
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

    fn backward_round(self, sk: &Self::AuxData) -> KreyviumBackwardRoundOutput<Self::Bit> {
        if sk.message_modulus.0 == 4 && sk.carry_modulus.0 == 4 {
            backward_round_2_2(&self, sk)
        } else {
            backward_round_naive(&self, sk)
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

    for (l, r) in [(a3, a4), (b3, b4), (c3, c4)] {
        sk.is_functional_bivariate_pbs_possible(l.noise_degree(), r.noise_degree(), None)
            .expect("bivariate bitand precondition violated for kreyvium round_2_2");
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

    for (l, r) in [(a3, a4), (b3, b4), (c3, c4)] {
        sk.is_functional_bivariate_pbs_possible(l.noise_degree(), r.noise_degree(), None)
            .expect("bivariate bitand precondition violated for kreyvium round_naive");
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

/// Backward Kreyvium round optimized for MESSAGE_2_CARRY_2.
fn backward_round_2_2(
    input: &KreyviumFheRoundInput<'_>,
    sk: &ServerKey,
) -> KreyviumBackwardRoundOutput<Ciphertext> {
    assert!(
        sk.max_noise_level.get() >= 4,
        "backward_round_2_2 needs max_noise_level >= 4, got {}",
        sk.max_noise_level.get(),
    );

    let KreyviumRoundInput {
        a: (new_a, a1, a3, a4, a5),
        b: (new_b, b1, b3, b4, b5),
        c: (new_c, c1, c3, c4, c5),
        k,
        iv,
    } = input;

    for (l, r) in [(a3, a4), (b3, b4), (c3, c4)] {
        sk.is_functional_bivariate_pbs_possible(l.noise_degree(), r.noise_degree(), None)
            .expect("bivariate bitand precondition violated for kreyvium backward_round_2_2");
    }

    let (a, (b, c)) = rayon::join(
        || {
            // new_b = a1 ^ a2 ^ (a3 & a4) ^ iv ^ b5
            // so
            // a2 = (a3 & a4) ^ new_b ^ a1 ^ b5 ^ iv
            let mut a2 = sk.unchecked_bitand(a3, a4);
            sk.unchecked_add_assign(&mut a2, new_b);
            sk.unchecked_add_assign(&mut a2, a1);
            sk.unchecked_add_assign(&mut a2, b5);
            sk.unchecked_add_assign(&mut a2, iv);
            sk.message_extract_assign(&mut a2);
            a2
        },
        || {
            rayon::join(
                || {
                    // new_c = b1 ^ b2 ^ (b3 & b4) ^ c5
                    // so
                    // b2 = (b3 & b4) ^ new_c ^ b1 ^ c5
                    let mut b2 = sk.unchecked_bitand(b3, b4);
                    sk.unchecked_add_assign(&mut b2, new_c);
                    sk.unchecked_add_assign(&mut b2, b1);
                    sk.unchecked_add_assign(&mut b2, c5);
                    sk.message_extract_assign(&mut b2);
                    b2
                },
                || {
                    // new_a = c1 ^ c2 ^ (c3 & c3) ^ a5 ^ k
                    // so
                    // c2 = (c3 & c4) ^ new_a ^ c1 ^ a5 ^ k
                    let mut c2 = sk.unchecked_bitand(c3, c4);
                    sk.unchecked_add_assign(&mut c2, new_a);
                    sk.unchecked_add_assign(&mut c2, c1);
                    sk.unchecked_add_assign(&mut c2, a5);
                    sk.unchecked_add_assign(&mut c2, k);
                    sk.message_extract_assign(&mut c2);
                    c2
                },
            )
        },
    );

    KreyviumBackwardRoundOutput { a, b, c }
}

/// Param-agnostic fallback backward round, mirroring [`round_naive`]
fn backward_round_naive(
    input: &KreyviumFheRoundInput<'_>,
    sk: &ServerKey,
) -> KreyviumBackwardRoundOutput<Ciphertext> {
    assert!(
        sk.max_noise_level.get() >= 3,
        "backward_round_naive needs max_noise_level >= 3, got {}",
        sk.max_noise_level.get(),
    );

    let KreyviumRoundInput {
        a: (new_a, a1, a3, a4, a5),
        b: (new_b, b1, b3, b4, b5),
        c: (new_c, c1, c3, c4, c5),
        k,
        iv,
    } = input;

    for (l, r) in [(a3, a4), (b3, b4), (c3, c4)] {
        sk.is_functional_bivariate_pbs_possible(l.noise_degree(), r.noise_degree(), None)
            .expect("bivariate bitand precondition violated for kreyvium backward_round_naive");
    }

    let (a, (b, c)) = rayon::join(
        || {
            // new_b = a1 ^ a2 ^ (a3 & a4) ^ iv ^ b5
            // so
            // a2 = (a3 & a4) ^ new_b ^ a1 ^ b5 ^ iv
            let mut a2 = sk.unchecked_bitand(a3, a4);
            sk.unchecked_add_assign(&mut a2, new_b);
            sk.unchecked_add_assign(&mut a2, a1);
            sk.add_assign(&mut a2, b5);
            sk.add_assign(&mut a2, iv);
            sk.message_extract_assign(&mut a2);
            a2
        },
        || {
            rayon::join(
                || {
                    // new_c = b1 ^ b2 ^ (b3 & b4) ^ c5
                    // so
                    // b2 = (b3 & b4) ^ new_c ^ b1 ^ c5
                    let mut b2 = sk.unchecked_bitand(b3, b4);
                    sk.unchecked_add_assign(&mut b2, new_c);
                    sk.unchecked_add_assign(&mut b2, b1);
                    sk.add_assign(&mut b2, c5);
                    sk.message_extract_assign(&mut b2);
                    b2
                },
                || {
                    // new_a = c1 ^ c2 ^ (c3 & c4) ^ a5 ^ k
                    // so
                    // c2 = (c3 & c4) ^ new_a ^ c1 ^ a5 ^ k
                    let mut c2 = sk.unchecked_bitand(c3, c4);
                    sk.unchecked_add_assign(&mut c2, new_a);
                    sk.unchecked_add_assign(&mut c2, c1);
                    sk.add_assign(&mut c2, a5);
                    sk.add_assign(&mut c2, k);
                    sk.message_extract_assign(&mut c2);
                    c2
                },
            )
        },
    );

    KreyviumBackwardRoundOutput { a, b, c }
}
