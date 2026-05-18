//! Plaintext implementation of the Kreyvium Algorithm

use crate::transciphering::ciphers::shift_register::ShiftRegister;
use crate::transciphering::{StreamCipher, TranscipheringCipherKind};

use super::{
    KreyviumRound, KreyviumRoundInput, KreyviumRoundOutput, KreyviumState, KreyviumStream,
};

/// Pack `bits` into `bytes` LSB-first within each byte. `bytes` must be
/// zero-initialized and at least `bits.len().div_ceil(8)` long.
fn pack_bits_lsb_first(bits: &[bool], bytes: &mut [u8]) {
    for (i, &bit) in bits.iter().enumerate() {
        if bit {
            bytes[i / 8] |= 1 << (i % 8);
        }
    }
}

pub struct KreyviumSymmetricKey {
    bits: [u8; 16],
}

impl KreyviumSymmetricKey {
    /// Expand the packed 128-bit key into one bit per byte (LSB-first within
    /// each input byte), suitable for loading into the K shift register.
    fn expand(self) -> [bool; 128] {
        let mut out = [false; 128];
        for (b, &byte) in self.bits.iter().enumerate() {
            for j in 0..8 {
                out[8 * b + j] = ((byte >> j) & 1) == 1;
            }
        }
        out
    }
}

impl From<[u8; 16]> for KreyviumSymmetricKey {
    fn from(value: [u8; 16]) -> Self {
        Self { bits: value }
    }
}

impl From<[bool; 128]> for KreyviumSymmetricKey {
    fn from(value: [bool; 128]) -> Self {
        let mut bits = [0u8; 16];
        pack_bits_lsb_first(&value, &mut bits);
        Self { bits }
    }
}

pub type KreyviumPlainStream = KreyviumStream<bool>;

impl KreyviumPlainStream {
    /// Constructor for `KreyviumPlainStream`: arguments are the secret key and the input vector.
    /// Outputs a KreyviumStream object already initialized (1152 steps have been run before
    /// returning)
    pub fn new(key: KreyviumSymmetricKey, iv: [bool; 128]) -> Self {
        let mut state = KreyviumPlainState::new(key, iv);
        state.warmup(&());

        Self { state }
    }
}

impl StreamCipher for KreyviumPlainStream {
    fn kind(&self) -> TranscipheringCipherKind {
        TranscipheringCipherKind::Kreyvium
    }

    fn next_keystream_bits(&mut self, n_bits: usize) -> Vec<u8> {
        let bits = self.state.next_n(&(), n_bits);
        let mut result = vec![0u8; n_bits.div_ceil(8)];
        pack_bits_lsb_first(&bits, &mut result);
        result
    }

    fn skip(&mut self, n_bits: usize) {
        self.state.next_n(&(), n_bits);
    }

    fn current_counter(&self) -> u64 {
        self.state.counter
    }
}

type KreyviumPlainState = KreyviumState<bool>;

impl KreyviumPlainState {
    pub fn new(key: KreyviumSymmetricKey, mut iv: [bool; 128]) -> Self {
        let mut key = key.expand();

        // Initialization of Kreyvium registers: a has the secret key, b the beginning of the IV,
        // c the end of the iv and padding 1s.
        let mut a_register = [false; 93];
        let mut b_register = [false; 84];
        let mut c_register = [false; 111];

        for i in 0..93 {
            a_register[i] = key[128 - 93 + i];
        }
        for i in 0..84 {
            b_register[i] = iv[128 - 84 + i];
        }
        for i in 0..44 {
            c_register[111 - 44 + i] = iv[i];
        }
        for i in 0..66 {
            c_register[i + 1] = true;
        }

        key.reverse();
        iv.reverse();
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

type KreyviumPlainRoundInput<'a> = KreyviumRoundInput<'a, bool>;

impl KreyviumRound for KreyviumPlainRoundInput<'_> {
    type AuxData = ();

    type Bit = bool;

    fn round(self, _aux: &Self::AuxData) -> KreyviumRoundOutput<Self::Bit> {
        let Self {
            a: (a1, a2, a3, a4, a5),
            b: (b1, b2, b3, b4, b5),
            c: (c1, c2, c3, c4, c5),
            k,
            iv,
        } = self;

        let temp_a = a1 ^ a2;
        let temp_b = b1 ^ b2;

        let temp_c = (c1 ^ c2) ^ k;

        let a_and = (a3 & a4) ^ iv;
        let b_and = b3 & b4;
        let c_and = c3 & c4;

        let output = (temp_a ^ temp_b) ^ temp_c;
        let a = temp_c ^ (c_and ^ a5);
        let b = temp_a ^ (a_and ^ b5);
        let c = temp_b ^ (b_and ^ c5);

        KreyviumRoundOutput { output, a, b, c }
    }
}
