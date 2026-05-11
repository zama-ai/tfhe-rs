//! Plaintext implementation of the Kreyvium Algorithm

use crate::shortint::ClientKey;
use crate::transciphering::ciphers::shift_register::ShiftRegister;
use crate::transciphering::ciphers::{pack_bits_lsb_first, unpack_bits_lsb_first};
use crate::transciphering::{StreamCipher, StreamCipherKind};

use super::{
    KreyviumBackwardRoundOutput, KreyviumFheKey, KreyviumRound, KreyviumRoundInput,
    KreyviumRoundOutput, KreyviumState,
};

fn unpack_key_bits(bytes: &[u8; 16]) -> [bool; 128] {
    let mut out = [false; 128];
    unpack_bits_lsb_first(bytes, &mut out);
    out
}

pub struct KreyviumPlainKey {
    bits: [u8; 16],
}

impl KreyviumPlainKey {
    /// Expand the packed 128-bit key into one bit per byte (LSB-first within
    /// each input byte), suitable for loading into the K shift register.
    pub(super) fn expand(self) -> [bool; 128] {
        unpack_key_bits(&self.bits)
    }

    /// Encrypt this key bit-by-bit under `client_key`, producing the FHE-side
    /// key consumed by [`KreyviumFheState`](super::KreyviumFheState).
    pub fn encrypt(&self, client_key: &ClientKey) -> KreyviumFheKey {
        super::collect_boxed_array(
            unpack_key_bits(&self.bits)
                .iter()
                .map(|&b| client_key.encrypt(b as u64)),
        )
        .expect("array and iter size match")
        .into()
    }

    pub fn init_state(self, iv: KreyviumIV) -> KreyviumPlainState {
        KreyviumPlainState::new(self, iv)
    }
}

impl From<[u8; 16]> for KreyviumPlainKey {
    fn from(value: [u8; 16]) -> Self {
        Self { bits: value }
    }
}

impl From<[bool; 128]> for KreyviumPlainKey {
    fn from(value: [bool; 128]) -> Self {
        let mut bits = [0u8; 16];
        pack_bits_lsb_first(&value, &mut bits);
        Self { bits }
    }
}

pub struct KreyviumIV {
    bits: [u8; 16],
}

impl KreyviumIV {
    /// Expand the packed 128-bit IV into one bit per byte (LSB-first within
    /// each input byte), suitable for loading into the IV shift register.
    pub(super) fn expand(self) -> [bool; 128] {
        unpack_key_bits(&self.bits)
    }
}

impl From<[u8; 16]> for KreyviumIV {
    fn from(value: [u8; 16]) -> Self {
        Self { bits: value }
    }
}

impl From<[bool; 128]> for KreyviumIV {
    fn from(value: [bool; 128]) -> Self {
        let mut bits = [0u8; 16];
        pack_bits_lsb_first(&value, &mut bits);
        Self { bits }
    }
}

pub type KreyviumPlainState = KreyviumState<bool>;

impl KreyviumPlainState {
    /// Constructor for `KreyviumPlainState`: arguments are the secret key and the input vector.
    /// Outputs a state already initialized (1152 steps have been run before returning)
    pub fn new(key: impl Into<KreyviumPlainKey>, iv: impl Into<KreyviumIV>) -> Self {
        let mut key = key.into().expand();
        let mut iv = iv.into().expand();

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
        let mut state = Self {
            a: ShiftRegister::new(Box::new(a_register)),
            b: ShiftRegister::new(Box::new(b_register)),
            c: ShiftRegister::new(Box::new(c_register)),
            k: ShiftRegister::new(Box::new(key)),
            iv: ShiftRegister::new(Box::new(iv)),
            counter: 0,
        };
        state.warmup(&());
        state
    }
}

impl StreamCipher for KreyviumPlainState {
    fn kind(&self) -> StreamCipherKind {
        StreamCipherKind::Kreyvium
    }

    fn next_keystream_bits(&mut self, n_bits: usize) -> Vec<u8> {
        let bits = self.next_n(&(), n_bits);
        let mut result = vec![0u8; n_bits.div_ceil(8)];
        pack_bits_lsb_first(&bits, &mut result);
        result
    }

    fn seek(&mut self, target_counter: u64) {
        self.seek_to(&(), target_counter)
    }

    fn current_counter(&self) -> u64 {
        self.counter
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

    fn backward_round(self, _aux: &Self::AuxData) -> KreyviumBackwardRoundOutput<Self::Bit> {
        let Self {
            a: (new_a, a1, a3, a4, a5),
            b: (new_b, b1, b3, b4, b5),
            c: (new_c, c1, c3, c4, c5),
            k,
            iv,
        } = self;

        // Recover the bits destroyed at the forward step (see backward derivation in mod.rs):
        let a = new_b ^ a1 ^ (a3 & a4) ^ iv ^ b5;
        let b = new_c ^ b1 ^ (b3 & b4) ^ c5;
        let c = new_a ^ c1 ^ (c3 & c4) ^ a5 ^ k;

        KreyviumBackwardRoundOutput { a, b, c }
    }
}
