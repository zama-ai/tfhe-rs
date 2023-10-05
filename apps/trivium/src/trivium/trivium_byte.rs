//! This module implements the Trivium stream cipher, using u8 or FheUint8
//! for the representation of the inner bits.

use crate::static_deque::{StaticByteDeque, StaticByteDequeInput};

use tfhe::prelude::*;
use tfhe::{set_server_key, unset_server_key, FheUint8, ServerKey};

use rayon::prelude::*;

/// Internal trait specifying which operations are necessary for TriviumStreamByte generic type
pub trait TriviumByteInput<OpOutput>:
    Sized
    + Clone
    + Send
    + Sync
    + StaticByteDequeInput<OpOutput>
    + std::ops::BitXor<Output = OpOutput>
    + std::ops::BitAnd<Output = OpOutput>
    + std::ops::Shr<u8, Output = OpOutput>
    + std::ops::Shl<u8, Output = OpOutput>
    + std::ops::Add<Output = OpOutput>
{
}
impl TriviumByteInput<u8> for u8 {}
impl TriviumByteInput<u8> for &u8 {}
impl TriviumByteInput<FheUint8> for FheUint8 {}
impl TriviumByteInput<FheUint8> for &FheUint8 {}

/// TriviumStreamByte: a struct implementing the Trivium stream cipher, using T for the internal
/// representation of bits (u8 or FheUint8). To be able to compute FHE operations, it also owns
/// an Option for a ServerKey.
/// Since the original Trivium registers' sizes are not a multiple of 8, these registers (which
/// store byte-like objects) have a size that is the eighth of the closest multiple of 8 above the
/// originals' sizes.
pub struct TriviumStreamByte<T> {
    a_byte: StaticByteDeque<12, T>,
    b_byte: StaticByteDeque<11, T>,
    c_byte: StaticByteDeque<14, T>,
    fhe_key: Option<ServerKey>,
}

impl TriviumStreamByte<u8> {
    /// Constructor for `TriviumStreamByte<u8>`: arguments are the secret key and the input vector.
    /// Outputs a TriviumStream object already initialized (1152 steps have been run before
    /// returning)
    pub fn new(key: [u8; 10], iv: [u8; 10]) -> TriviumStreamByte<u8> {
        // Initialization of Trivium registers: a has the secret key, b the input vector,
        // and c a few ones.
        let mut a_byte_reg = [0u8; 12];
        let mut b_byte_reg = [0u8; 11];
        let mut c_byte_reg = [0u8; 14];

        for i in 0..10 {
            a_byte_reg[12 - 10 + i] = key[i];
            b_byte_reg[11 - 10 + i] = iv[i];
        }

        // Magic number 14, aka 00001110: this represents the 3 ones at the beginning of the c
        // registers, with additional zeros to make the register's size a multiple of 8.
        c_byte_reg[0] = 14;

        let mut ret =
            TriviumStreamByte::<u8>::new_from_registers(a_byte_reg, b_byte_reg, c_byte_reg, None);
        ret.init();
        ret
    }
}

impl TriviumStreamByte<FheUint8> {
    /// Constructor for `TriviumStream<FheUint8>`: arguments are the encrypted secret key and input
    /// vector, and the FHE server key.
    /// Outputs a TriviumStream object already initialized (1152 steps have been run before
    /// returning)
    pub fn new(
        key: [FheUint8; 10],
        iv: [u8; 10],
        server_key: &ServerKey,
    ) -> TriviumStreamByte<FheUint8> {
        set_server_key(server_key.clone());

        // Initialization of Trivium registers: a has the secret key, b the input vector,
        // and c a few ones.
        let mut a_byte_reg = [0u8; 12].map(FheUint8::encrypt_trivial);
        let mut b_byte_reg = [0u8; 11].map(FheUint8::encrypt_trivial);
        let mut c_byte_reg = [0u8; 14].map(FheUint8::encrypt_trivial);

        for i in 0..10 {
            a_byte_reg[12 - 10 + i] = key[i].clone();
            b_byte_reg[11 - 10 + i] = FheUint8::encrypt_trivial(iv[i]);
        }

        // Magic number 14, aka 00001110: this represents the 3 ones at the beginning of the c
        // registers, with additional zeros to make the register's size a multiple of 8.
        c_byte_reg[0] = FheUint8::encrypt_trivial(14u8);

        unset_server_key();
        let mut ret = TriviumStreamByte::<FheUint8>::new_from_registers(
            a_byte_reg,
            b_byte_reg,
            c_byte_reg,
            Some(server_key.clone()),
        );
        ret.init();
        ret
    }
}

impl<T> TriviumStreamByte<T>
where
    T: TriviumByteInput<T> + Send,
    for<'a> &'a T: TriviumByteInput<T>,
{
    /// Internal generic constructor: arguments are already prepared registers, and an optional FHE
    /// server key
    fn new_from_registers(
        a_register: [T; 12],
        b_register: [T; 11],
        c_register: [T; 14],
        sk: Option<ServerKey>,
    ) -> Self {
        Self {
            a_byte: StaticByteDeque::<12, T>::new(a_register),
            b_byte: StaticByteDeque::<11, T>::new(b_register),
            c_byte: StaticByteDeque::<14, T>::new(c_register),
            fhe_key: sk,
        }
    }

    /// The specification of Trivium includes running 1152 (= 18*64) unused steps to mix up the
    /// registers, before starting the proper stream
    fn init(&mut self) {
        for _ in 0..18 {
            self.next_64();
        }
    }

    /// Computes 8 potential future step of Trivium, b*8 terms in the future. This does not update
    /// registers, but rather returns with the output, the three values that will be used to
    /// update the registers, when the time is right. This function is meant to be used in
    /// parallel.
    fn get_output_and_values(&self, b: usize) -> [T; 4] {
        let n = b * 8 + 7;
        assert!(n < 65);

        let ((a1, a2, a3, a4, a5), ((b1, b2, b3, b4, b5), (c1, c2, c3, c4, c5))) = rayon::join(
            || Self::get_bytes(&self.a_byte, [91 - n, 90 - n, 68 - n, 65 - n, 92 - n]),
            || {
                rayon::join(
                    || Self::get_bytes(&self.b_byte, [82 - n, 81 - n, 77 - n, 68 - n, 83 - n]),
                    || Self::get_bytes(&self.c_byte, [109 - n, 108 - n, 86 - n, 65 - n, 110 - n]),
                )
            },
        );

        let (((temp_a, temp_b), (temp_c, a_and)), (b_and, c_and)) = rayon::join(
            || {
                rayon::join(
                    || rayon::join(|| a4 ^ a5, || b4 ^ b5),
                    || rayon::join(|| c4 ^ c5, || a1 & a2),
                )
            },
            || rayon::join(|| b1 & b2, || c1 & c2),
        );

        let (temp_a_2, temp_b_2, temp_c_2) = (temp_a.clone(), temp_b.clone(), temp_c.clone());

        let ((o, a), (b, c)) = rayon::join(
            || {
                rayon::join(
                    || (temp_a_2 ^ temp_b_2) ^ temp_c_2,
                    || temp_c ^ ((c_and) ^ a3),
                )
            },
            || rayon::join(|| temp_a ^ (a_and ^ b3), || temp_b ^ (b_and ^ c3)),
        );

        [o, a, b, c]
    }

    /// This calls `get_output_and_values` in parallel 8 times, and stores all results in a Vec.
    fn get_64_output_and_values(&self) -> Vec<[T; 4]> {
        (0..8)
            .into_par_iter()
            .map(|i| self.get_output_and_values(i))
            .collect()
    }

    /// Computes 64 turns of the stream, outputting the 64 bits (in 8 bytes) all at once in a
    /// Vec (first value is oldest, last is newest)
    pub fn next_64(&mut self) -> Vec<T> {
        match &self.fhe_key {
            Some(sk) => {
                rayon::broadcast(|_| set_server_key(sk.clone()));
            }
            None => (),
        }
        let values = self.get_64_output_and_values();
        match &self.fhe_key {
            Some(_) => {
                rayon::broadcast(|_| unset_server_key());
            }
            None => (),
        }

        let mut bytes = Vec::<T>::with_capacity(8);
        for [o, a, b, c] in values {
            self.a_byte.push(a);
            self.b_byte.push(b);
            self.c_byte.push(c);
            bytes.push(o);
        }

        bytes
    }

    /// Reconstructs a bunch of 5 bytes in a parallel fashion.
    fn get_bytes<const N: usize>(
        reg: &StaticByteDeque<N, T>,
        offsets: [usize; 5],
    ) -> (T, T, T, T, T) {
        let mut ret = offsets
            .par_iter()
            .rev()
            .map(|&i| reg.byte(i))
            .collect::<Vec<_>>();
        (
            ret.pop().unwrap(),
            ret.pop().unwrap(),
            ret.pop().unwrap(),
            ret.pop().unwrap(),
            ret.pop().unwrap(),
        )
    }
}

impl TriviumStreamByte<FheUint8> {
    pub fn get_server_key(&self) -> &ServerKey {
        self.fhe_key.as_ref().unwrap()
    }
}
