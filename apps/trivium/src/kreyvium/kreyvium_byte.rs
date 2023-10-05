//! This module implements the Kreyvium stream cipher, using u8 or FheUint8
//! for the representation of the inner bits.

use crate::static_deque::{StaticByteDeque, StaticByteDequeInput};

use tfhe::prelude::*;
use tfhe::{set_server_key, unset_server_key, FheUint8, ServerKey};

use rayon::prelude::*;

/// Internal trait specifying which operations are necessary for KreyviumStreamByte generic type
pub trait KreyviumByteInput<OpOutput>:
    Sized
    + Send
    + Sync
    + Clone
    + StaticByteDequeInput<OpOutput>
    + std::ops::BitXor<Output = OpOutput>
    + std::ops::BitAnd<Output = OpOutput>
    + std::ops::Shr<u8, Output = OpOutput>
    + std::ops::Shl<u8, Output = OpOutput>
    + std::ops::Add<Output = OpOutput>
{
}
impl KreyviumByteInput<u8> for u8 {}
impl KreyviumByteInput<u8> for &u8 {}
impl KreyviumByteInput<FheUint8> for FheUint8 {}
impl KreyviumByteInput<FheUint8> for &FheUint8 {}

/// KreyviumStreamByte: a struct implementing the Kreyvium stream cipher, using T for the internal
/// representation of bits (u8 or FheUint8). To be able to compute FHE operations, it also owns
/// an Option for a ServerKey.
/// Since the original Kreyvium registers' sizes are not a multiple of 8, these registers (which
/// store byte-like objects) have a size that is the eighth of the closest multiple of 8 above the
/// originals' sizes.
pub struct KreyviumStreamByte<T> {
    a_byte: StaticByteDeque<12, T>,
    b_byte: StaticByteDeque<11, T>,
    c_byte: StaticByteDeque<14, T>,
    k_byte: StaticByteDeque<16, T>,
    iv_byte: StaticByteDeque<16, T>,
    fhe_key: Option<ServerKey>,
}

impl KreyviumStreamByte<u8> {
    /// Constructor for `KreyviumStreamByte<u8>`: arguments are the secret key and the input vector.
    /// Outputs a KreyviumStream object already initialized (1152 steps have been run before
    /// returning)
    pub fn new(key_bytes: [u8; 16], iv_bytes: [u8; 16]) -> KreyviumStreamByte<u8> {
        // Initialization of Kreyvium registers: a has the secret key, b the input vector,
        // and c a few ones.
        let mut a_byte_reg = [0u8; 12];
        let mut b_byte_reg = [0u8; 11];
        let mut c_byte_reg = [0u8; 14];

        // Copy key bits into a register
        a_byte_reg.copy_from_slice(&key_bytes[4..]);

        // Copy iv bits into a register
        b_byte_reg.copy_from_slice(&iv_bytes[5..]);

        // Copy a lot of ones in the c register
        c_byte_reg[0] = 252;
        c_byte_reg[1..8].fill(255);

        // Copy iv bits in the c register
        c_byte_reg[8] = (iv_bytes[0] << 4) | 31;
        for b in 9..14 {
            c_byte_reg[b] = (iv_bytes[b - 9] >> 4) | (iv_bytes[b - 8] << 4);
        }

        // Key and iv are stored in reverse in their shift registers
        let mut key = key_bytes.map(|b| b.reverse_bits());
        let mut iv = iv_bytes.map(|b| b.reverse_bits());
        key.reverse();
        iv.reverse();

        let mut ret = KreyviumStreamByte::<u8>::new_from_registers(
            a_byte_reg, b_byte_reg, c_byte_reg, key, iv, None,
        );
        ret.init();
        ret
    }
}

impl KreyviumStreamByte<FheUint8> {
    /// Constructor for `KreyviumStream<FheUint8>`: arguments are the encrypted secret key and input
    /// vector, and the FHE server key.
    /// Outputs a KreyviumStream object already initialized (1152 steps have been run before
    /// returning)
    pub fn new(
        key_bytes: [FheUint8; 16],
        iv_bytes: [u8; 16],
        server_key: &ServerKey,
    ) -> KreyviumStreamByte<FheUint8> {
        set_server_key(server_key.clone());

        // Initialization of Kreyvium registers: a has the secret key, b the input vector,
        // and c a few ones.
        let mut a_byte_reg = [0u8; 12].map(FheUint8::encrypt_trivial);
        let mut b_byte_reg = [0u8; 11].map(FheUint8::encrypt_trivial);
        let mut c_byte_reg = [0u8; 14].map(FheUint8::encrypt_trivial);

        // Copy key bits into a register
        a_byte_reg.clone_from_slice(&key_bytes[4..]);

        // Copy iv bits into a register
        for b in 0..11 {
            b_byte_reg[b] = FheUint8::encrypt_trivial(iv_bytes[b + 5]);
        }
        // Copy a lot of ones in the c register
        c_byte_reg[0] = FheUint8::encrypt_trivial(252u8);

        c_byte_reg[1..8].fill_with(|| FheUint8::encrypt_trivial(255u8));

        // Copy iv bits in the c register
        c_byte_reg[8] = FheUint8::encrypt_trivial((&iv_bytes[0] << 4u8) | 31u8);
        for b in 9..14 {
            c_byte_reg[b] =
                FheUint8::encrypt_trivial((&iv_bytes[b - 9] >> 4u8) | (&iv_bytes[b - 8] << 4u8));
        }

        // Key and iv are stored in reverse in their shift registers
        let mut key = key_bytes.map(|b| b.map(|x| (x as u8).reverse_bits() as u64));
        let mut iv = iv_bytes.map(|x| FheUint8::encrypt_trivial(x.reverse_bits()));
        key.reverse();
        iv.reverse();

        unset_server_key();

        let mut ret = KreyviumStreamByte::<FheUint8>::new_from_registers(
            a_byte_reg,
            b_byte_reg,
            c_byte_reg,
            key,
            iv,
            Some(server_key.clone()),
        );
        ret.init();
        ret
    }
}

impl<T> KreyviumStreamByte<T>
where
    T: KreyviumByteInput<T> + Send,
    for<'a> &'a T: KreyviumByteInput<T>,
{
    /// Internal generic constructor: arguments are already prepared registers, and an optional FHE
    /// server key
    fn new_from_registers(
        a_register: [T; 12],
        b_register: [T; 11],
        c_register: [T; 14],
        k_register: [T; 16],
        iv_register: [T; 16],
        sk: Option<ServerKey>,
    ) -> Self {
        Self {
            a_byte: StaticByteDeque::<12, T>::new(a_register),
            b_byte: StaticByteDeque::<11, T>::new(b_register),
            c_byte: StaticByteDeque::<14, T>::new(c_register),
            k_byte: StaticByteDeque::<16, T>::new(k_register),
            iv_byte: StaticByteDeque::<16, T>::new(iv_register),
            fhe_key: sk,
        }
    }

    /// The specification of Kreyvium includes running 1152 (= 18*64) unused steps to mix up the
    /// registers, before starting the proper stream
    fn init(&mut self) {
        for _ in 0..18 {
            self.next_64();
        }
    }

    /// Computes 8 potential future step of Kreyvium, b*8 terms in the future. This does not update
    /// registers, but rather returns with the output, the three values that will be used to
    /// update the registers, when the time is right. This function is meant to be used in
    /// parallel.
    fn get_output_and_values(&self, b: usize) -> [T; 4] {
        let n = b * 8 + 7;
        assert!(n < 65);

        let (((k, iv), (a1, a2, a3, a4, a5)), ((b1, b2, b3, b4, b5), (c1, c2, c3, c4, c5))) =
            rayon::join(
                || {
                    rayon::join(
                        || (self.k_byte.byte(127 - n), self.iv_byte.byte(127 - n)),
                        || Self::get_bytes(&self.a_byte, [91 - n, 90 - n, 68 - n, 65 - n, 92 - n]),
                    )
                },
                || {
                    rayon::join(
                        || Self::get_bytes(&self.b_byte, [82 - n, 81 - n, 77 - n, 68 - n, 83 - n]),
                        || {
                            Self::get_bytes(
                                &self.c_byte,
                                [109 - n, 108 - n, 86 - n, 65 - n, 110 - n],
                            )
                        },
                    )
                },
            );

        let (((temp_a, temp_b), (temp_c, a_and)), (b_and, c_and)) = rayon::join(
            || {
                rayon::join(
                    || rayon::join(|| a4 ^ a5, || b4 ^ b5),
                    || rayon::join(|| c4 ^ c5 ^ k, || a1 & a2 ^ iv),
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
        self.k_byte.n_shifts(8);
        self.iv_byte.n_shifts(8);

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

impl KreyviumStreamByte<FheUint8> {
    pub fn get_server_key(&self) -> &ServerKey {
        self.fhe_key.as_ref().unwrap()
    }
}
