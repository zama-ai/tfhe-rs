//! This module implements the Kreyvium stream cipher, using booleans or FheBool
//! for the representation of the inner bits.

use crate::static_deque::StaticDeque;

use tfhe::prelude::*;
use tfhe::{set_server_key, unset_server_key, FheBool, ServerKey};

use rayon::prelude::*;

/// Internal trait specifying which operations are necessary for KreyviumStream generic type
pub trait KreyviumBoolInput<OpOutput>:
    Sized
    + Clone
    + std::ops::BitXor<Output = OpOutput>
    + std::ops::BitAnd<Output = OpOutput>
    + std::ops::Not<Output = OpOutput>
{
}
impl KreyviumBoolInput<bool> for bool {}
impl KreyviumBoolInput<bool> for &bool {}
impl KreyviumBoolInput<FheBool> for FheBool {}
impl KreyviumBoolInput<FheBool> for &FheBool {}

/// KreyviumStream: a struct implementing the Kreyvium stream cipher, using T for the internal
/// representation of bits (bool or FheBool). To be able to compute FHE operations, it also owns
/// an Option for a ServerKey.
pub struct KreyviumStream<T> {
    a: StaticDeque<93, T>,
    b: StaticDeque<84, T>,
    c: StaticDeque<111, T>,
    k: StaticDeque<128, T>,
    iv: StaticDeque<128, T>,
    fhe_key: Option<ServerKey>,
}

impl KreyviumStream<bool> {
    /// Constructor for `KreyviumStream<bool>`: arguments are the secret key and the input vector.
    /// Outputs a KreyviumStream object already initialized (1152 steps have been run before
    /// returning)
    pub fn new(mut key: [bool; 128], mut iv: [bool; 128]) -> KreyviumStream<bool> {
        // Initialization of Kreyvium registers: a has the secret key, b the input vector,
        // and c a few ones.
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
        KreyviumStream::<bool>::new_from_registers(
            a_register, b_register, c_register, key, iv, None,
        )
    }
}

impl KreyviumStream<FheBool> {
    /// Constructor for `KreyviumStream<FheBool>`: arguments are the encrypted secret key and input
    /// vector, and the FHE server key.
    /// Outputs a KreyviumStream object already initialized (1152 steps have been run before
    /// returning)
    pub fn new(
        mut key: [FheBool; 128],
        mut iv: [bool; 128],
        sk: &ServerKey,
    ) -> KreyviumStream<FheBool> {
        set_server_key(sk.clone());

        // Initialization of Kreyvium registers: a has the secret key, b the input vector,
        // and c a few ones.
        let mut a_register = [false; 93].map(FheBool::encrypt_trivial);
        let mut b_register = [false; 84].map(FheBool::encrypt_trivial);
        let mut c_register = [false; 111].map(FheBool::encrypt_trivial);

        for i in 0..93 {
            a_register[i] = key[128 - 93 + i].clone();
        }
        for i in 0..84 {
            b_register[i] = FheBool::encrypt_trivial(iv[128 - 84 + i]);
        }
        for i in 0..44 {
            c_register[111 - 44 + i] = FheBool::encrypt_trivial(iv[i]);
        }
        for i in 0..66 {
            c_register[i + 1] = FheBool::encrypt_trivial(true);
        }

        key.reverse();
        iv.reverse();
        let iv = iv.map(FheBool::encrypt_trivial);

        unset_server_key();
        KreyviumStream::<FheBool>::new_from_registers(
            a_register,
            b_register,
            c_register,
            key,
            iv,
            Some(sk.clone()),
        )
    }
}

impl<T> KreyviumStream<T>
where
    T: KreyviumBoolInput<T> + std::marker::Send + std::marker::Sync,
    for<'a> &'a T: KreyviumBoolInput<T>,
{
    /// Internal generic constructor: arguments are already prepared registers, and an optional FHE
    /// server key
    fn new_from_registers(
        a_register: [T; 93],
        b_register: [T; 84],
        c_register: [T; 111],
        k_register: [T; 128],
        iv_register: [T; 128],
        key: Option<ServerKey>,
    ) -> Self {
        let mut ret = Self {
            a: StaticDeque::<93, T>::new(a_register),
            b: StaticDeque::<84, T>::new(b_register),
            c: StaticDeque::<111, T>::new(c_register),
            k: StaticDeque::<128, T>::new(k_register),
            iv: StaticDeque::<128, T>::new(iv_register),
            fhe_key: key,
        };
        ret.init();
        ret
    }

    /// The specification of Kreyvium includes running 1152 (= 18*64) unused steps to mix up the
    /// registers, before starting the proper stream
    fn init(&mut self) {
        for _ in 0..18 {
            self.next_64();
        }
    }

    /// Computes one turn of the stream, updating registers and outputting the new bit.
    pub fn next_bool(&mut self) -> T {
        match &self.fhe_key {
            Some(sk) => set_server_key(sk.clone()),
            None => (),
        };

        let [o, a, b, c] = self.get_output_and_values(0);

        self.a.push(a);
        self.b.push(b);
        self.c.push(c);
        self.k.shift();
        self.iv.shift();

        o
    }

    /// Computes a potential future step of Kreyvium, n terms in the future. This does not update
    /// registers, but rather returns with the output, the three values that will be used to
    /// update the registers, when the time is right. This function is meant to be used in
    /// parallel.
    fn get_output_and_values(&self, n: usize) -> [T; 4] {
        assert!(n < 65);

        let (((temp_a, temp_b), (temp_c, a_and)), (b_and, c_and)) = rayon::join(
            || {
                rayon::join(
                    || {
                        rayon::join(
                            || &self.a[65 - n] ^ &self.a[92 - n],
                            || &self.b[68 - n] ^ &self.b[83 - n],
                        )
                    },
                    || {
                        rayon::join(
                            || &(&self.c[65 - n] ^ &self.c[110 - n]) ^ &self.k[127 - n],
                            || &(&self.a[91 - n] & &self.a[90 - n]) ^ &self.iv[127 - n],
                        )
                    },
                )
            },
            || {
                rayon::join(
                    || &self.b[82 - n] & &self.b[81 - n],
                    || &self.c[109 - n] & &self.c[108 - n],
                )
            },
        );

        let ((o, a), (b, c)) = rayon::join(
            || {
                rayon::join(
                    || &(&temp_a ^ &temp_b) ^ &temp_c,
                    || &temp_c ^ &(&c_and ^ &self.a[68 - n]),
                )
            },
            || {
                rayon::join(
                    || &temp_a ^ &(&a_and ^ &self.b[77 - n]),
                    || &temp_b ^ &(&b_and ^ &self.c[86 - n]),
                )
            },
        );

        [o, a, b, c]
    }

    /// This calls `get_output_and_values` in parallel 64 times, and stores all results in a Vec.
    fn get_64_output_and_values(&self) -> Vec<[T; 4]> {
        (0..64)
            .into_par_iter()
            .map(|x| self.get_output_and_values(x))
            .rev()
            .collect()
    }

    /// Computes 64 turns of the stream, outputting the 64 bits all at once in a
    /// Vec (first value is oldest, last is newest)
    pub fn next_64(&mut self) -> Vec<T> {
        match &self.fhe_key {
            Some(sk) => {
                rayon::broadcast(|_| set_server_key(sk.clone()));
            }
            None => (),
        }
        let mut values = self.get_64_output_and_values();
        match &self.fhe_key {
            Some(_) => {
                rayon::broadcast(|_| unset_server_key());
            }
            None => (),
        }

        let mut ret = Vec::<T>::with_capacity(64);

        while let Some([o, a, b, c]) = values.pop() {
            ret.push(o);
            self.a.push(a);
            self.b.push(b);
            self.c.push(c);
        }
        self.k.n_shifts(64);
        self.iv.n_shifts(64);
        ret
    }
}
