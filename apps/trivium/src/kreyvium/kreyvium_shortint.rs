use crate::static_deque::StaticDeque;

// use tfhe::prelude::*;
use tfhe::shortint::prelude::*;
use tfhe::shortint::{ciphertext::KeyswitchBootstrap, CastingKey};

use rayon::prelude::*;

type FheShortint = CiphertextBase<KeyswitchBootstrap>;

/// KreyviumStreamShortint: a struct implementing the Kreyvium stream cipher, using a generic Ciphertext for the internal
/// representation of bits (intended to represent a single bit). To be able to compute FHE operations, it also owns
/// a ServerKey.
pub struct KreyviumStreamShortint {
    a: StaticDeque<93, FheShortint>,
    b: StaticDeque<84, FheShortint>,
    c: StaticDeque<111, FheShortint>,
    k: StaticDeque<128, FheShortint>,
    iv: StaticDeque<128, FheShortint>,
    internal_server_key: ServerKey,
    transciphering_casting_key: CastingKey<ServerKey, tfhe::ServerKey>,
    hl_server_key: tfhe::ServerKey,
}

impl KreyviumStreamShortint {
    /// Contructor for KreyviumStreamShortint: arguments are the secret key and the input vector, and a ServerKey reference.
    /// Outputs a KreyviumStream object already initialized (1152 steps have been run before returning)
    pub fn new(
        mut key: [FheShortint; 128],
        mut iv: [u64; 128],
        sk: &ServerKey,
        ksk: &CastingKey<ServerKey, tfhe::ServerKey>,
        hl_sk: &tfhe::ServerKey,
    ) -> Self {
        // Initialization of Kreyvium registers: a has the secret key, b the input vector,
        // and c a few ones.
        let mut a_register: [FheShortint; 93] = [0; 93].map(|x| sk.create_trivial(x));
        let mut b_register: [FheShortint; 84] = [0; 84].map(|x| sk.create_trivial(x));
        let mut c_register: [FheShortint; 111] = [0; 111].map(|x| sk.create_trivial(x));

        for i in 0..93 {
            a_register[i] = key[128 - 93 + i].clone();
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

        let mut ret = Self {
            a: StaticDeque::<93, FheShortint>::new(a_register),
            b: StaticDeque::<84, FheShortint>::new(b_register),
            c: StaticDeque::<111, FheShortint>::new(c_register),
            k: StaticDeque::<128, FheShortint>::new(key),
            iv: StaticDeque::<128, FheShortint>::new(iv),
            internal_server_key: sk.clone(),
            transciphering_casting_key: ksk.clone(),
            hl_server_key: hl_sk.clone(),
        };
        ret.init();
        ret
    }

    /// The specification of Kreyvium includes running 1152 (= 18*64) unused steps to mix up the registers,
    /// before starting the proper stream
    fn init(&mut self) {
        for _ in 0..18 {
            self.next_64();
        }
    }

    /// Computes one turn of the stream, updating registers and outputting the new bit.
    pub fn next(&mut self) -> FheShortint {
        let [o, a, b, c] = self.get_output_and_values(0);

        self.a.push(a);
        self.b.push(b);
        self.c.push(c);

        o
    }

    /// Computes a potential future step of Kreyvium, n terms in the future. This does not update registers,
    /// but rather returns with the output, the three values that will be used to update the registers,
    /// when the time is right. This function is meant to be used in parallel.
    fn get_output_and_values(&self, n: usize) -> [FheShortint; 4] {
        let (k, iv) = (&self.k[127 - n], &self.iv[127 - n]);

        let (a1, a2, a3, a4, a5) = (
            &self.a[65 - n],
            &self.a[92 - n],
            &self.a[91 - n],
            &self.a[90 - n],
            &self.a[68 - n],
        );
        let (b1, b2, b3, b4, b5) = (
            &self.b[68 - n],
            &self.b[83 - n],
            &self.b[82 - n],
            &self.b[81 - n],
            &self.b[77 - n],
        );
        let (c1, c2, c3, c4, c5) = (
            &self.c[65 - n],
            &self.c[110 - n],
            &self.c[109 - n],
            &self.c[108 - n],
            &self.c[86 - n],
        );

        let temp_a = self.internal_server_key.unchecked_add(a1, a2);
        let temp_b = self.internal_server_key.unchecked_add(b1, b2);
        let mut temp_c = self.internal_server_key.unchecked_add(c1, c2);
        self.internal_server_key
            .unchecked_add_assign(&mut temp_c, k);

        let ((new_a, new_b), (new_c, o)) = rayon::join(
            || {
                rayon::join(
                    || {
                        let mut new_a = self.internal_server_key.unchecked_bitand(c3, c4);
                        self.internal_server_key
                            .unchecked_add_assign(&mut new_a, a5);
                        self.internal_server_key.add_assign(&mut new_a, &temp_c);
                        new_a
                    },
                    || {
                        let mut new_b = self.internal_server_key.unchecked_bitand(a3, a4);
                        self.internal_server_key
                            .unchecked_add_assign(&mut new_b, b5);
                        self.internal_server_key
                            .unchecked_add_assign(&mut new_b, &temp_a);
                        self.internal_server_key.add_assign(&mut new_b, iv);
                        new_b
                    },
                )
            },
            || {
                rayon::join(
                    || {
                        let mut new_c = self.internal_server_key.unchecked_bitand(b3, b4);
                        self.internal_server_key
                            .unchecked_add_assign(&mut new_c, c5);
                        self.internal_server_key
                            .unchecked_add_assign(&mut new_c, &temp_b);
                        self.internal_server_key.clear_carry_assign(&mut new_c);
                        new_c
                    },
                    || {
                        self.internal_server_key.bitxor(
                            &self.internal_server_key.unchecked_add(&temp_a, &temp_b),
                            &temp_c,
                        )
                    },
                )
            },
        );

        [o, new_a, new_b, new_c]
    }

    /// This calls `get_output_and_values` in parallel 64 times, and stores all results in a Vec.
    fn get_64_output_and_values(&self) -> Vec<[FheShortint; 4]> {
        (0..64)
            .into_par_iter()
            .map(|x| self.get_output_and_values(x))
            .rev()
            .collect()
    }

    /// Computes 64 turns of the stream, outputting the 64 bits all at once in a
    /// Vec (first value is oldest, last is newest)
    pub fn next_64(&mut self) -> Vec<FheShortint> {
        let mut values = self.get_64_output_and_values();

        let mut ret = Vec::<FheShortint>::with_capacity(64);
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

    pub fn get_internal_server_key(&self) -> &ServerKey {
        &self.internal_server_key
    }

    pub fn get_casting_key(&self) -> &CastingKey<ServerKey, tfhe::ServerKey> {
        &self.transciphering_casting_key
    }

    pub fn get_hl_server_key(&self) -> &tfhe::ServerKey {
        &self.hl_server_key
    }
}
