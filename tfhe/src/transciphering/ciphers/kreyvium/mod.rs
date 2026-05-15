mod fast_fhe;
mod fhe;
mod plain;
#[cfg(test)]
mod test;

use super::shift_register::ShiftRegister;

pub use fast_fhe::{encrypt_fast_bit, FastBit, KreyviumFastEncryptedKey, KreyviumFastFheStream};
pub use fhe::{KreyviumEncryptedKey, KreyviumFheStream};
pub use plain::KreyviumPlainStream;
use rayon::prelude::*;

/// Internal state of the kreyvium cipher
#[derive(Clone)]
struct KreyviumState<T> {
    a: ShiftRegister<93, T>,
    b: ShiftRegister<84, T>,
    c: ShiftRegister<111, T>,
    k: ShiftRegister<128, T>,
    iv: ShiftRegister<128, T>,
    counter: u64,
}

impl<T> KreyviumState<T> {
    fn round_input(&self, n: usize) -> KreyviumRoundInput<'_, T> {
        assert!(n <= 65);

        let (k, iv) = (&self.k[127 - n], &self.iv[127 - n]);

        let a = (
            &self.a[65 - n],
            &self.a[92 - n],
            &self.a[91 - n],
            &self.a[90 - n],
            &self.a[68 - n],
        );

        let b = (
            &self.b[68 - n],
            &self.b[83 - n],
            &self.b[82 - n],
            &self.b[81 - n],
            &self.b[77 - n],
        );

        let c = (
            &self.c[65 - n],
            &self.c[110 - n],
            &self.c[109 - n],
            &self.c[108 - n],
            &self.c[86 - n],
        );

        KreyviumRoundInput { a, b, c, k, iv }
    }

    fn update(&mut self, values: impl ExactSizeIterator<Item = [T; 3]>) {
        let n_rounds = values.len();

        for [a, b, c] in values {
            self.a.push(a);
            self.b.push(b);
            self.c.push(c);
        }
        self.k.n_shifts(n_rounds);
        self.iv.n_shifts(n_rounds);

        // Panic explicitly if counter overflows
        self.counter = self.counter.checked_add(n_rounds as u64).unwrap();
    }
}

impl<T, A> KreyviumState<T>
where
    for<'a> KreyviumRoundInput<'a, T>: KreyviumRound<Bit = T, AuxData = A>,
{
    fn next(&mut self, aux: &A) -> T {
        let round_input = self.round_input(0);
        let KreyviumRoundOutput { output, a, b, c } = round_input.round(aux);

        self.update(std::iter::once([a, b, c]));

        output
    }
}

impl<T, A> KreyviumState<T>
where
    for<'a> KreyviumRoundInput<'a, T>: KreyviumRound<Bit = T, AuxData = A>,
    T: Send + Sync,
    A: Sync,
{
    fn next_64(&mut self, aux: &A) -> Vec<T> {
        let values = (0..64).into_par_iter().map(|x| {
            let round_input = self.round_input(x);
            let KreyviumRoundOutput { output, a, b, c } = round_input.round(aux);
            (output, [a, b, c])
        });

        let (res, updates): (Vec<_>, Vec<_>) = values.unzip();
        self.update(updates.into_iter());

        res
    }

    fn next_n(&mut self, aux: &A, n_bits: usize) -> Vec<T> {
        let mut result = Vec::with_capacity(n_bits);

        for _ in 0..n_bits / 64 {
            result.extend(self.next_64(aux));
        }
        for _ in 0..n_bits % 64 {
            result.push(self.next(aux));
        }

        result
    }

    /// The specification of Kreyvium includes running 1152 (= 18*64) unused steps to mix up the
    /// registers, before starting the proper stream
    fn warmup(&mut self, aux: &A) {
        for _ in 0..18 {
            self.next_64(aux);
        }

        // Spec specifies that counter is 0 after the warmup, but running rounds will advance it
        self.counter = 0;
    }
}

/// A struct implementing the Kreyvium stream cipher.
pub struct KreyviumStream<T> {
    state: KreyviumState<T>,
}

struct KreyviumRoundInput<'a, T> {
    a: (&'a T, &'a T, &'a T, &'a T, &'a T),
    b: (&'a T, &'a T, &'a T, &'a T, &'a T),
    c: (&'a T, &'a T, &'a T, &'a T, &'a T),
    k: &'a T,
    iv: &'a T,
}

struct KreyviumRoundOutput<T> {
    output: T,
    a: T,
    b: T,
    c: T,
}

/// Internal only trait used to factorize kreyvium implementation in plaintext and FHE
trait KreyviumRound {
    type AuxData;
    type Bit;

    /// Arithmetic part of a Kreyvium round. Can be optimized for FHE or cleartext impl.
    fn round(self, aux: &Self::AuxData) -> KreyviumRoundOutput<Self::Bit>;
}
