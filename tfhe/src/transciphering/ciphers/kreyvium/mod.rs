mod fhe;
mod plain;
#[cfg(test)]
mod test;

use super::shift_register::ShiftRegister;

pub use fhe::{KreyviumFheKey, KreyviumFheState};
pub use plain::{KreyviumIV, KreyviumPlainKey, KreyviumPlainState};
use rayon::prelude::*;

/// Collect an iterator of `T` into a heap-allocated `Box<[T; N]>`, avoiding
/// any intermediate `[T; N]` on the stack.
///
/// # Panics
/// Panics if the iterator does not yield exactly `N` items.
fn collect_boxed_array<T: std::fmt::Debug, const N: usize>(
    iter: impl IntoIterator<Item = T>,
) -> Box<[T; N]> {
    iter.into_iter()
        .collect::<Vec<_>>()
        .into_boxed_slice()
        .try_into()
        .unwrap()
}

/// Internal state of the kreyvium cipher
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KreyviumState<T> {
    a: ShiftRegister<93, T>,
    b: ShiftRegister<84, T>,
    c: ShiftRegister<111, T>,
    k: ShiftRegister<128, T>,
    iv: ShiftRegister<128, T>,
    counter: u64,
}

impl<T> KreyviumState<T> {
    /// Recover the inputs of the n-th round in the future from the state.
    /// Since the values in the registers are simply shifted between rounds, we can recover
    /// the inputs to the n-th round in the future by shifting the reading offsets by n, as long as
    /// we do not read outside of the register.
    ///
    /// # Panics
    /// Panics if n > 65.
    fn round_input(&self, n: usize) -> KreyviumRoundInput<'_, T> {
        assert!(n <= 65);

        // Offsets are taken from the formula in the kreyvium paper
        let (k, iv) = (&self.k[127 - n], &self.iv[127 - n]);

        let a = (
            &self.a[65 - n], // a1
            &self.a[92 - n], // a2
            &self.a[91 - n], // a3
            &self.a[90 - n], // a4
            &self.a[68 - n], // a5
        );

        let b = (
            &self.b[68 - n], // b1
            &self.b[83 - n], // b2
            &self.b[82 - n], // b3
            &self.b[81 - n], // b4
            &self.b[77 - n], // b5
        );

        let c = (
            &self.c[65 - n],  // c1
            &self.c[110 - n], // c2
            &self.c[109 - n], // c3
            &self.c[108 - n], // c4
            &self.c[86 - n],  // c5
        );

        KreyviumRoundInput { a, b, c, k, iv }
    }

    /// Inputs to one backward round, read from the current state `S_{t+1}` the values needed to
    /// reconstruct S_t.
    fn backward_round_input(&self) -> KreyviumRoundInput<'_, T> {
        // From the forward round input above, we see that (a2, b2, c2) are the values that need to
        // be recovered, since they are at the edge of each of register and are pushed out after the
        // round.
        // Looking at the round formula:
        // - new_a is built from (c1, c2, c3, c4, a5, k)
        // - new_b is built from (a1, a2, a3, a4, b5, iv)
        // - new_c is built from (b1, b2, b3, b4, c5)
        //
        // Thus, we can recover:
        // - c2 from (new_a, c1, c3, c4, a5, k)
        // - a2 from (new_b, a1, a3, a4, b5, iv)
        // - b2 from (new_c, b1, b3, b4, c5)
        //
        // Since we want the inputs for one step in the past, we need to add 1 to each offset to
        // read the correct value in the register.
        // new_a, new_b and new_c are the values pushed by the round at the beginning of the
        // register.
        // k and iv are circular registers of size 128, so the value at index 127 in S_t is equal
        // to the value at index 0 in S_{t+1}

        let (k, iv) = (&self.k[0], &self.iv[0]);

        let a = (
            &self.a[0],  // new_a
            &self.a[66], // a1 (was a[65]_t)
            &self.a[92], // a3 (was a[91]_t)
            &self.a[91], // a4 (was a[90]_t)
            &self.a[69], // a5 (was a[68]_t)
        );

        let b = (
            &self.b[0],  // new_b
            &self.b[69], // b1 (was b[68]_t)
            &self.b[83], // b3 (was b[82]_t)
            &self.b[82], // b4 (was b[81]_t)
            &self.b[78], // b5 (was b[77]_t)
        );

        let c = (
            &self.c[0],   // new_c
            &self.c[66],  // c1 (was c[65]_t)
            &self.c[110], // c3 (was c[109]_t)
            &self.c[109], // c4 (was c[108]_t)
            &self.c[87],  // c5 (was c[86]_t)
        );

        KreyviumRoundInput { a, b, c, k, iv }
    }

    /// Update the content of the registers with the values computed in the round.
    ///
    /// # Panics
    /// panics if counter overflows
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

    /// Inverse of [`update`](Self::update): roll the registers back by `n_rounds` using the
    /// recovered `(a, b, c)` bits in the order they were destroyed (most recent first).
    ///
    /// # Panics
    /// panics if counter underflows
    fn rewind(&mut self, values: impl ExactSizeIterator<Item = [T; 3]>) {
        let n_rounds = values.len();

        for [a, b, c] in values {
            self.a.push_back(a);
            self.b.push_back(b);
            self.c.push_back(c);
        }
        self.k.n_unshifts(n_rounds);
        self.iv.n_unshifts(n_rounds);

        self.counter = self.counter.checked_sub(n_rounds as u64).unwrap();
    }
}

#[allow(
    private_bounds,
    reason = "All methods in this impl block are private, so the private bounds won't be visible on user side"
)]
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

    /// One sequential backward round: recover the destroyed bits from the current
    /// post-round state and roll the registers back by one.
    fn prev(&mut self, aux: &A) {
        let backward_input = self.backward_round_input();
        let KreyviumBackwardRoundOutput { a, b, c } = backward_input.backward_round(aux);

        self.rewind(std::iter::once([a, b, c]));
    }
}

#[allow(
    private_bounds,
    reason = "All methods in this impl block are private, so the private bounds won't be visible on user side"
)]
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

    /// Advance the registers by `n_bits` forward rounds without accumulating the
    /// keystream. Same parallelism as [`next_n`](Self::next_n).
    fn skip_n(&mut self, aux: &A, n_bits: usize) {
        for _ in 0..n_bits / 64 {
            let _ = self.next_64(aux);
        }
        for _ in 0..n_bits % 64 {
            self.next(aux);
        }
    }

    fn prev_n(&mut self, aux: &A, n_bits: usize) {
        // Currently, it is not possible to parallelize the backward rounds, since the inputs for
        // state n-2 need state n-1 to be fully recovered.
        // It could be solved by increasing the state size, by storing more values in the registers.
        for _ in 0..n_bits {
            self.prev(aux);
        }
    }

    /// Set the keystream position to `target`. Equivalent to a forward
    /// [`skip_n`](Self::skip_n) of `target - counter` bits when `target >= counter`, or to
    /// `counter - target` sequential [`prev`](Self::prev) calls when `target < counter`.
    fn seek_to(&mut self, aux: &A, target: u64) {
        match target.cmp(&self.counter) {
            std::cmp::Ordering::Greater => {
                let n = (target - self.counter) as usize;
                self.skip_n(aux, n);
            }
            std::cmp::Ordering::Less => {
                let n = (self.counter - target) as usize;
                self.prev_n(aux, n);
            }
            std::cmp::Ordering::Equal => {}
        }
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

/// Five registers + key + iv passed to one Kreyvium round.
///
/// `[backward_]round_input` populate the tuple in the appropriate order; impls destructure
/// in matching order.
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

/// The three destroyed bits (`a2`, `b2`, `c2`) recovered by one backward round.
struct KreyviumBackwardRoundOutput<T> {
    a: T,
    b: T,
    c: T,
}

/// Internal only trait used to factorize kreyvium implementation in plaintext and FHE
trait KreyviumRound {
    type AuxData;
    type Bit;

    /// Arithmetic part of one forward Kreyvium round. `self` is read as
    /// `(a1, a2, a3, a4, a5)` etc.
    fn round(self, aux: &Self::AuxData) -> KreyviumRoundOutput<Self::Bit>;

    /// Arithmetic part of one backward Kreyvium round: recover `(a2, b2, c2)` of `S_t`
    /// from the post-round state `S_{t+1}`. `self` is read as `(new_a, a1, a3, a4, a5)`
    /// etc. (see [`KreyviumRoundInput`] doc).
    fn backward_round(self, aux: &Self::AuxData) -> KreyviumBackwardRoundOutput<Self::Bit>;
}
