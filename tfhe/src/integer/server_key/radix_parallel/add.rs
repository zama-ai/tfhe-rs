use std::sync::Mutex;

use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::ServerKey;
use crate::shortint::PBSOrderMarker;

impl ServerKey {
    /// Computes homomorphically an addition between two ciphertexts encrypting integer values.
    ///
    /// # Warning
    ///
    /// - Multithreaded
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, num_blocks);
    ///
    /// let msg1 = 14;
    /// let msg2 = 97;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.smart_add_parallelized(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg1 + msg2);
    /// ```
    pub fn smart_add_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct_left: &mut RadixCiphertext<PBSOrder>,
        ct_right: &mut RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        if !self.is_add_possible(ct_left, ct_right) {
            rayon::join(
                || self.full_propagate_parallelized(ct_left),
                || self.full_propagate_parallelized(ct_right),
            );
        }
        self.unchecked_add(ct_left, ct_right)
    }

    pub fn smart_add_assign_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct_left: &mut RadixCiphertext<PBSOrder>,
        ct_right: &mut RadixCiphertext<PBSOrder>,
    ) {
        if !self.is_add_possible(ct_left, ct_right) {
            rayon::join(
                || self.full_propagate_parallelized(ct_left),
                || self.full_propagate_parallelized(ct_right),
            );
        }
        self.unchecked_add_assign(ct_left, ct_right);
    }

    /// op must be associative and commutative
    pub fn smart_binary_op_seq_parallelized<'this, 'item, PBSOrder: PBSOrderMarker + 'item>(
        &'this self,
        ct_seq: impl IntoIterator<Item = &'item mut RadixCiphertext<PBSOrder>>,
        op: impl for<'a> Fn(
                &'a ServerKey,
                &'a mut RadixCiphertext<PBSOrder>,
                &'a mut RadixCiphertext<PBSOrder>,
            ) -> RadixCiphertext<PBSOrder>
            + Sync,
    ) -> Option<RadixCiphertext<PBSOrder>> {
        enum CiphertextCow<'a, O: PBSOrderMarker> {
            Borrowed(&'a mut RadixCiphertext<O>),
            Owned(RadixCiphertext<O>),
        }
        impl<O: PBSOrderMarker> CiphertextCow<'_, O> {
            fn as_mut(&mut self) -> &mut RadixCiphertext<O> {
                match self {
                    CiphertextCow::Borrowed(b) => b,
                    CiphertextCow::Owned(o) => o,
                }
            }
        }

        let ct_seq = ct_seq
            .into_iter()
            .map(CiphertextCow::Borrowed)
            .collect::<Vec<_>>();
        let op = &op;

        // overhead of dynamic dispatch is negligible compared to multithreading, PBS, etc.
        // we defer all calls to a single implementation to avoid code bloat and long compile
        // times
        #[allow(clippy::type_complexity)]
        fn reduce_impl<PBSOrder: PBSOrderMarker>(
            sks: &ServerKey,
            mut ct_seq: Vec<CiphertextCow<PBSOrder>>,
            op: &(dyn for<'a> Fn(
                &'a ServerKey,
                &'a mut RadixCiphertext<PBSOrder>,
                &'a mut RadixCiphertext<PBSOrder>,
            ) -> RadixCiphertext<PBSOrder>
                  + Sync),
        ) -> Option<RadixCiphertext<PBSOrder>> {
            use rayon::prelude::*;

            if ct_seq.is_empty() {
                None
            } else {
                // we repeatedly divide the number of terms by two by iteratively reducing
                // consecutive terms in the array
                while ct_seq.len() > 1 {
                    let results = Mutex::new(Vec::<RadixCiphertext<PBSOrder>>::with_capacity(
                        ct_seq.len() / 2,
                    ));

                    // if the number of elements is odd, we skip the first element
                    let untouched_prefix = ct_seq.len() % 2;
                    let ct_seq_slice = &mut ct_seq[untouched_prefix..];

                    ct_seq_slice.par_chunks_mut(2).for_each(|chunk| {
                        let (first, second) = chunk.split_at_mut(1);
                        let first = &mut first[0];
                        let second = &mut second[0];
                        let result = op(sks, first.as_mut(), second.as_mut());
                        results.lock().unwrap().push(result);
                    });

                    let results = results.into_inner().unwrap();
                    ct_seq.truncate(untouched_prefix);
                    ct_seq.extend(results.into_iter().map(CiphertextCow::Owned));
                }

                let sum = ct_seq.pop().unwrap();

                Some(match sum {
                    CiphertextCow::Borrowed(b) => b.clone(),
                    CiphertextCow::Owned(o) => o,
                })
            }
        }

        reduce_impl(self, ct_seq, op)
    }
}
