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

    /// Computes homomorphically an addition between two ciphertexts encrypting integer values.
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertexts block carries are empty and clears them if it's not the
    /// case and the operation requires it. It outputs a ciphertext whose block carries are always
    /// empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
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
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.add_parallelized(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg1 + msg2);
    /// ```
    pub fn add_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct_left: &RadixCiphertext<PBSOrder>,
        ct_right: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        let mut ct_res = ct_left.clone();
        self.add_assign_parallelized(&mut ct_res, ct_right);
        ct_res
    }

    pub fn add_assign_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct_left: &mut RadixCiphertext<PBSOrder>,
        ct_right: &RadixCiphertext<PBSOrder>,
    ) {
        let mut tmp_rhs: RadixCiphertext<PBSOrder>;

        let (lhs, rhs) = match (
            ct_left.block_carries_are_empty(),
            ct_right.block_carries_are_empty(),
        ) {
            (true, true) => (ct_left, ct_right),
            (true, false) => {
                tmp_rhs = ct_right.clone();
                self.full_propagate_parallelized(&mut tmp_rhs);
                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                self.full_propagate_parallelized(ct_left);
                (ct_left, ct_right)
            }
            (false, false) => {
                tmp_rhs = ct_right.clone();
                rayon::join(
                    || self.full_propagate_parallelized(ct_left),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (ct_left, &tmp_rhs)
            }
        };

        self.unchecked_add_assign(lhs, rhs);
        self.full_propagate_parallelized(lhs);
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
                let num_blocks = ct_seq[0].as_mut().blocks.len();
                while ct_seq.len() > 1 {
                    let mut results =
                        vec![sks.create_trivial_radix(0u64, num_blocks); ct_seq.len() / 2];

                    // if the number of elements is odd, we skip the first element
                    let untouched_prefix = ct_seq.len() % 2;
                    let ct_seq_slice = &mut ct_seq[untouched_prefix..];

                    results
                        .par_iter_mut()
                        .zip(ct_seq_slice.par_chunks_exact_mut(2))
                        .for_each(|(ct_res, chunk)| {
                            let (first, second) = chunk.split_at_mut(1);
                            let first = first[0].as_mut();
                            let second = second[0].as_mut();
                            *ct_res = op(sks, first, second);
                        });

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

    /// op must be associative and commutative
    pub fn default_binary_op_seq_parallelized<'this, 'item, PBSOrder: PBSOrderMarker + 'item>(
        &'this self,
        ct_seq: impl IntoIterator<Item = &'item RadixCiphertext<PBSOrder>>,
        op: impl for<'a> Fn(
                &'a ServerKey,
                &'a RadixCiphertext<PBSOrder>,
                &'a RadixCiphertext<PBSOrder>,
            ) -> RadixCiphertext<PBSOrder>
            + Sync,
    ) -> Option<RadixCiphertext<PBSOrder>> {
        enum CiphertextCow<'a, O: PBSOrderMarker> {
            Borrowed(&'a RadixCiphertext<O>),
            Owned(RadixCiphertext<O>),
        }
        impl<O: PBSOrderMarker> CiphertextCow<'_, O> {
            fn as_ref(&self) -> &RadixCiphertext<O> {
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
                &'a RadixCiphertext<PBSOrder>,
                &'a RadixCiphertext<PBSOrder>,
            ) -> RadixCiphertext<PBSOrder>
                  + Sync),
        ) -> Option<RadixCiphertext<PBSOrder>> {
            use rayon::prelude::*;

            if ct_seq.is_empty() {
                None
            } else {
                // we repeatedly divide the number of terms by two by iteratively reducing
                // consecutive terms in the array
                let num_blocks = ct_seq[0].as_ref().blocks.len();
                while ct_seq.len() > 1 {
                    let mut results =
                        vec![sks.create_trivial_radix(0u64, num_blocks); ct_seq.len() / 2];
                    // if the number of elements is odd, we skip the first element
                    let untouched_prefix = ct_seq.len() % 2;
                    let ct_seq_slice = &mut ct_seq[untouched_prefix..];

                    results
                        .par_iter_mut()
                        .zip(ct_seq_slice.par_chunks_exact(2))
                        .for_each(|(ct_res, chunk)| {
                            let first = chunk[0].as_ref();
                            let second = chunk[1].as_ref();
                            *ct_res = op(sks, first, second);
                        });

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
