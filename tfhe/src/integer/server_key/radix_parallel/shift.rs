use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::server_key::radix_parallel::bit_extractor::BitExtractor;
use crate::integer::ServerKey;

use rayon::prelude::*;

pub(super) enum BarrelShifterOperation {
    LeftRotate,
    LeftShift,
    RightShift,
    RightRotate,
}

impl ServerKey {
    //======================================================================
    //                Shift Right
    //======================================================================

    pub fn unchecked_right_shift_parallelized(
        &self,
        ct_left: &RadixCiphertext,
        shift: &RadixCiphertext,
    ) -> RadixCiphertext {
        let mut result = ct_left.clone();
        self.unchecked_right_shift_assign_parallelized(&mut result, shift);
        result
    }

    pub fn unchecked_right_shift_assign_parallelized(
        &self,
        ct: &mut RadixCiphertext,
        shift: &RadixCiphertext,
    ) {
        self.barrel_shifter(ct, shift, BarrelShifterOperation::RightShift);
    }

    pub fn smart_right_shift_assign_parallelized(
        &self,
        ct: &mut RadixCiphertext,
        shift: &mut RadixCiphertext,
    ) {
        rayon::join(
            || {
                if !ct.block_carries_are_empty() {
                    self.full_propagate_parallelized(ct);
                }
            },
            || {
                if !shift.block_carries_are_empty() {
                    self.full_propagate_parallelized(shift);
                }
            },
        );
        self.unchecked_right_shift_assign_parallelized(ct, shift);
    }

    pub fn smart_right_shift_parallelized(
        &self,
        ct: &mut RadixCiphertext,
        shift: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        rayon::join(
            || {
                if !ct.block_carries_are_empty() {
                    self.full_propagate_parallelized(ct);
                }
            },
            || {
                if !shift.block_carries_are_empty() {
                    self.full_propagate_parallelized(shift);
                }
            },
        );
        self.unchecked_right_shift_parallelized(ct, shift)
    }

    pub fn right_shift_assign_parallelized(
        &self,
        ct: &mut RadixCiphertext,
        shift: &RadixCiphertext,
    ) {
        let mut tmp_rhs: RadixCiphertext;

        let (lhs, rhs) = match (
            ct.block_carries_are_empty(),
            shift.block_carries_are_empty(),
        ) {
            (true, true) => (ct, shift),
            (true, false) => {
                tmp_rhs = shift.clone();
                self.full_propagate_parallelized(&mut tmp_rhs);
                (ct, &tmp_rhs)
            }
            (false, true) => {
                self.full_propagate_parallelized(ct);
                (ct, shift)
            }
            (false, false) => {
                tmp_rhs = shift.clone();
                rayon::join(
                    || self.full_propagate_parallelized(ct),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (ct, &tmp_rhs)
            }
        };

        self.unchecked_right_shift_assign_parallelized(lhs, rhs)
    }

    /// Computes homomorphically a right shift by an encrypted amount
    ///
    /// The result is returned as a new ciphertext.
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
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 128;
    /// let shift = 2;
    ///
    /// let ct = cks.encrypt(msg);
    /// let shift_ct = cks.encrypt(shift as u64);
    ///
    /// // Compute homomorphically a right shift:
    /// let ct_res = sks.right_shift_parallelized(&ct, &shift_ct);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg >> shift, dec);
    /// ```
    pub fn right_shift_parallelized(
        &self,
        ct: &RadixCiphertext,
        shift: &RadixCiphertext,
    ) -> RadixCiphertext {
        let mut ct_res = ct.clone();
        self.right_shift_assign_parallelized(&mut ct_res, shift);
        ct_res
    }

    //======================================================================
    //                Shift Left
    //======================================================================

    /// left shift by and encrypted amount
    ///
    /// This requires:
    /// - ct to have clean carries
    /// - shift to have clean carries
    /// - the number of bits in the block to be >= 3
    pub fn unchecked_left_shift_parallelized(
        &self,
        ct_left: &RadixCiphertext,
        shift: &RadixCiphertext,
    ) -> RadixCiphertext {
        let mut result = ct_left.clone();
        self.unchecked_left_shift_assign_parallelized(&mut result, shift);
        result
    }

    /// left shift by and encrypted amount
    ///
    /// This requires:
    /// - ct to have clean carries
    /// - shift to have clean carries
    /// - the number of bits in the block to be >= 3
    pub fn unchecked_left_shift_assign_parallelized(
        &self,
        ct: &mut RadixCiphertext,
        shift: &RadixCiphertext,
    ) {
        self.barrel_shifter(ct, shift, BarrelShifterOperation::LeftShift);
    }

    pub fn smart_left_shift_assign_parallelized(
        &self,
        ct: &mut RadixCiphertext,
        shift: &mut RadixCiphertext,
    ) {
        rayon::join(
            || {
                if !ct.block_carries_are_empty() {
                    self.full_propagate_parallelized(ct);
                }
            },
            || {
                if !shift.block_carries_are_empty() {
                    self.full_propagate_parallelized(shift);
                }
            },
        );
        self.unchecked_left_shift_assign_parallelized(ct, shift);
    }

    pub fn smart_left_shift_parallelized(
        &self,
        ct: &mut RadixCiphertext,
        shift: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        rayon::join(
            || {
                if !ct.block_carries_are_empty() {
                    self.full_propagate_parallelized(ct);
                }
            },
            || {
                if !shift.block_carries_are_empty() {
                    self.full_propagate_parallelized(shift);
                }
            },
        );
        self.unchecked_left_shift_parallelized(ct, shift)
    }

    pub fn left_shift_assign_parallelized(
        &self,
        ct: &mut RadixCiphertext,
        shift: &RadixCiphertext,
    ) {
        let mut tmp_rhs: RadixCiphertext;

        let (lhs, rhs) = match (
            ct.block_carries_are_empty(),
            shift.block_carries_are_empty(),
        ) {
            (true, true) => (ct, shift),
            (true, false) => {
                tmp_rhs = shift.clone();
                self.full_propagate_parallelized(&mut tmp_rhs);
                (ct, &tmp_rhs)
            }
            (false, true) => {
                self.full_propagate_parallelized(ct);
                (ct, shift)
            }
            (false, false) => {
                tmp_rhs = shift.clone();
                rayon::join(
                    || self.full_propagate_parallelized(ct),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (ct, &tmp_rhs)
            }
        };

        self.unchecked_left_shift_assign_parallelized(lhs, rhs)
    }

    /// Computes homomorphically a left shift by an encrypted amount.
    ///
    /// The result is returned as a new ciphertext.
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
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 21;
    /// let shift = 2;
    ///
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(shift as u64);
    ///
    /// // Compute homomorphically a left shift:
    /// let ct_res = sks.left_shift_parallelized(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg << shift, dec);
    /// ```
    pub fn left_shift_parallelized(
        &self,
        ct: &RadixCiphertext,
        shift: &RadixCiphertext,
    ) -> RadixCiphertext {
        let mut ct_res = ct.clone();
        self.left_shift_assign_parallelized(&mut ct_res, shift);
        ct_res
    }

    /// This implemements a "barrel shifter".
    ///
    /// This construct is what is used in hardware to
    /// implemement left/right shift/rotate
    ///
    /// This requires:
    /// - ct to have clean carries
    /// - shift to have clean carries
    /// - the number of bits in the block to be >= 3
    ///
    /// Similarly to rust `wrapping_shl/shr` functions
    /// it removes any high-order bits of `shift`
    /// that would cause the shift to exceed the bitwidth of the type.
    ///
    /// **However**, when the total number of bits represented by the
    /// radix ciphertext is not a power of two (eg a ciphertext with 12 bits)
    /// then, it removes bit that are higher than the closest higher power of two.
    /// So for a 12 bits radix ciphertext, its closest higher power of two is 16,
    /// thus, any bit that are higher than log2(16) will be removed
    ///
    /// `ct` will be assigned the result, and it will be in a fresh state
    pub(super) fn barrel_shifter(
        &self,
        ct: &mut RadixCiphertext,
        shift: &RadixCiphertext,
        operation: BarrelShifterOperation,
    ) {
        let num_blocks = shift.blocks.len();
        let message_bits_per_block = self.key.message_modulus.0.ilog2() as u64;
        let carry_bits_per_block = self.key.carry_modulus.0.ilog2() as u64;
        let total_nb_bits = message_bits_per_block * num_blocks as u64;

        assert!(
            (message_bits_per_block + carry_bits_per_block) >= 3,
            "Blocks must have at least 3 bits"
        );

        let bit_extractor = BitExtractor::new(self, message_bits_per_block as usize);
        let (bits, shift_bits) = rayon::join(
            || bit_extractor.extract_all_bits(&ct.blocks),
            || {
                let mut max_num_bits_that_tell_shift = total_nb_bits.ilog2() as u64;
                // This effectively means, that if the block parameters
                // give a total_nb_bits that is not a power of two,
                // then the behaviour of shifting won't be the same
                // if shift >= total_nb_bits compared to when total_nb_bits
                // is a power of two, as will 'capture' more bits in `shift_bits`
                if !total_nb_bits.is_power_of_two() {
                    max_num_bits_that_tell_shift += 1;
                }
                bit_extractor.extract_n_bits(&shift.blocks, max_num_bits_that_tell_shift as usize)
            },
        );

        let mux_lut = self.key.generate_lookup_table(|x| {
            // x is expected to be x = 0bcba
            // where
            // - c is the control bit
            // - b the bit value returned if c is 1
            // - a the bit value returned if c is 0
            // (any bit above c is ignored)
            let x = x & 7;
            let control_bit = x >> 2;
            let previous_bit = (x & 2) >> 1;
            let current_bit = x & 1;

            if control_bit == 1 {
                previous_bit
            } else {
                current_bit
            }
        });

        let offset = match operation {
            BarrelShifterOperation::LeftShift | BarrelShifterOperation::LeftRotate => 0,
            BarrelShifterOperation::RightShift | BarrelShifterOperation::RightRotate => {
                total_nb_bits
            }
        };

        use std::cell::UnsafeCell;

        #[derive(Copy, Clone)]
        pub struct UnsafeSlice<'a, T> {
            slice: &'a [UnsafeCell<T>],
        }
        unsafe impl<'a, T: Send + Sync> Send for UnsafeSlice<'a, T> {}
        unsafe impl<'a, T: Send + Sync> Sync for UnsafeSlice<'a, T> {}

        impl<'a, T> UnsafeSlice<'a, T> {
            pub fn new(slice: &'a mut [T]) -> Self {
                let ptr = slice as *mut [T] as *const [UnsafeCell<T>];
                Self {
                    slice: unsafe { &*ptr },
                }
            }

            /// SAFETY: It is UB if two threads read/write the pointer without synchronisation
            pub unsafe fn get(&self, i: usize) -> *mut T {
                self.slice[i].get()
            }
        }

        let mut input_bits_a = bits;
        let mut input_bits_b = input_bits_a.clone();
        let mut mux_inputs = input_bits_a.clone();

        for (d, shift_bit) in shift_bits.iter().enumerate() {
            for i in 0..total_nb_bits as usize {
                input_bits_b[i].clone_from(&input_bits_a[i]);
                mux_inputs[i].clone_from(shift_bit);
            }

            match operation {
                BarrelShifterOperation::LeftShift => {
                    input_bits_b.rotate_right(1 << d);
                    for bit_that_wrapped in &mut input_bits_b[..1 << d] {
                        self.key.create_trivial_assign(bit_that_wrapped, 0);
                    }
                }
                BarrelShifterOperation::RightShift => {
                    input_bits_b.rotate_left(1 << d);
                    let bits_that_wrapped = &mut input_bits_b[total_nb_bits as usize - (1 << d)..];
                    for bit_that_wrapped in bits_that_wrapped {
                        self.key.create_trivial_assign(bit_that_wrapped, 0);
                    }
                }
                BarrelShifterOperation::LeftRotate => {
                    input_bits_b.rotate_right(1 << d);
                }
                BarrelShifterOperation::RightRotate => {
                    input_bits_b.rotate_left(1 << d);
                }
            }

            let input_bits_a_slc = UnsafeSlice::new(&mut input_bits_a);
            let mux_inputs_slc = UnsafeSlice::new(&mut mux_inputs);

            (0..total_nb_bits).into_par_iter().for_each(|i| {
                unsafe {
                    // SAFETY
                    //
                    // `get` still does bound checks
                    // (but we expect the index to alway be valid)
                    //
                    // Also, each index i is unique to each thread
                    // as it comes from the iteration over a range.
                    //
                    // (i + offset) % total_nb_bits is also unique to each
                    // thread as i is in [0..total_nb_bits[ and offset is either 0
                    // or total_nb_bits

                    let a_ptr = input_bits_a_slc.get(i as usize);
                    let b = &input_bits_b[((i + offset) % total_nb_bits) as usize];

                    // pack bits into one block so that we have
                    // control_bit|b|a

                    let mux_gate_input = &mut *mux_inputs_slc.get(i as usize);
                    self.key.unchecked_scalar_mul_assign(mux_gate_input, 2);
                    self.key.unchecked_add_assign(mux_gate_input, b);
                    self.key.unchecked_scalar_mul_assign(mux_gate_input, 2);
                    self.key.unchecked_add_assign(mux_gate_input, &*a_ptr);

                    // we have
                    //
                    // control_bit|b|a
                    self.key.apply_lookup_table_assign(mux_gate_input, &mux_lut);
                    (*a_ptr).clone_from(mux_gate_input);
                }
            });
        }

        // rename for clarity
        let mut output_bits = input_bits_a;
        assert!(output_bits.len() == message_bits_per_block as usize * num_blocks);
        let output_blocks = UnsafeSlice::new(&mut ct.blocks);
        // We have to reconstruct blocks from the individual bits
        output_bits
            .as_mut_slice()
            .par_chunks_exact_mut(message_bits_per_block as usize)
            .enumerate()
            .for_each(|(block_index, grouped_bits)| {
                let (head, last) = grouped_bits.split_at_mut(message_bits_per_block as usize - 1);
                for bit in head.iter().rev() {
                    self.key.unchecked_scalar_mul_assign(&mut last[0], 2);
                    self.key.unchecked_add_assign(&mut last[0], bit);
                }
                // To give back a clean ciphertext
                self.key.message_extract_assign(&mut last[0]);
                let block = unsafe {
                    // SAFETY
                    //
                    // `get` still does bounds check,
                    // (but we know block_index always be valid)
                    //
                    // As block index in acquired from enumerate,
                    // we know it is unique to each thread/loop iteration
                    // thus only one thread will access the element at block_index
                    &mut *output_blocks.get(block_index)
                };
                std::mem::swap(block, &mut last[0]);
            });
    }
}
