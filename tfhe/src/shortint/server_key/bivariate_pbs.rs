use super::{CheckError, CiphertextNoiseDegree, LookupTable, ServerKey};
use crate::core_crypto::prelude::container::Container;
use crate::shortint::ciphertext::{Degree, MaxDegree, NoiseLevel};
use crate::shortint::server_key::add::unchecked_add_assign;
use crate::shortint::{Ciphertext, MessageModulus};
use std::cmp::Ordering;

#[must_use]
pub struct BivariateLookupTable<C: Container<Element = u64>> {
    // A bivariate lookup table is an univariate loolookup table
    // where the message space is shared to encode
    // 2 values
    pub acc: LookupTable<C>,
    // By how much we shift the lhs in the LUT
    pub ct_right_modulus: MessageModulus,
}

pub type BivariateLookupTableOwned = BivariateLookupTable<Vec<u64>>;
pub type BivariateLookupTableMutView<'a> = BivariateLookupTable<&'a mut [u64]>;
pub type BivariateLookupTableView<'a> = BivariateLookupTable<&'a [u64]>;

/// Returns whether it is possible to pack lhs and rhs into a unique
/// ciphertext without exceeding the max storable value using the formula:
/// `unique_ciphertext = (lhs * factor) + rhs`
fn ciphertexts_can_be_packed_without_exceeding_space_or_noise(
    server_key: &ServerKey,
    lhs: CiphertextNoiseDegree,
    rhs: CiphertextNoiseDegree,
    factor: u64,
) -> Result<(), CheckError> {
    let final_degree = (lhs.degree * factor) + rhs.degree;

    // Do not use server key max degree as it may be smaller (to keep carry propagation margin)
    let max_degree =
        MaxDegree::from_msg_carry_modulus(server_key.message_modulus, server_key.carry_modulus);

    max_degree.validate(final_degree)?;

    let final_noise_level = (lhs.noise_level * factor) + rhs.noise_level;

    server_key.max_noise_level.validate(final_noise_level)?;

    if rhs.degree.get() >= factor {
        return Err(CheckError::UnscaledScaledOverlap {
            unscaled_degree: rhs.degree,
            scale: factor as u8,
        });
    }

    Ok(())
}

impl ServerKey {
    /// Generates a bivariate accumulator
    pub fn generate_lookup_table_bivariate_with_factor<F>(
        &self,
        f: F,
        left_message_scaling: MessageModulus,
    ) -> BivariateLookupTableOwned
    where
        F: Fn(u64, u64) -> u64,
    {
        // Depending on the factor used, rhs and / or lhs may have carries
        // (degree >= message_modulus) which is why we need to apply the message_modulus
        // to clear them
        let factor_u64 = left_message_scaling.0;
        let message_modulus = self.message_modulus.0;
        let wrapped_f = |input: u64| -> u64 {
            let lhs = (input / factor_u64) % message_modulus;
            let rhs = (input % factor_u64) % message_modulus;

            f(lhs, rhs)
        };
        let accumulator = self.generate_lookup_table(wrapped_f);

        BivariateLookupTable {
            acc: accumulator,
            ct_right_modulus: left_message_scaling,
        }
    }

    /// Constructs the lookup table for a given bivariate function as input.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 3;
    /// let msg_2 = 2;
    ///
    /// let ct1 = cks.encrypt(msg_1);
    /// let ct2 = cks.encrypt(msg_2);
    ///
    /// let f = |x, y| (x + y) % 4;
    ///
    /// let acc = sks.generate_lookup_table_bivariate(f);
    ///
    /// let ct_res = sks.apply_lookup_table_bivariate(&ct1, &ct2, &acc);
    ///
    /// let dec = cks.decrypt(&ct_res);
    /// assert_eq!(dec, f(msg_1, msg_2));
    /// ```
    pub fn generate_lookup_table_bivariate<F>(&self, f: F) -> BivariateLookupTableOwned
    where
        F: Fn(u64, u64) -> u64,
    {
        self.generate_lookup_table_bivariate_with_factor(f, self.message_modulus)
    }

    /// Compute a keyswitch and programmable bootstrap.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg: u64 = 3;
    /// let msg2: u64 = 2;
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg2);
    /// let modulus = cks.parameters.message_modulus().0;
    ///
    /// // Generate the lookup table for the function f: x, y -> (x * y * x) mod 4
    /// let acc = sks.generate_lookup_table_bivariate(|x, y| x * y * x % modulus);
    /// let ct_res = sks.unchecked_apply_lookup_table_bivariate(&ct1, &ct2, &acc);
    ///
    /// let dec = cks.decrypt(&ct_res);
    /// assert_eq!(dec, (msg * msg2 * msg) % modulus);
    /// ```
    pub fn unchecked_apply_lookup_table_bivariate(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
        acc: &BivariateLookupTableOwned,
    ) -> Ciphertext {
        let mut ct_res = ct_left.clone();
        self.unchecked_apply_lookup_table_bivariate_assign(&mut ct_res, ct_right, acc);
        ct_res
    }

    pub fn unchecked_apply_lookup_table_bivariate_assign(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
        acc: &BivariateLookupTableOwned,
    ) {
        let modulus = ct_right.degree.get() + 1;
        assert!(modulus <= acc.ct_right_modulus.0);

        self.unchecked_scalar_mul_assign(ct_left, acc.ct_right_modulus.0 as u8);

        unchecked_add_assign(ct_left, ct_right, self.max_noise_level);

        // Compute the PBS
        self.apply_lookup_table_assign(ct_left, &acc.acc);
    }

    /// Compute a keyswitch and programmable bootstrap.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg: u64 = 3;
    /// let msg2: u64 = 2;
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg2);
    /// let modulus = cks.parameters.message_modulus().0;
    ///
    /// // Generate the lookup table for the function f: x, y -> (x * y * x) mod 4
    /// let acc = sks.generate_lookup_table_bivariate(|x, y| x * y * x % modulus);
    /// let ct_res = sks.apply_lookup_table_bivariate(&ct1, &ct2, &acc);
    ///
    /// let dec = cks.decrypt(&ct_res);
    /// assert_eq!(dec, (msg * msg2 * msg) % modulus);
    /// ```
    pub fn apply_lookup_table_bivariate(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
        acc: &BivariateLookupTableOwned,
    ) -> Ciphertext {
        let ct_left_clean;
        let ct_right_clean;

        let (ct_left, ct_right) = if self
            .is_functional_bivariate_pbs_possible(
                ct_left.noise_degree(),
                ct_right.noise_degree(),
                Some(acc),
            )
            .is_err()
        {
            // After the message_extract, we'll have ct_left, ct_right in [0, message_modulus[
            // so the factor has to be message_modulus
            assert_eq!(ct_right.message_modulus.0, acc.ct_right_modulus.0);
            ct_left_clean = self.message_extract(ct_left);
            ct_right_clean = self.message_extract(ct_right);

            (&ct_left_clean, &ct_right_clean)
        } else {
            (ct_left, ct_right)
        };

        self.is_functional_bivariate_pbs_possible(
            ct_left.noise_degree(),
            ct_right.noise_degree(),
            Some(acc),
        )
        .unwrap();

        self.unchecked_apply_lookup_table_bivariate(ct_left, ct_right, acc)
    }

    pub fn apply_lookup_table_bivariate_assign(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
        acc: &BivariateLookupTableOwned,
    ) {
        if self
            .is_functional_bivariate_pbs_possible(
                ct_left.noise_degree(),
                ct_right.noise_degree(),
                Some(acc),
            )
            .is_err()
        {
            // After the message_extract, we'll have ct_left, ct_right in [0, message_modulus[
            // so the factor has to be message_modulus
            assert_eq!(ct_right.message_modulus.0, acc.ct_right_modulus.0);
            self.message_extract_assign(ct_left);
            self.message_extract_assign(ct_right);
        }

        self.is_functional_bivariate_pbs_possible(
            ct_left.noise_degree(),
            ct_right.noise_degree(),
            Some(acc),
        )
        .unwrap();

        self.unchecked_apply_lookup_table_bivariate_assign(ct_left, ct_right, acc);
    }
    /// Generic programmable bootstrap where messages are concatenated into one ciphertext to
    /// evaluate a bivariate function. This is used to apply many binary operations (comparisons,
    /// multiplications, division).
    pub fn unchecked_evaluate_bivariate_function<F>(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
        f: F,
    ) -> Ciphertext
    where
        F: Fn(u64, u64) -> u64,
    {
        let mut ct_res = ct_left.clone();
        self.unchecked_evaluate_bivariate_function_assign(&mut ct_res, ct_right, f);
        ct_res
    }

    pub fn unchecked_evaluate_bivariate_function_assign<F>(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
        f: F,
    ) where
        F: Fn(u64, u64) -> u64,
    {
        // Generate the lookup _table for the function
        let factor = MessageModulus(ct_right.degree.get() + 1);
        let lookup_table = self.generate_lookup_table_bivariate_with_factor(f, factor);

        self.unchecked_apply_lookup_table_bivariate_assign(ct_left, ct_right, &lookup_table);
    }

    /// Verify if a functional bivariate pbs can be applied on ct_left and ct_right.
    /// If the bivariate lookup table is already built, it must be passed to do the check with the
    /// correct scale.
    /// If the bivariate lookup table is going to be built (if this function returns true) assuming
    /// ct1 is going to be scaled by ct2.degree+1, None must be passed.
    pub fn is_functional_bivariate_pbs_possible(
        &self,
        ct1: CiphertextNoiseDegree,
        ct2: CiphertextNoiseDegree,
        lut: Option<&BivariateLookupTableOwned>,
    ) -> Result<(), CheckError> {
        let scale = lut.map_or_else(|| ct2.degree.get() + 1, |lut| lut.ct_right_modulus.0);

        ciphertexts_can_be_packed_without_exceeding_space_or_noise(self, ct1, ct2, scale)?;

        Ok(())
    }

    pub fn smart_evaluate_bivariate_function_assign<F>(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
        f: F,
    ) where
        F: Fn(u64, u64) -> u64,
    {
        *ct_left = self.smart_evaluate_bivariate_function(ct_left, ct_right, f);
    }

    pub fn smart_evaluate_bivariate_function<F>(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
        f: F,
    ) -> Ciphertext
    where
        F: Fn(u64, u64) -> u64,
    {
        let ScalingOperation {
            order,
            scaled_behavior,
            unscaled_bootstrapped,
            scale,
        } = self
            .get_best_bivariate_scaling(ct_left, ct_right)
            .expect("Current parameters can't be used to make a bivariate function evaluation");

        let (ct_to_scale, unscaled_ct) = match order {
            Order::ScaleLeft => (ct_left, ct_right),
            Order::ScaleRight => (ct_right, ct_left),
        };

        if unscaled_bootstrapped {
            self.message_extract_assign(unscaled_ct);
        }

        let scaled = match scaled_behavior {
            ScaledBehavior::Scaled => self.unchecked_scalar_mul(ct_to_scale, scale),
            ScaledBehavior::BootstrappedThenScaled => {
                self.message_extract_assign(ct_to_scale);

                self.unchecked_scalar_mul(ct_to_scale, scale)
            }
            ScaledBehavior::ScaledInBootstrap => {
                let lookup_table =
                    self.generate_lookup_table(|a| (a % self.message_modulus.0) * u64::from(scale));

                self.apply_lookup_table(ct_to_scale, &lookup_table)
            }
        };

        let temp = self.unchecked_add(&scaled, unscaled_ct);

        let lookup_table = match order {
            Order::ScaleLeft => self
                .generate_lookup_table_bivariate_with_factor(f, MessageModulus(u64::from(scale))),
            Order::ScaleRight => self.generate_lookup_table_bivariate_with_factor(
                |rhs: u64, lhs: u64| f(lhs, rhs),
                MessageModulus(u64::from(scale)),
            ),
        };

        self.apply_lookup_table(&temp, &lookup_table.acc)
    }

    /// To apply a bivariate function to two inputs, we must have both their messages on the same
    /// ciphertexts To do that, we add a shift of an input 1 to the other input 2
    /// But we must ensure that:
    ///  - The carry of the input 2 does not overlap with input 1 message
    ///  - The padding bit is clean
    ///  - The noise is not too high
    ///
    /// We have multiple possibilities:
    ///  - choose which input to shift
    ///  - bootstrap the unscaled input (less noise and allows for a smaller scale as not carry
    ///    overlapping is possible) or not
    ///  - do not bootstrap the scaled input (cheaper), scale it in a bootstrap (least noise) or
    ///    bootstrap it then scale it (the input is cleaner for other operations)
    ///
    /// This function choose the solution with the smallest cost and in case of equality, with the
    /// most cleaned inputs
    fn get_best_bivariate_scaling(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> Option<ScalingOperation> {
        let valid = |scaled_noise_degree: CiphertextNoiseDegree,
                     unscaled_noise_degree: CiphertextNoiseDegree| {
            let valid_degree = self
                .max_degree
                .validate(scaled_noise_degree.degree + unscaled_noise_degree.degree)
                .is_ok();
            let valid_noise = self
                .max_noise_level
                .validate(scaled_noise_degree.noise_level + unscaled_noise_degree.noise_level)
                .is_ok();

            valid_degree && valid_noise
        };

        [Order::ScaleLeft, Order::ScaleRight]
            .into_iter()
            .flat_map(move |order| {
                let (scaled_ct, unscaled_ct) = match order {
                    Order::ScaleLeft => (ct_left, ct_right),
                    Order::ScaleRight => (ct_right, ct_left),
                };

                [false, true]
                    .into_iter()
                    .flat_map(move |unscaled_bootstrapped| {
                        let unscaled_noise_degree = if unscaled_bootstrapped {
                            unscaled_ct.noise_degree_if_bootstrapped()
                        } else {
                            unscaled_ct.noise_degree()
                        };

                        let scale = unscaled_noise_degree.degree.get() as u8 + 1;

                        [
                            ScaledBehavior::Scaled,
                            ScaledBehavior::BootstrappedThenScaled,
                            ScaledBehavior::ScaledInBootstrap,
                        ]
                        .into_iter()
                        .filter_map(move |scaled_behavior| {
                            let scaled_noise_degree = match scaled_behavior {
                                ScaledBehavior::Scaled => scaled_ct.noise_degree_if_scaled(scale),
                                ScaledBehavior::BootstrappedThenScaled => {
                                    scaled_ct.noise_degree_if_bootstrapped_then_scaled(scale)
                                }
                                ScaledBehavior::ScaledInBootstrap => {
                                    scaled_ct.noise_degree_if_scaled_in_bootstrap(scale)
                                }
                            };

                            if valid(scaled_noise_degree, unscaled_noise_degree) {
                                Some(ScalingOperation {
                                    order,
                                    scaled_behavior,
                                    unscaled_bootstrapped,
                                    scale,
                                })
                            } else {
                                None
                            }
                        })
                    })
            })
            .max_by(
                |op1, op2| match op1.number_of_pbs().cmp(&op2.number_of_pbs()) {
                    // If op1 has less pbs,
                    // we want it to dominate (Greater) op2 (as we take the max)
                    Ordering::Less => Ordering::Greater,
                    Ordering::Greater => Ordering::Less,
                    // op1 and op2 have as many pbs,
                    // if op1 has more cleaned inputs, we want it to dominate op2
                    Ordering::Equal => op1.cleaned_inputs().cmp(&op2.cleaned_inputs()),
                },
            )
    }
}

#[derive(Copy, Clone, Debug)]
enum Order {
    ScaleLeft,
    ScaleRight,
}

#[derive(Copy, Clone, Debug)]
enum ScaledBehavior {
    Scaled,
    BootstrappedThenScaled,
    ScaledInBootstrap,
}

#[derive(Copy, Clone, Debug)]
struct ScalingOperation {
    order: Order,
    scaled_behavior: ScaledBehavior,
    unscaled_bootstrapped: bool,
    scale: u8,
}

impl ScalingOperation {
    fn cleaned_inputs(self) -> usize {
        let scaled_bootstrapped_inplace =
            matches!(self.scaled_behavior, ScaledBehavior::BootstrappedThenScaled);

        usize::from(self.unscaled_bootstrapped) + usize::from(scaled_bootstrapped_inplace)
    }
    fn number_of_pbs(self) -> usize {
        let scaled_bootstrapped = matches!(
            self.scaled_behavior,
            ScaledBehavior::BootstrappedThenScaled | ScaledBehavior::ScaledInBootstrap
        );

        usize::from(self.unscaled_bootstrapped) + usize::from(scaled_bootstrapped)
    }
}

impl Ciphertext {
    fn noise_degree_if_scaled(&self, scale: u8) -> CiphertextNoiseDegree {
        CiphertextNoiseDegree {
            noise_level: self.noise_level() * u64::from(scale),
            degree: self.degree * u64::from(scale),
        }
    }
    fn noise_degree_if_bootstrapped_then_scaled(&self, scale: u8) -> CiphertextNoiseDegree {
        let CiphertextNoiseDegree {
            noise_level: noise,
            degree,
        } = self.noise_degree_if_bootstrapped();

        CiphertextNoiseDegree {
            noise_level: noise * u64::from(scale),
            degree: degree * u64::from(scale),
        }
    }
    fn noise_degree_if_scaled_in_bootstrap(&self, scale: u8) -> CiphertextNoiseDegree {
        CiphertextNoiseDegree {
            noise_level: NoiseLevel::NOMINAL,
            degree: Degree::new(self.degree.get().min(self.message_modulus.0 - 1))
                * u64::from(scale),
        }
    }
}
