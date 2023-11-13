use crate::core_crypto::algorithms::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::misc::divide_ceil;
use crate::shortint::ciphertext::Degree;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::{Ciphertext, ServerKey};

impl ShortintEngine {
    pub(crate) fn unchecked_neg(&mut self, server_key: &ServerKey, ct: &Ciphertext) -> Ciphertext {
        let mut result = ct.clone();
        self.unchecked_neg_assign(server_key, &mut result);
        result
    }

    pub(crate) fn unchecked_neg_with_correcting_term(
        &mut self,
        server_key: &ServerKey,
        ct: &Ciphertext,
    ) -> (Ciphertext, u64) {
        let mut result = ct.clone();
        let z = self.unchecked_neg_assign_with_correcting_term(server_key, &mut result);
        (result, z)
    }

    pub(crate) fn unchecked_neg_assign(&mut self, server_key: &ServerKey, ct: &mut Ciphertext) {
        let _z = self.unchecked_neg_assign_with_correcting_term(server_key, ct);
    }

    pub(crate) fn unchecked_neg_assign_with_correcting_term(
        &mut self,
        server_key: &ServerKey,
        ct: &mut Ciphertext,
    ) -> u64 {
        // z = ceil( degree / 2^p ) * 2^p
        let msg_mod = ct.message_modulus.0;
        // Ensure z is always >= 1 (which would not be the case if degree == 0)
        // some algorithms (e.g. overflowing_sub) require this even for trivial zeros
        let mut z = divide_ceil(ct.degree.0, msg_mod).max(1) as u64;
        z *= msg_mod as u64;

        // Value of the shift we multiply our messages by
        let delta =
            (1_u64 << 63) / (server_key.message_modulus.0 * server_key.carry_modulus.0) as u64;

        //Scaling + 1 on the padding bit
        let w = Plaintext(z * delta);

        // (0,Delta*z) - ct
        lwe_ciphertext_opposite_assign(&mut ct.ct);

        lwe_ciphertext_plaintext_add_assign(&mut ct.ct, w);

        // Update the degree
        ct.degree = Degree(z as usize);

        z
    }

    pub(crate) fn smart_neg(&mut self, server_key: &ServerKey, ct: &mut Ciphertext) -> Ciphertext {
        // If the ciphertext cannot be negated without exceeding the capacity of a ciphertext
        if !server_key.is_neg_possible(ct) {
            self.message_extract_assign(server_key, ct);
        }

        assert!(server_key.is_neg_possible(ct));

        self.unchecked_neg(server_key, ct)
    }

    pub(crate) fn smart_neg_assign(&mut self, server_key: &ServerKey, ct: &mut Ciphertext) {
        // If the ciphertext cannot be negated without exceeding the capacity of a ciphertext
        if !server_key.is_neg_possible(ct) {
            self.message_extract_assign(server_key, ct);
        }
        assert!(server_key.is_neg_possible(ct));
        self.unchecked_neg_assign(server_key, ct)
    }
}
