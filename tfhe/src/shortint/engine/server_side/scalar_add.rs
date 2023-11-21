use crate::core_crypto::algorithms::*;
use crate::core_crypto::entities::*;
use crate::shortint::ciphertext::Degree;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::{Ciphertext, ServerKey};

impl ShortintEngine {
    pub(crate) fn unchecked_scalar_add(
        &mut self,
        server_key: &ServerKey,
        ct: &Ciphertext,
        scalar: u8,
    ) -> Ciphertext {
        let mut ct_result = ct.clone();
        self.unchecked_scalar_add_assign(server_key, &mut ct_result, scalar);
        ct_result
    }

    pub(crate) fn unchecked_scalar_add_assign(
        &mut self,
        server_key: &ServerKey,
        ct: &mut Ciphertext,
        scalar: u8,
    ) {
        let delta =
            (1_u64 << 63) / (server_key.message_modulus.0 * server_key.carry_modulus.0) as u64;
        let shift_plaintext = u64::from(scalar) * delta;
        let encoded_scalar = Plaintext(shift_plaintext);
        lwe_ciphertext_plaintext_add_assign(&mut ct.ct, encoded_scalar);

        ct.degree = Degree(ct.degree.0 + scalar as usize);
    }

    // by convention smart operations take mut refs to their inputs, even if they do not modify them
    #[allow(clippy::needless_pass_by_ref_mut)]
    pub(crate) fn smart_scalar_add(
        &mut self,
        server_key: &ServerKey,
        ct: &mut Ciphertext,
        scalar: u8,
    ) -> Ciphertext {
        let mut ct_result = ct.clone();
        self.smart_scalar_add_assign(server_key, &mut ct_result, scalar);

        ct_result
    }

    pub(crate) fn smart_scalar_add_assign(
        &mut self,
        server_key: &ServerKey,
        ct: &mut Ciphertext,
        scalar: u8,
    ) {
        // Direct scalar computation is possible
        if server_key.is_scalar_add_possible(ct, scalar).is_ok() {
            self.unchecked_scalar_add_assign(server_key, ct, scalar);
        } else {
            // If the scalar is too large, PBS is used to compute the scalar mul
            let acc = server_key
                .generate_msg_lookup_table(|x| scalar as u64 + x, server_key.message_modulus);
            self.apply_lookup_table_assign(server_key, ct, &acc);
            ct.degree = Degree(server_key.message_modulus.0 - 1);
        }
    }
}
