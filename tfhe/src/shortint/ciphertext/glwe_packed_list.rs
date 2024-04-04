use itertools::Itertools;

use crate::core_crypto::prelude::*;
use crate::shortint::{CarryModulus, MessageModulus};

use super::{Ciphertext, Degree, NoiseLevel};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct GlwePackedCiphertextList {
    compressed_modulus_switched_lwe_ciphertext: Vec<GlweCiphertext<Vec<u64>>>,
    noise_levels: Vec<NoiseLevel>,
    degrees: Vec<Degree>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    pbs_order: PBSOrder,
    lwe_per_glwe: usize,
}

impl GlwePackedCiphertextList {
    pub fn pack_lwe_ciphertexts_into_glwes<KeyCont>(
        lwe_pksk: &LwePackingKeyswitchKey<KeyCont>,
        ciphertexts: impl Iterator<Item = Ciphertext>,
        lwe_per_glwe: usize,
    ) -> Self
    where
        KeyCont: Container<Element = u64> + Sync,
    {
        let mut glwe_ct_list = vec![];

        let mut noise_levels = vec![];
        let mut degrees = vec![];

        let polynomial_size = lwe_pksk.output_polynomial_size();
        let ciphertext_modulus = lwe_pksk.ciphertext_modulus();
        let glwe_size = lwe_pksk.output_glwe_size();
        let lwe_size = lwe_pksk.input_key_lwe_dimension().to_lwe_size();

        assert!(
            lwe_per_glwe <= polynomial_size.0,
            "Cannot pack more than polynomial_size(=) elements per glwe, {lwe_per_glwe} requested",
            polynomial_size.0
        );

        let mut pack_and_add_list = |list| {
            let mut out = GlweCiphertext::new(0, glwe_size, polynomial_size, ciphertext_modulus);

            let list = LweCiphertextList::from_container(list, lwe_size, ciphertext_modulus);

            par_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
                lwe_pksk, &list, &mut out,
            );

            glwe_ct_list.push(out);
        };

        let mut ciphertexts = ciphertexts.peekable();

        let first_ct = ciphertexts.peek().unwrap();

        let message_modulus = first_ct.message_modulus;
        let carry_modulus = first_ct.carry_modulus;
        let pbs_order = first_ct.pbs_order;

        'outer: loop {
            let mut list = vec![];

            for _ in 0..lwe_per_glwe {
                if let Some(ct) = ciphertexts.next() {
                    assert_eq!(
                        lwe_size, ct.ct.lwe_size(),
                        "All ciphertexts do not have the same lwe size as the packing keyswitch key"
                    );

                    assert_eq!(
                        message_modulus, ct.message_modulus,
                        "All ciphertexts do not have the same message modulus"
                    );
                    assert_eq!(
                        carry_modulus, ct.carry_modulus,
                        "All ciphertexts do not have the same carry modulus"
                    );
                    assert_eq!(
                        pbs_order, ct.pbs_order,
                        "All ciphertexts do not have the same pbs order"
                    );

                    noise_levels.push(ct.noise_level());
                    degrees.push(ct.degree);

                    list.extend(ct.ct.as_view().into_container());
                } else {
                    if !list.is_empty() {
                        pack_and_add_list(list);
                    }
                    break 'outer;
                }
            }

            pack_and_add_list(list);
        }

        Self {
            compressed_modulus_switched_lwe_ciphertext: glwe_ct_list,
            message_modulus,
            carry_modulus,
            pbs_order,
            noise_levels,
            degrees,
            lwe_per_glwe,
        }
    }

    pub fn unpack(&self) -> Vec<Ciphertext> {
        let polynomial_size = self.compressed_modulus_switched_lwe_ciphertext[0].polynomial_size();
        let ciphertext_modulus =
            self.compressed_modulus_switched_lwe_ciphertext[0].ciphertext_modulus();

        let glwe_size = self.compressed_modulus_switched_lwe_ciphertext[0].glwe_size();

        let lwe_size = glwe_size
            .to_glwe_dimension()
            .to_equivalent_lwe_dimension(polynomial_size)
            .to_lwe_size();

        let mut lwe_ct_list = vec![];

        for (out_lwe_index, (degree, noise_level)) in self
            .degrees
            .iter()
            .zip_eq(self.noise_levels.iter())
            .enumerate()
        {
            let glwe_index = out_lwe_index / self.lwe_per_glwe;

            let packed_glwe = &self.compressed_modulus_switched_lwe_ciphertext[glwe_index];

            let mut output_lwe = Ciphertext::new(
                LweCiphertext::new(0, lwe_size, ciphertext_modulus),
                *degree,
                *noise_level,
                self.message_modulus,
                self.carry_modulus,
                self.pbs_order,
            );

            let monomial_degree = MonomialDegree(out_lwe_index - glwe_index * self.lwe_per_glwe);

            extract_lwe_sample_from_glwe_ciphertext(
                packed_glwe,
                &mut output_lwe.ct,
                monomial_degree,
            );

            lwe_ct_list.push(output_lwe);
        }

        lwe_ct_list
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::shortint::engine::ShortintEngine;
    use crate::shortint::ClientKey;

    #[test]
    fn test_packing() {
        use crate::shortint::gen_keys;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        // Generate the client key and the server key:
        let (cks, _sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

        let pksk = ShortintEngine::with_thread_local_mut(|engine| {
            allocate_and_generate_new_lwe_packing_keyswitch_key(
                &cks.large_lwe_secret_key(),
                &cks.glwe_secret_key(),
                DecompositionBaseLog(22),
                DecompositionLevelCount(1),
                Gaussian::from_dispersion_parameter(StandardDev(0.0), 0.0),
                CiphertextModulus::new_native(),
                &mut engine.encryption_generator,
            )
        });

        let f = |x| x % 4;

        for number_to_pack in [1, 10, 2099, 30000] {
            test_packing_(&pksk, &cks, f, number_to_pack);
        }
    }

    fn test_packing_(
        pksk: &LwePackingKeyswitchKey<Vec<u64>>,
        cks: &ClientKey,
        f: impl Fn(u64) -> u64,
        number_to_pack: usize,
    ) {
        let ct = (0..number_to_pack).map(|i| cks.encrypt(f(i as u64)));

        let packed =
            GlwePackedCiphertextList::pack_lwe_ciphertexts_into_glwes(pksk, ct.into_iter(), 10);

        let unpacked = packed.unpack();

        assert_eq!(unpacked.len(), number_to_pack);

        for (i, ct) in unpacked.iter().enumerate() {
            let res = cks.decrypt(ct);

            assert_eq!(f(i as u64), res);
        }
    }
}
