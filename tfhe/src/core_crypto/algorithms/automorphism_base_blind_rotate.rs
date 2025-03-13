use super::automorphism_base_decomposition::{BaseDecomposer, Decomposition};
use crate::core_crypto::commons::math::random::{Distribution, Uniform};
use crate::core_crypto::entities::automorphism::Automorphism;
use crate::core_crypto::prelude::automorphism_base_decomposition::compute_power;
use crate::core_crypto::prelude::polynomial_algorithms::polynomial_wrapping_monic_monomial_div;
use crate::core_crypto::prelude::*;
use aligned_vec::ABox;
use tfhe_fft::c64;

struct AutomKey {
    automorphism: Automorphism,
    ksk: GlweKeyswitchKey<Vec<u64>>,
}

impl AutomKey {
    fn new<Gen: ByteRandomGenerator>(
        glwe_secret_key: &GlweSecretKey<Vec<u64>>,
        automorphism: Automorphism,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        glwe_noise_distribution: Gaussian<f64>,
        ciphertext_modulus: CiphertextModulus<u64>,
        encryption_generator: &mut EncryptionRandomGenerator<Gen>,
    ) -> Self {
        let mut autom_glwe_secret_key = GlweSecretKey::new_empty_key(
            0,
            glwe_secret_key.glwe_dimension(),
            glwe_secret_key.polynomial_size(),
        );

        automorphism.apply_to_glwe_secret_key(glwe_secret_key, &mut autom_glwe_secret_key);

        let ksk = allocate_and_generate_new_glwe_keyswitch_key(
            &autom_glwe_secret_key,
            glwe_secret_key,
            decomp_base_log,
            decomp_level_count,
            glwe_noise_distribution,
            ciphertext_modulus,
            encryption_generator,
        );

        Self { automorphism, ksk }
    }

    fn apply<InCont, OutCont>(
        &self,
        ct: &mut GlweCiphertext<InCont>,
        temp_ct: &mut GlweCiphertext<OutCont>,
    ) where
        InCont: ContainerMut<Element = u64>,
        OutCont: ContainerMut<Element = u64>,
    {
        self.automorphism.apply_to_glwe_ciphertext(ct, temp_ct);

        keyswitch_glwe_ciphertext(&self.ksk, temp_ct, ct);
    }
}

pub struct Travs {
    window_size: u16,
    ak: Vec<AutomKey>,
}

impl Travs {
    #[allow(clippy::too_many_arguments)]
    pub fn new<Gen: ByteRandomGenerator>(
        glwe_secret_key: &GlweSecretKey<Vec<u64>>,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        glwe_noise_distribution: Gaussian<f64>,
        ciphertext_modulus: CiphertextModulus<u64>,
        window_size: u16,
        base: u64,
        encryption_generator: &mut EncryptionRandomGenerator<Gen>,
    ) -> Self {
        let base = base as usize;

        let polynomial_size = glwe_secret_key.polynomial_size();

        let mut ak = vec![];

        let automorphism = Automorphism::new(2 * polynomial_size.0 - 1, polynomial_size);

        ak.push(AutomKey::new(
            glwe_secret_key,
            automorphism,
            decomp_base_log,
            decomp_level_count,
            glwe_noise_distribution,
            ciphertext_modulus,
            encryption_generator,
        ));

        let mut power = base;

        for _power_jump in 1..=window_size as usize {
            // power = base^_power_jump
            for change_sign in [false, true] {
                let power = if change_sign {
                    2 * polynomial_size.0 - power
                } else {
                    power
                };

                let automorphism = Automorphism::new(power, polynomial_size);

                ak.push(AutomKey::new(
                    glwe_secret_key,
                    automorphism,
                    decomp_base_log,
                    decomp_level_count,
                    glwe_noise_distribution,
                    ciphertext_modulus,
                    encryption_generator,
                ));
            }

            power = (power * base) % (2 * polynomial_size.0);
        }

        Self { window_size, ak }
    }
    fn get(&self, diff: u16, change_sign: bool) -> &AutomKey {
        &self.ak[2 * (diff as usize) + change_sign as usize - 1]
    }
}

pub struct TravBsk {
    pub window_size: u16,
    ak: Vec<Vec<FourierGgswCiphertext<ABox<[c64]>>>>,
}

impl TravBsk {
    #[allow(clippy::too_many_arguments)]
    pub fn new<D>(
        base: usize,
        lwe_secret_key: &LweSecretKey<Vec<u64>>,
        glwe_secret_key: &GlweSecretKey<Vec<u64>>,
        window_size: u16,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<u64>,
        glwe_noise_distribution: D,
        encryption_random_generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
    ) -> Self
    where
        D: Distribution,
        u64: Encryptable<Uniform, D>,
    {
        let polynomial_size = glwe_secret_key.polynomial_size();
        let glwe_size = glwe_secret_key.glwe_dimension().to_glwe_size();

        let mut autom_glwe_sk = glwe_secret_key.clone();

        let ak: Vec<_> = lwe_secret_key
            .as_ref()
            .iter()
            .copied()
            .map(|sk_bit| {
                let mut ak = vec![];

                let mut power = 1;

                for _power_jump in 0..=window_size {
                    for change_sign in [false, true] {
                        let power = if change_sign {
                            2 * polynomial_size.0 - power
                        } else {
                            power
                        };

                        let automorphism = Automorphism::new(power, polynomial_size);

                        automorphism.apply_to_glwe_secret_key(glwe_secret_key, &mut autom_glwe_sk);

                        let mut ggsw = GgswCiphertext::new(
                            0u64,
                            glwe_size,
                            polynomial_size,
                            decomp_base_log,
                            decomp_level_count,
                            ciphertext_modulus,
                        );

                        encrypt_monomial_ggsw_ciphertext(
                            &autom_glwe_sk,
                            glwe_secret_key,
                            &mut ggsw,
                            Cleartext(1),
                            sk_bit as usize,
                            glwe_noise_distribution,
                            encryption_random_generator,
                        );

                        let mut fourier_ggsw = FourierGgswCiphertext::new(
                            glwe_size,
                            polynomial_size,
                            decomp_base_log,
                            decomp_level_count,
                        );

                        convert_polynomials_list_to_fourier(
                            &ggsw.as_polynomial_list(),
                            fourier_ggsw.as_mut_polynomial_list(),
                            polynomial_size,
                        );

                        ak.push(fourier_ggsw);
                    }
                    power = (power * base) % (2 * polynomial_size.0);
                }

                ak
            })
            .collect();

        Self { window_size, ak }
    }

    fn get(
        &self,
        sk_index: usize,
        diff: u16,
        change_sign: bool,
    ) -> Option<&FourierGgswCiphertext<ABox<[c64]>>> {
        self.ak[sk_index].get(2 * (diff as usize) + change_sign as usize)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn blind_rotate(
    b: u64,
    ais: &[u64],
    bsks: &TravBsk,
    base: u64,
    trav: &Travs,
    lut: GlweCiphertextMutView<'_, u64>,
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
) {
    let mut accumulator = lut;

    assert_eq!(ais.len(), bsks.ak.len());

    let ciphertext_modulus = CiphertextModulus::new_native();

    let decomposer = BaseDecomposer::new(base, polynomial_size);

    let window_size = trav.window_size;

    let mut ai_s: Vec<_> = ais
        .iter()
        .enumerate()
        .map(|(index, value)| (index, decomposer.decompose_in_base(*value)))
        .collect();

    ai_s.sort_unstable_by_key(
        |(
            _index,
            Decomposition {
                base_power,
                negative,
            },
        )| (*base_power, *negative),
    );

    let mut tmp_poly = Polynomial::from_container(vec![0; polynomial_size.0]);

    let monomial_degree = MonomialDegree(b as usize);

    accumulator
        .as_mut_polynomial_list()
        .iter_mut()
        .for_each(|mut poly| {
            tmp_poly.as_mut().copy_from_slice(poly.as_ref());
            polynomial_wrapping_monic_monomial_div(&mut poly, &tmp_poly, monomial_degree);
        });

    let mut temp_accumulator =
        GlweCiphertext::new(0, glwe_size, polynomial_size, ciphertext_modulus);

    let mut previous_base_power = 0;
    let mut previous_negative = false;

    let mu = polynomial_size.0 / 2;

    let m = polynomial_size.0 * 2;

    for (
        i,
        Decomposition {
            base_power,
            negative,
        },
    ) in ai_s.iter().rev()
    {
        let mut diff = (mu + previous_base_power as usize - *base_power as usize) % mu;

        let sign_changed = *negative != previous_negative;

        loop {
            if let Some(ggsw) = bsks.get(*i, diff as u16, sign_changed) {
                let power = compute_power(base, diff as u64, m as u64) as usize;

                let power = if sign_changed { m - power } else { power };

                let automorphism = Automorphism::new(power, polynomial_size);

                automorphism.apply_to_glwe_ciphertext(&accumulator, &mut temp_accumulator);

                accumulator.as_mut().fill(0);

                add_external_product_assign(&mut accumulator, ggsw, &temp_accumulator);

                break;
            }

            assert!(0 < diff);

            if window_size < diff as u16 {
                let autom = trav.get(window_size, false);

                autom.apply(&mut accumulator, &mut temp_accumulator);

                diff -= window_size as usize;
            } else {
                let autom = trav.get(diff as u16, false);

                autom.apply(&mut accumulator, &mut temp_accumulator);

                diff = 0;
            }
        }

        previous_negative = *negative;
        previous_base_power = *base_power;
    }

    match (previous_base_power, previous_negative) {
        (0, false) => {}
        (mut diff, sign_changed) => {
            while window_size < diff {
                let autom = trav.get(window_size, false);

                autom.apply(&mut accumulator, &mut temp_accumulator);

                diff -= window_size;
            }

            let autom = trav.get(diff, sign_changed);

            autom.apply(&mut accumulator, &mut temp_accumulator);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core_crypto::fft_impl::common::automorphism_modulus_switch;
    use crate::core_crypto::prelude::test::TestResources;
    use std::iter::once;

    fn decrypt_print(glwe_secret_key: &GlweSecretKey<Vec<u64>>, acc: &GlweCiphertext<&[u64]>) {
        let mut result = PlaintextList::new(0, PlaintextCount(glwe_secret_key.polynomial_size().0));

        decrypt_glwe_ciphertext(glwe_secret_key, acc, &mut result);

        print_plaintext_list(&result);
    }

    fn print_plaintext_list(result: &PlaintextList<Vec<u64>>) {
        for i in result.as_ref() {
            let decomposer =
                SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));

            let decoded = decomposer.closest_representable(*i) >> 60;

            if decoded == 0 {
                print!("_");
            } else {
                print!(" {decoded} ");
            }
        }

        println!();
    }

    #[test]
    fn test() {
        let lwe_dimension = LweDimension(100);

        let glwe_size = GlweSize(2);
        let polynomial_size = PolynomialSize(2048);

        let lwe_noise_distribution = Gaussian::from_dispersion_parameter(StandardDev(0.0), 0.0);

        let glwe_noise_distribution = Gaussian::from_dispersion_parameter(StandardDev(0.0), 0.0);

        let decomp_base_log = DecompositionBaseLog(30);
        let decomp_level_count = DecompositionLevelCount(1);

        let mut rsc = TestResources::new();

        let ciphertext_modulus = CiphertextModulus::new_native();

        let lwe_secret_key: LweSecretKey<Vec<u64>> =
            allocate_and_generate_new_binary_lwe_secret_key(
                lwe_dimension,
                &mut rsc.secret_random_generator,
            );

        let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
            glwe_size.to_glwe_dimension(),
            polynomial_size,
            &mut rsc.secret_random_generator,
        );

        let base = 5;

        let window_size = 4;

        let travs = Travs::new(
            &glwe_secret_key,
            decomp_base_log,
            decomp_level_count,
            glwe_noise_distribution,
            ciphertext_modulus,
            window_size,
            base,
            &mut rsc.encryption_random_generator,
        );

        let bsks = TravBsk::new(
            base as usize,
            &lwe_secret_key,
            &glwe_secret_key,
            2,
            decomp_base_log,
            decomp_level_count,
            ciphertext_modulus,
            glwe_noise_distribution,
            &mut rsc.encryption_random_generator,
        );

        let lwe = allocate_and_encrypt_new_lwe_ciphertext(
            &lwe_secret_key,
            Plaintext(1 << 60),
            lwe_noise_distribution,
            ciphertext_modulus,
            &mut rsc.encryption_random_generator,
        );

        let (lwe_mask, lwe_body) = lwe.get_mask_and_body();

        let b = automorphism_modulus_switch(*lwe_body.data, polynomial_size) as u64;

        let ais: Vec<u64> = lwe_mask
            .as_ref()
            .iter()
            .map(|a| automorphism_modulus_switch(*a, polynomial_size) as u64)
            .collect();

        let mut lut = vec![0; polynomial_size.0];

        lut[0] = 1 << 60;

        lut[1] = 2 << 60;

        lut[2] = 3 << 60;

        let lut_glwe = allocate_and_trivially_encrypt_new_glwe_ciphertext(
            glwe_size,
            &PlaintextList::from_container(lut.clone()),
            ciphertext_modulus,
        );

        let mut acc = lut_glwe;

        blind_rotate(
            b,
            &ais,
            &bsks,
            base,
            &travs,
            acc.as_mut_view(),
            polynomial_size,
            glwe_size,
        );

        println!("final");

        decrypt_print(&glwe_secret_key, &acc.as_view());

        let log_modulus = polynomial_size.to_blind_rotation_input_modulus_log();

        let container: Vec<u64> = ais
            .iter()
            .copied()
            .chain(once(b))
            .map(|a| a << (64 - log_modulus.0))
            .collect();

        let ms_ed = LweCiphertext::from_container(container, ciphertext_modulus);

        let shift = decrypt_lwe_ciphertext(&lwe_secret_key, &ms_ed);

        let decomposer = SignedDecomposer::new(
            DecompositionBaseLog(log_modulus.0),
            DecompositionLevelCount(1),
        );

        let decoded = decomposer.closest_representable(shift.0) >> (64 - log_modulus.0);

        dbg!(decoded);

        lut.rotate_left(decoded as usize);

        let lut = PlaintextList::from_container(lut);

        println!("expected");

        print_plaintext_list(&lut);
    }
}
