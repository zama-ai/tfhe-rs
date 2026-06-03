use std::iter::once;

use super::Diff;
use crate::core_crypto::commons::math::random::{Distribution, Uniform};
use crate::core_crypto::experimental::entities::automorphism::Automorphism;
use crate::core_crypto::fft_impl::fft64::math::fft::par_convert_polynomials_list_to_fourier;
use crate::core_crypto::prelude::*;
use aligned_vec::ABox;
use itertools::izip;
use tfhe_fft::c64;

/// Traversal bootstrapping keys:
/// a set of GGSW(Aut_u(sk) -> sk, X^si)
/// where u is in the first window_size elements of `[base^0, -base^0, base^1, -base^1, base^2,
/// -base^2, …]`
///
/// It allows to merge the external product with the preceding keyswitch.
///
/// When `allow_combine = true`, additional combined keys are generated for `s_i + s_{i+1}`,
/// enabling the bit-combining modulus-switch path that avoids even mask values without
/// extra noise.
pub struct TravBsk {
    ak: Vec<Vec<FourierGgswCiphertext<ABox<[c64]>>>>,
    ak_combined: Vec<Vec<FourierGgswCiphertext<ABox<[c64]>>>>,
}

impl TravBsk {
    #[allow(clippy::too_many_arguments)]
    pub fn new<D>(
        base: usize,
        lwe_secret_key: &LweSecretKey<Vec<u64>>,
        glwe_secret_key: &GlweSecretKey<Vec<u64>>,
        // window_size = 1 corresponds to Algorithm 3.2
        // Bigger window_size corresponds to Algorithm 4.1
        window_size: u16,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<u64>,
        glwe_noise_distribution: D,
        encryption_random_generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
        // allow_combine corresponds to the second method described in section A.1
        allow_combine: bool,
    ) -> Self
    where
        D: Distribution + Sync,
        u64: Encryptable<Uniform, D>,
    {
        let polynomial_size = glwe_secret_key.polynomial_size();

        let mut build_autom_bsk_key = |sk_integer: u64, power: usize, sign_change| {
            build_autom_bsk_key(
                glwe_secret_key,
                decomp_base_log,
                decomp_level_count,
                ciphertext_modulus,
                glwe_noise_distribution,
                encryption_random_generator,
                sk_integer,
                power,
                sign_change,
            )
        };

        let mut build_ggsw_for_sk = |sk_integer| {
            let mut power = 1;

            (0..)
                .flat_map(|_| {
                    let positive = build_autom_bsk_key(sk_integer, power, false);

                    let negative = build_autom_bsk_key(sk_integer, power, true);

                    power = (power * base) % (2 * polynomial_size.0);

                    [positive, negative].into_iter()
                })
                .take(window_size as usize)
                .collect()
        };

        let lwe_secret_key = lwe_secret_key.as_ref();

        let ak: Vec<_> = lwe_secret_key
            .iter()
            .copied()
            .map(&mut build_ggsw_for_sk)
            .collect();

        let ak_combined = if allow_combine {
            izip!(
                lwe_secret_key,
                lwe_secret_key[1..].iter().chain(once(&lwe_secret_key[0]))
            )
            .map(|(sk_integer1, sk_integer2)| build_ggsw_for_sk(*sk_integer1 + *sk_integer2))
            .collect()
        } else {
            Vec::new()
        };

        Self { ak, ak_combined }
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.ak.len()
    }

    /// Returns the GGSW ciphertext for secret key integer at `sk_index` and automorphism step
    /// `diff`.
    ///
    /// Returns `None` when `diff` is outside the pre-computed window.
    ///
    /// Set `combined = true` to use the `s_i + s_{i+1}` combined key.
    pub fn get(
        &self,
        sk_index: usize,
        diff: Diff,
        combined: bool,
    ) -> Option<&FourierGgswCiphertext<ABox<[c64]>>> {
        let index = 2 * diff.power_diff + diff.sign_change as usize;

        if combined {
            assert!(!self.ak_combined.is_empty());

            self.ak_combined[sk_index].get(index)
        } else {
            self.ak[sk_index].get(index)
        }
    }
}

/// Builds a single Fourier-domain GGSW key encrypting `sk_integer` for automorphism exponent
/// `(power, sign_change)`.
///
/// Steps:
/// 1. Derive the automorphism secret key `σ_power(glwe_secret_key)`.
/// 2. Encrypt a monomial GGSW of `sk_integer` under the automorphism key (input) and the original
///    GLWE key (output), ready for an external product that simultaneously applies the automorphism
///    and multiplies by `sk_integer`.
/// 3. Convert to the Fourier domain.
#[allow(clippy::too_many_arguments)]
fn build_autom_bsk_key<D>(
    glwe_secret_key: &GlweSecretKey<Vec<u64>>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    ciphertext_modulus: CiphertextModulus<u64>,
    glwe_noise_distribution: D,
    encryption_random_generator: &mut EncryptionRandomGenerator<
        tfhe_csprng::generators::AesniRandomGenerator,
    >,
    sk_integer: u64,
    power: usize,
    sign_change: bool,
) -> FourierGgswCiphertext<ABox<[pulp::num_complex::Complex<f64>], aligned_vec::ConstAlign<128>>>
where
    D: Distribution + Sync,
    u64: Encryptable<Uniform, D>,
{
    let glwe_dimension = glwe_secret_key.glwe_dimension();
    let glwe_size = glwe_dimension.to_glwe_size();
    let polynomial_size = glwe_secret_key.polynomial_size();

    let power = if sign_change {
        2 * polynomial_size.0 - power
    } else {
        power
    };

    let mut autom_glwe_sk = glwe_secret_key.clone();

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

    par_encrypt_monomial_ggsw_ciphertext(
        &autom_glwe_sk,
        glwe_secret_key,
        &mut ggsw,
        Cleartext(1),
        sk_integer as usize,
        glwe_noise_distribution,
        encryption_random_generator,
    );

    let mut fourier_ggsw = FourierGgswCiphertext::new(
        glwe_size,
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
    );

    let fft = Fft::new(polynomial_size);
    let fft = fft.as_view();

    par_convert_polynomials_list_to_fourier(
        fourier_ggsw.as_mut_polynomial_list().as_mut(),
        ggsw.as_polynomial_list().as_ref(),
        polynomial_size,
        fft,
    );

    fourier_ggsw
}
