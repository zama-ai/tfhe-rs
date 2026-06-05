use crate::high_level_api::global_state;
use crate::high_level_api::integers::FheIntegerType;
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::re_randomization::{
    ReRandomizationHashAlgo, ReRandomizationMetadata, ReRandomizationMode,
};
use crate::integer::server_key::radix_parallel::bitonic_shuffle::BitonicShuffleKeySize;
use crate::OprfSeed;

/// Shuffles `data` into a uniformly random permutation using a bitonic
/// sorting network with OPRF-generated random keys.
///
/// `key_size` controls the bit-width of the random sort keys used internally,
/// either by specifying a target collision probability or by passing a raw
/// bit count. Larger keys reduce collision probability (improving shuffle
/// uniformity) at the cost of more computation per comparison.
///
/// The re-randomization metadata of the input elements is not preserved
/// through the shuffle.
///
/// # Errors
///
/// Returns an error if the resolved key block count is 0
pub fn bitonic_shuffle<T, S>(
    data: Vec<T>,
    key_size: BitonicShuffleKeySize,
    seed: S,
) -> Result<Vec<T>, crate::Error>
where
    T: FheIntegerType,
    S: OprfSeed,
{
    global_state::with_internal_keys(|key| match key {
        InternalServerKey::Cpu(cpu_key) => {
            let inner = data.into_iter().map(|v| v.into_cpu()).collect();
            let result =
                cpu_key
                    .pbs_key()
                    .bitonic_shuffle(&cpu_key.oprf_key(), inner, key_size, seed)?;
            Ok(result
                .into_iter()
                .map(|ct| T::from_cpu(ct, cpu_key.tag.clone(), ReRandomizationMetadata::default()))
                .collect())
        }
        #[cfg(feature = "gpu")]
        InternalServerKey::Cuda(_) => Err(crate::Error::new(
            "bitonic_shuffle is not supported on Cuda".to_string(),
        )),
        #[cfg(feature = "hpu")]
        InternalServerKey::Hpu(_) => Err(crate::Error::new(
            "bitonic_shuffle is not supported on Hpu".to_string(),
        )),
    })
}

pub fn re_randomized_keys_bitonic_shuffle<T, S>(
    data: Vec<T>,
    key_size: BitonicShuffleKeySize,
    seed: S,
    re_randomization_mode: ReRandomizationMode,
    re_randomization_hash_algo: ReRandomizationHashAlgo,
) -> Result<Vec<T>, crate::Error>
where
    T: FheIntegerType,
    S: OprfSeed,
{
    global_state::with_internal_keys(|key| match key {
        InternalServerKey::Cpu(cpu_key) => {
            let re_randomization_key =
                cpu_key.integer_re_randomization_key_from_mode(re_randomization_mode)?;
            let inner = data.into_iter().map(|v| v.into_cpu()).collect();
            let result = cpu_key.pbs_key().re_randomized_keys_bitonic_shuffle(
                &cpu_key.oprf_key(),
                inner,
                key_size,
                seed,
                &re_randomization_key,
                re_randomization_hash_algo,
            )?;
            Ok(result
                .into_iter()
                .map(|ct| T::from_cpu(ct, cpu_key.tag.clone(), ReRandomizationMetadata::default()))
                .collect())
        }
        #[cfg(feature = "gpu")]
        InternalServerKey::Cuda(_) => Err(crate::Error::new(
            "bitonic_shuffle is not supported on Cuda".to_string(),
        )),
        #[cfg(feature = "hpu")]
        InternalServerKey::Hpu(_) => Err(crate::Error::new(
            "bitonic_shuffle is not supported on Hpu".to_string(),
        )),
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::core_crypto::prelude::new_seeder;
    use crate::high_level_api::prelude::*;
    use crate::high_level_api::tests::setup_default_cpu;
    use crate::high_level_api::{set_server_key, ClientKey, ConfigBuilder, ServerKey};
    use crate::shortint::parameters::ReRandomizationParameters;
    use crate::{FheInt8, FheUint8};
    use rand::Rng;

    #[test]
    fn test_bitonic_shuffle_fheuint() {
        let cks = {
            let config = ConfigBuilder::default()
                .use_dedicated_oprf_key(true)
                .enable_ciphertext_re_randomization(
                    ReRandomizationParameters::DerivedCPKWithoutKeySwitch,
                )
                .build();

            let cks = ClientKey::generate(config);
            let sks = ServerKey::new(&cks);

            set_server_key(sks);

            cks
        };
        let mut rng = rand::thread_rng();
        let mut clear_values: Vec<u8> = (0..15).map(|_| rng.gen()).collect();

        let encrypted: Vec<FheUint8> = clear_values
            .iter()
            .map(|&v| FheUint8::try_encrypt(v, &cks).unwrap())
            .collect();

        let seed = new_seeder().seed();
        println!("seed: {seed:?}");
        let key_size = BitonicShuffleKeySize::num_bits(32);
        let shuffled = bitonic_shuffle(encrypted.clone(), key_size, seed).unwrap();
        let shuffled_rerand = {
            let mut shuffled_rerand = vec![];

            for algo in [
                ReRandomizationHashAlgo::Blake3,
                ReRandomizationHashAlgo::Shake256,
            ] {
                shuffled_rerand.push(
                    re_randomized_keys_bitonic_shuffle(
                        encrypted.clone(),
                        key_size,
                        seed,
                        ReRandomizationMode::UseAvailableMode,
                        algo,
                    )
                    .unwrap(),
                );
            }

            shuffled_rerand
        };

        let decrypted_ref: Vec<u8> = shuffled.iter().map(|ct| ct.decrypt(&cks)).collect();

        clear_values.sort_unstable();
        let decrypted_sorted = {
            let mut tmp = decrypted_ref.clone();
            tmp.sort_unstable();
            tmp
        };

        assert_eq!(decrypted_sorted, clear_values);

        for (idx, rerand_result) in shuffled_rerand.into_iter().enumerate() {
            let decrypted_rerand: Vec<u8> =
                rerand_result.iter().map(|ct| ct.decrypt(&cks)).collect();

            assert_eq!(
                decrypted_ref, decrypted_rerand,
                "failed at index {idx} of decrypted_rerand"
            );
        }
    }

    #[test]
    fn test_bitonic_shuffle_fheint() {
        let cks = {
            let config = ConfigBuilder::default()
                .use_dedicated_oprf_key(true)
                .enable_ciphertext_re_randomization(
                    ReRandomizationParameters::DerivedCPKWithoutKeySwitch,
                )
                .build();

            let cks = ClientKey::generate(config);
            let sks = ServerKey::new(&cks);

            set_server_key(sks);

            cks
        };

        let mut rng = rand::thread_rng();
        let mut clear_values: Vec<i8> = (0..15).map(|_| rng.gen()).collect();

        let encrypted: Vec<FheInt8> = clear_values
            .iter()
            .map(|&v| FheInt8::try_encrypt(v, &cks).unwrap())
            .collect();

        let seed = new_seeder().seed();
        println!("seed: {seed:?}");
        let key_size = BitonicShuffleKeySize::num_bits(32);
        let shuffled = bitonic_shuffle(encrypted.clone(), key_size, seed).unwrap();
        let shuffled_rerand = {
            let mut shuffled_rerand = vec![];

            for algo in [
                ReRandomizationHashAlgo::Blake3,
                ReRandomizationHashAlgo::Shake256,
            ] {
                shuffled_rerand.push(
                    re_randomized_keys_bitonic_shuffle(
                        encrypted.clone(),
                        key_size,
                        seed,
                        ReRandomizationMode::UseAvailableMode,
                        algo,
                    )
                    .unwrap(),
                );
            }

            shuffled_rerand
        };

        let decrypted_ref: Vec<i8> = shuffled.iter().map(|ct| ct.decrypt(&cks)).collect();

        clear_values.sort_unstable();
        let decrypted_sorted = {
            let mut tmp = decrypted_ref.clone();
            tmp.sort_unstable();
            tmp
        };

        assert_eq!(decrypted_sorted, clear_values);

        for (idx, rerand_result) in shuffled_rerand.into_iter().enumerate() {
            let decrypted_rerand: Vec<i8> =
                rerand_result.iter().map(|ct| ct.decrypt(&cks)).collect();

            assert_eq!(
                decrypted_ref, decrypted_rerand,
                "failed at index {idx} of decrypted_rerand"
            );
        }
    }

    #[test]
    fn test_bitonic_shuffle_collision_probability() {
        let cks = setup_default_cpu();
        let mut rng = rand::thread_rng();
        let mut clear_values: Vec<u8> = (0..15).map(|_| rng.gen()).collect();

        let encrypted: Vec<FheUint8> = clear_values
            .iter()
            .map(|&v| FheUint8::try_encrypt(v, &cks).unwrap())
            .collect();

        let seed = new_seeder().seed();
        println!("seed: {seed:?}");
        // For n = 15, ceil(log2(15^2 / (2 * 4e-8))) = 32 bits of key.
        let key_size = BitonicShuffleKeySize::collision_probability(4e-8);
        let shuffled = bitonic_shuffle(encrypted, key_size, seed).unwrap();

        let mut decrypted: Vec<u8> = shuffled.iter().map(|ct| ct.decrypt(&cks)).collect();

        clear_values.sort_unstable();
        decrypted.sort_unstable();
        assert_eq!(decrypted, clear_values);
    }
}
