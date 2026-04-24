use crate::high_level_api::global_state;
use crate::high_level_api::integers::FheIntegerType;
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::re_randomization::ReRandomizationMetadata;
use crate::integer::server_key::radix_parallel::bitonic_shuffle::BitonicShuffleKeySize;
use tfhe_csprng::seeders::Seeder;

/// Shuffles `data` into a uniformly random permutation using a bitonic
/// sorting network with OPRF-generated random keys.
///
/// `key_size` controls the bit-width of the random sort keys used internally,
/// either by specifying a target collision probability or by passing a raw
/// block count. Larger keys reduce collision probability (improving shuffle
/// uniformity) at the cost of more computation per comparison.
///
/// The re-randomization metadata of the input elements is not preserved
/// through the shuffle.
///
/// # Errors
///
/// Returns an error if the resolved key block count is 0, or if the Cuda/Hpu
/// backend is active (not yet supported).
pub fn bitonic_shuffle<T, S>(
    data: Vec<T>,
    key_size: BitonicShuffleKeySize,
    seeder: &mut S,
) -> Result<Vec<T>, crate::Error>
where
    T: FheIntegerType,
    S: Seeder,
{
    global_state::with_internal_keys(|key| match key {
        InternalServerKey::Cpu(cpu_key) => {
            let inner = data.into_iter().map(|v| v.into_cpu()).collect();
            let result =
                cpu_key
                    .pbs_key()
                    .bitonic_shuffle(&cpu_key.oprf_key(), inner, key_size, seeder)?;
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
    use super::{bitonic_shuffle, BitonicShuffleKeySize};
    use crate::core_crypto::commons::generators::DeterministicSeeder;
    use crate::core_crypto::prelude::new_seeder;
    use crate::high_level_api::prelude::*;
    use crate::high_level_api::tests::setup_default_cpu;
    use crate::{FheInt8, FheUint8};
    use rand::Rng;
    use tfhe_csprng::generators::DefaultRandomGenerator;

    #[test]
    fn test_bitonic_shuffle_fheuint() {
        let cks = setup_default_cpu();
        let mut rng = rand::thread_rng();
        let mut clear_values: Vec<u8> = (0..15).map(|_| rng.gen()).collect();

        let encrypted: Vec<FheUint8> = clear_values
            .iter()
            .map(|&v| FheUint8::try_encrypt(v, &cks).unwrap())
            .collect();

        let seed = new_seeder().seed();
        println!("seed: {seed:?}");
        let mut seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);
        let shuffled = bitonic_shuffle(
            encrypted,
            BitonicShuffleKeySize::num_blocks(16),
            &mut seeder,
        )
        .unwrap();

        let mut decrypted: Vec<u8> = shuffled.iter().map(|ct| ct.decrypt(&cks)).collect();

        clear_values.sort_unstable();
        decrypted.sort_unstable();
        assert_eq!(decrypted, clear_values);
    }

    #[test]
    fn test_bitonic_shuffle_fheint() {
        let cks = setup_default_cpu();
        let mut rng = rand::thread_rng();
        let mut clear_values: Vec<i8> = (0..15).map(|_| rng.gen()).collect();

        let encrypted: Vec<FheInt8> = clear_values
            .iter()
            .map(|&v| FheInt8::try_encrypt(v, &cks).unwrap())
            .collect();

        let seed = new_seeder().seed();
        println!("seed: {seed:?}");
        let mut seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);
        let shuffled = bitonic_shuffle(
            encrypted,
            BitonicShuffleKeySize::num_blocks(16),
            &mut seeder,
        )
        .unwrap();

        let mut decrypted: Vec<i8> = shuffled.iter().map(|ct| ct.decrypt(&cks)).collect();

        clear_values.sort_unstable();
        decrypted.sort_unstable();
        assert_eq!(decrypted, clear_values);
    }
}
