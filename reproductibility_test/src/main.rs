use rayon::prelude::*;
use sha2::{Digest, Sha256};
use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::core_crypto::commons::math::random::Seed;
use tfhe::core_crypto::prelude::DefaultRandomGenerator;
use tfhe::shortint::engine::ShortintEngine;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
use tfhe::shortint::server_key::{generate_lookup_table, LookupTableOwned, LookupTableSize};
use tfhe::shortint::{gen_keys, ClientKey, ServerKey, ShortintParameterSet};

fn hash_vec_u8(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn hash_for_keyset(
    num_ct: usize,
    seed: Seed,
    cks: &ClientKey,
    sks: &ServerKey,
    lut: &LookupTableOwned,
) -> Vec<u8> {
    let mut seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);

    let shortint_engine = ShortintEngine::new_from_seeder(&mut seeder);
    ShortintEngine::with_thread_local_mut(|local_engine| {
        let _ = std::mem::replace(local_engine, shortint_engine);
    });

    let msg = 0;

    let inputs: Vec<_> = (0..num_ct).map(|_| cks.encrypt(msg)).collect();

    let hashes: Vec<_> = inputs
        .par_iter()
        .map(|ct| {
            let ct_res = sks.apply_lookup_table(ct, lut);

            let res = bincode::serialize(&ct_res).unwrap();

            hash_vec_u8(&res)
        })
        .collect();

    let hashes_concatenated: Vec<u8> = hashes.iter().flatten().copied().collect();

    hash_vec_u8(&hashes_concatenated)
}

fn full_hash(params: ShortintParameterSet, num_keyset: usize, num_ct_per_keyset: usize) -> Vec<u8> {
    let modulus = params.message_modulus().0;

    let lut = generate_lookup_table(
        LookupTableSize::new(
            params.glwe_dimension().to_glwe_size(),
            params.polynomial_size(),
        ),
        params.ciphertext_modulus(),
        params.message_modulus(),
        params.carry_modulus(),
        |x| x % modulus,
    );

    let mut hashes_concatenated = vec![];

    for i in 0..num_keyset {
        let mut seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(Seed(i as u128));

        let shortint_engine = ShortintEngine::new_from_seeder(&mut seeder);
        ShortintEngine::with_thread_local_mut(|local_engine| {
            let _ = std::mem::replace(local_engine, shortint_engine);
        });

        let (cks, sks) = gen_keys(params);

        hashes_concatenated.extend_from_slice(&hash_for_keyset(
            num_ct_per_keyset,
            Seed(i as u128),
            &cks,
            &sks,
            &lut,
        ));

        println!("Done {}/{num_keyset}", i + 1);
    }

    hash_vec_u8(&hashes_concatenated)
}

fn main() {
    let full_hash = full_hash(PARAM_MESSAGE_2_CARRY_2_KS_PBS.into(), 60, 30_000);

    println!("{:?}", &full_hash);
}
