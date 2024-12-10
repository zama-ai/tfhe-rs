#[test]
fn test_replacing_thread_local_engine() {
    use crate::boolean::engine::BooleanEngine;
    use crate::core_crypto::commons::generators::DeterministicSeeder;
    use crate::core_crypto::commons::math::random::Seed;
    use crate::core_crypto::prelude::ActivatedRandomGenerator;

    let deterministic_seed = Seed(0);

    // We change the engine in the main thread
    // then generate a client key, and then encrypt
    // a boolean value and serialize it to compare
    // it with other ciphertext
    let mut seeder = DeterministicSeeder::<ActivatedRandomGenerator>::new(deterministic_seed);
    let boolean_engine = BooleanEngine::new_from_seeder(&mut seeder);
    BooleanEngine::replace_thread_local(boolean_engine);

    let (cks, _) = crate::boolean::gen_keys();
    let ct = cks.encrypt(false);
    let main_thread_data = bincode::serialize(&ct).unwrap();

    // In this thread, we don't change the engine
    // and so we expect the encrypted value to be
    // different compared with the one from the main thread
    //
    // This also "proves" that a thread is not affected
    // by engine changes from other thread as engines are
    // thread_local
    let second_thread_data = std::thread::spawn(|| {
        let (cks, _) = crate::boolean::gen_keys();
        let ct = cks.encrypt(false);
        bincode::serialize(&ct).unwrap()
    })
    .join()
    .unwrap();
    assert_ne!(second_thread_data, main_thread_data);

    // In this thread, we change the engine,
    // with a new engine that has the same seed
    // as the one in the main thread
    // So we expect the encrypted value to be the same
    // compared with the one from the main thread
    let third_thread_data = std::thread::spawn(move || {
        let mut seeder = DeterministicSeeder::<ActivatedRandomGenerator>::new(deterministic_seed);
        let boolean_engine = BooleanEngine::new_from_seeder(&mut seeder);
        BooleanEngine::replace_thread_local(boolean_engine);
        let (cks, _) = crate::boolean::gen_keys();
        let ct = cks.encrypt(false);
        bincode::serialize(&ct).unwrap()
    })
    .join()
    .unwrap();
    assert_eq!(third_thread_data, main_thread_data);
}
