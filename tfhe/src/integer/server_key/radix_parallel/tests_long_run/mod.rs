use rand::Rng;
use tfhe_csprng::generators::DefaultRandomGenerator;
use tfhe_csprng::seeders::Seed;
use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::integer::RadixClientKey;
use crate::integer::{RadixCiphertext, SignedRadixCiphertext};
use crate::integer::block_decomposition::DecomposableInto;
use tfhe_csprng::seeders::Seeder;

pub(crate) mod test_erc20;
pub(crate) mod test_random_op_sequence;
pub(crate) mod test_signed_erc20;
pub(crate) mod test_signed_random_op_sequence;
pub(crate) const NB_CTXT_LONG_RUN: usize = 32;
pub(crate) const NB_TESTS_LONG_RUN: usize = 20000;
pub(crate) const NB_TESTS_LONG_RUN_MINIMAL: usize = 200;

pub(crate) fn get_long_test_iterations() -> usize {
    static SINGLE_KEY_DEBUG: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

    let is_long_tests_minimal = *SINGLE_KEY_DEBUG.get_or_init(|| {
        std::env::var("TFHE_RS_TESTS_LONG_TESTS_MINIMAL")
            .is_ok_and(|val| val.to_uppercase() == "TRUE")
    });

    if is_long_tests_minimal {
        NB_TESTS_LONG_RUN_MINIMAL
    } else {
        NB_TESTS_LONG_RUN
    }
}


pub(crate) struct TestDataSample<P, C> {
    pub(crate) clear_value: P,
    pub(crate) encrypted_value: C,
    pub(crate) producer: String,
}

pub trait RadixEncryptable {
    type Output;

    fn encrypt(&self, key: &RadixClientKey) -> Self::Output;
}

impl RadixEncryptable for u64 {
    type Output = RadixCiphertext;


    fn encrypt(&self, key: &RadixClientKey) -> Self::Output {
        key.encrypt(*self)
    }
}

impl RadixEncryptable for i64 {
    type Output = SignedRadixCiphertext;


    fn encrypt(&self, key: &RadixClientKey) -> Self::Output {
        key.encrypt_signed(*self)
    }
}

/*impl EncryptSample for bool {
    fn encrypt(&self, cks: &RadixClientKey) -> RadixCiphertext {
        cks.encrypt_bool(*self)
    }
}*/

struct RandomOpSequenceDataGenerator<P, C> {
    pub(crate) clear_left_vec: Vec<TestDataSample<P, C>>,
    pub(crate) clear_right_vec: Vec<TestDataSample<P, C>>,
    deterministic_seeder: DeterministicSeeder::<DefaultRandomGenerator>,
    seed: Seed,
    cks: RadixClientKey,
}

impl<P:RadixEncryptable<Output = C> + DecomposableInto<u64> + From<u128>, C> RandomOpSequenceDataGenerator<P, C> {
    fn new(total_num_ops: usize, cks: &RadixClientKey) -> Self {
        let mut rng = rand::thread_rng();

        let seed: u128 = rng.gen();
        Self::new_with_seed(total_num_ops, Seed(seed), cks)
    }

    fn make_data_sample_vector(deterministic_seeder: &mut DeterministicSeeder<DefaultRandomGenerator>, total_num_ops: usize, cks: &RadixClientKey) -> Vec<TestDataSample<P, C>> {
        (0..total_num_ops)
            .map(|_| {
                let plain = P::from(deterministic_seeder.seed().0);
                let cipher: C = plain.encrypt(&cks);
                TestDataSample {
                    clear_value: plain,
                    encrypted_value: cipher,
                    producer: "encrypt".to_string(),
                }
            }) // Generate random i64 values and encrypt them
            .collect()
    }
    fn new_with_seed(total_num_ops: usize, seed: Seed, cks: &RadixClientKey) -> Self {
        let mut deterministic_seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);

        RandomOpSequenceDataGenerator {
            clear_left_vec: Self::make_data_sample_vector(&mut deterministic_seeder, total_num_ops, cks),
            clear_right_vec: Self::make_data_sample_vector(&mut deterministic_seeder, total_num_ops, cks),
            deterministic_seeder,
            seed,
            cks: RadixClientKey::from(cks.clone())
        }
    }

}

