use serde::Serialize;
use std::fs::{File, create_dir_all, read_dir, remove_dir_all, remove_file};
use std::path::{Path, PathBuf};

use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::core_crypto::commons::math::random::Seed;
use tfhe::core_crypto::prelude::*;
use tfhe_csprng::generators::SoftwareRandomGenerator;

// If you modify the content of these parameters, don't forget to also update `data/README.md`
const RAND_SEED: u128 = 0x74666865;

const MSG_A: u64 = 4;
const MSG_B: u64 = 3;

const VALID_LWE_DIMENSION: LweDimension = LweDimension(833);
const VALID_GLWE_DIMENSION: GlweDimension = GlweDimension(1);
const VALID_POLYNOMIAL_SIZE: PolynomialSize = PolynomialSize(2048);
const VALID_GAUSSIAN_LWE_NOISE_STDDEV: f64 = 3.6158408373309336e-06;
const VALID_GAUSSIAN_GLWE_NOISE_STDDEV: f64 = 2.845267479601915e-15;
const VALID_PBS_DECOMPOSITION_BASE_LOG: DecompositionBaseLog = DecompositionBaseLog(23);
const VALID_PBS_DECOMPOSITION_LEVEL_COUNT: DecompositionLevelCount = DecompositionLevelCount(1);
const VALID_KS_DECOMPOSITION_BASE_LOG: DecompositionBaseLog = DecompositionBaseLog(3);
const VALID_KS_DECOMPOSITION_LEVEL_COUNT: DecompositionLevelCount = DecompositionLevelCount(5);

const TOY_LWE_DIMENSION: LweDimension = LweDimension(10);
const TOY_GLWE_DIMENSION: GlweDimension = GlweDimension(1);
const TOY_POLYNOMIAL_SIZE: PolynomialSize = PolynomialSize(256);
const TOY_GAUSSIAN_LWE_NOISE_STDDEV: f64 = 0.;
const TOY_GAUSSIAN_GLWE_NOISE_STDDEV: f64 = 0.;
const TOY_PBS_DECOMPOSITION_BASE_LOG: DecompositionBaseLog = DecompositionBaseLog(24);
const TOY_PBS_DECOMPOSITION_LEVEL_COUNT: DecompositionLevelCount = DecompositionLevelCount(1);
const TOY_KS_DECOMPOSITION_BASE_LOG: DecompositionBaseLog = DecompositionBaseLog(37);
const TOY_KS_DECOMPOSITION_LEVEL_COUNT: DecompositionLevelCount = DecompositionLevelCount(1);

const ENCODING: Encoding = Encoding {
    ciphertext_modulus: CiphertextModulus::new_native(),
    msg_bits: 4,
};

const SPEC_LUT: fn(u64) -> u64 = |x| (x * 2) & (1u64 << ENCODING.msg_bits);
const ID_LUT: fn(u64) -> u64 = |x| x;

const DATA_DIR: &str = "./data";

struct Encoding {
    ciphertext_modulus: CiphertextModulus<u64>,
    msg_bits: usize,
}

impl Encoding {
    fn log_delta(&self) -> usize {
        self.ciphertext_modulus.into_modulus_log().0 - self.msg_bits - 1
    }

    const fn msg_modulus(&self) -> usize {
        1 << self.msg_bits
    }

    fn encode(&self, msg: u64) -> Plaintext<u64> {
        Plaintext(msg << self.log_delta())
    }

    fn decode(&self, plaintext: Plaintext<u64>) -> u64 {
        let decomposer = SignedDecomposer::new(
            DecompositionBaseLog(self.msg_bits + 1),
            DecompositionLevelCount(1),
        );
        let decoded = decomposer.decode_plaintext(plaintext);

        decoded.0
    }

    fn encode_lut(
        &self,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        f: impl Fn(u64) -> u64,
    ) -> GlweCiphertext<Vec<u64>> {
        generate_programmable_bootstrap_glwe_lut(
            polynomial_size,
            glwe_dimension.to_glwe_size(),
            self.msg_modulus(),
            self.ciphertext_modulus,
            1 << self.log_delta(),
            f,
        )
    }
}

fn modswitched_to_lwe(
    modswitched: &LazyStandardModulusSwitchedLweCiphertext<u64, usize, Vec<u64>>,
) -> LweCiphertextOwned<usize> {
    let cont = modswitched
        .mask()
        .chain(std::iter::once(modswitched.body()))
        // The coefficients are converted to use the power of two encoding
        .map(|coeff| coeff << (usize::BITS as usize - modswitched.log_modulus().0))
        .collect();

    LweCiphertext::from_container(
        cont,
        CiphertextModulus::new(1 << modswitched.log_modulus().0),
    )
}

fn store_data<Data: Serialize, P: AsRef<Path>>(path: P, data: &Data, name: &str) {
    let mut path = path.as_ref().to_path_buf();
    path.push(format!("{}.cbor", name));

    let mut file = File::create(path).unwrap();
    ciborium::ser::into_writer(data, &mut file).unwrap();
}

#[allow(clippy::too_many_arguments)]
fn generate_test_vectors<P: AsRef<Path>>(
    path: P,
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    lwe_noise_stddev: f64,
    glwe_noise_stddev: f64,
    pbs_decomp_base_log: DecompositionBaseLog,
    pbs_decomp_level_count: DecompositionLevelCount,
    ks_decomp_base_log: DecompositionBaseLog,
    ks_decomp_level_count: DecompositionLevelCount,
    encoding: Encoding,
) {
    let path = path.as_ref();
    create_dir_all(path).unwrap();

    let mut secret_generator =
        SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(RAND_SEED));
    let mut encryption_generator = EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(
        Seed(RAND_SEED),
        &mut DeterministicSeeder::<SoftwareRandomGenerator>::new(Seed(RAND_SEED)),
    );

    let glwe_secret_key: GlweSecretKey<Vec<u64>> =
        GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let large_lwe_secret_key = glwe_secret_key.as_lwe_secret_key();
    store_data(path, &large_lwe_secret_key, "large_lwe_secret_key");

    let small_lwe_secret_key: LweSecretKey<Vec<u64>> =
        LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_generator);
    store_data(path, &small_lwe_secret_key, "small_lwe_secret_key");

    let lwe_noise_distribution = Gaussian::from_standard_dev(StandardDev(lwe_noise_stddev), 0.);
    let glwe_noise_distribution = Gaussian::from_standard_dev(StandardDev(glwe_noise_stddev), 0.);

    let plaintext_a = encoding.encode(MSG_A);
    let lwe_a = allocate_and_encrypt_new_lwe_ciphertext(
        &large_lwe_secret_key,
        plaintext_a,
        glwe_noise_distribution,
        encoding.ciphertext_modulus,
        &mut encryption_generator,
    );
    store_data(path, &lwe_a, "lwe_a");

    let plaintext_b = encoding.encode(MSG_B);
    let lwe_b = allocate_and_encrypt_new_lwe_ciphertext(
        &large_lwe_secret_key,
        plaintext_b,
        glwe_noise_distribution,
        encoding.ciphertext_modulus,
        &mut encryption_generator,
    );
    store_data(path, &lwe_b, "lwe_b");

    let mut lwe_sum = LweCiphertext::new(
        0u64,
        glwe_dimension
            .to_equivalent_lwe_dimension(polynomial_size)
            .to_lwe_size(),
        encoding.ciphertext_modulus,
    );
    lwe_ciphertext_add(&mut lwe_sum, &lwe_a, &lwe_b);
    let decrypted_sum = decrypt_lwe_ciphertext(&large_lwe_secret_key, &lwe_sum);
    let res = encoding.decode(decrypted_sum);

    assert_eq!(res, MSG_A + MSG_B);
    store_data(path, &lwe_sum, "lwe_sum");

    let mut lwe_prod = LweCiphertext::new(
        0u64,
        glwe_dimension
            .to_equivalent_lwe_dimension(polynomial_size)
            .to_lwe_size(),
        encoding.ciphertext_modulus,
    );
    lwe_ciphertext_cleartext_mul(&mut lwe_prod, &lwe_a, Cleartext(MSG_B));
    let decrypted_prod = decrypt_lwe_ciphertext(&large_lwe_secret_key, &lwe_prod);
    let res = encoding.decode(decrypted_prod);

    assert_eq!(res, MSG_A * MSG_B);
    store_data(path, &lwe_prod, "lwe_prod");

    let ksk = allocate_and_generate_new_lwe_keyswitch_key(
        &large_lwe_secret_key,
        &small_lwe_secret_key,
        ks_decomp_base_log,
        ks_decomp_level_count,
        lwe_noise_distribution,
        encoding.ciphertext_modulus,
        &mut encryption_generator,
    );
    store_data(path, &ksk, "ksk");

    let mut lwe_ks = LweCiphertext::new(
        0u64,
        lwe_dimension.to_lwe_size(),
        encoding.ciphertext_modulus,
    );
    keyswitch_lwe_ciphertext(&ksk, &lwe_a, &mut lwe_ks);

    let decrypted_ks = decrypt_lwe_ciphertext(&small_lwe_secret_key, &lwe_ks);
    let res = encoding.decode(decrypted_ks);

    assert_eq!(res, MSG_A);
    store_data(path, &lwe_ks, "lwe_ks");

    let bsk = par_allocate_and_generate_new_lwe_bootstrap_key(
        &small_lwe_secret_key,
        &glwe_secret_key,
        pbs_decomp_base_log,
        pbs_decomp_level_count,
        glwe_noise_distribution,
        encoding.ciphertext_modulus,
        &mut encryption_generator,
    );
    store_data(path, &bsk, "bsk");

    let mut fourier_bsk = FourierLweBootstrapKey::new(
        bsk.input_lwe_dimension(),
        bsk.glwe_size(),
        bsk.polynomial_size(),
        bsk.decomposition_base_log(),
        bsk.decomposition_level_count(),
    );
    par_convert_standard_lwe_bootstrap_key_to_fourier(&bsk, &mut fourier_bsk);

    let lwe_in_ms =
        LweCiphertext::from_container(lwe_ks.as_ref().to_vec(), lwe_ks.ciphertext_modulus());
    let log_modulus = polynomial_size.to_blind_rotation_input_modulus_log();

    let modswitched = lwe_ciphertext_modulus_switch(lwe_in_ms, log_modulus);
    let lwe_ms = modswitched_to_lwe(&modswitched);
    store_data(path, &lwe_ms, "lwe_ms");

    let mut id_lut = encoding.encode_lut(glwe_dimension, polynomial_size, ID_LUT);

    blind_rotate_assign(&modswitched, &mut id_lut, &fourier_bsk);
    store_data(path, &id_lut, "glwe_after_id_br");

    let mut lwe_pbs_id = LweCiphertext::new(
        0u64,
        glwe_dimension
            .to_equivalent_lwe_dimension(polynomial_size)
            .to_lwe_size(),
        encoding.ciphertext_modulus,
    );

    extract_lwe_sample_from_glwe_ciphertext(&id_lut, &mut lwe_pbs_id, MonomialDegree(0));

    let decrypted_pbs_id = decrypt_lwe_ciphertext(&large_lwe_secret_key, &lwe_pbs_id);
    let res = encoding.decode(decrypted_pbs_id);

    assert_eq!(res, MSG_A);
    store_data(path, &lwe_pbs_id, "lwe_after_id_pbs");

    let mut spec_lut = encoding.encode_lut(glwe_dimension, polynomial_size, SPEC_LUT);

    blind_rotate_assign(&modswitched, &mut spec_lut, &fourier_bsk);
    store_data(path, &spec_lut, "glwe_after_spec_br");

    let mut lwe_pbs_spec = LweCiphertext::new(
        0u64,
        glwe_dimension
            .to_equivalent_lwe_dimension(polynomial_size)
            .to_lwe_size(),
        encoding.ciphertext_modulus,
    );

    extract_lwe_sample_from_glwe_ciphertext(&spec_lut, &mut lwe_pbs_spec, MonomialDegree(0));

    let decrypted_pbs_spec = decrypt_lwe_ciphertext(&large_lwe_secret_key, &lwe_pbs_spec);
    let res = encoding.decode(decrypted_pbs_spec);

    assert_eq!(res, SPEC_LUT(MSG_A));
    store_data(path, &lwe_pbs_spec, "lwe_after_spec_pbs");
}

fn rm_dir_except_readme<P: AsRef<Path>>(dir: P) {
    let dir = dir.as_ref();

    for entry_result in read_dir(dir).unwrap() {
        let entry = entry_result.unwrap();
        let path = entry.path();

        // Skip the README.md file at the root.
        if entry.file_name() == "README.md" {
            continue;
        }

        if path.is_dir() {
            remove_dir_all(&path).unwrap();
        } else {
            remove_file(&path).unwrap();
        }
    }
}

fn main() {
    rm_dir_except_readme(DATA_DIR);

    generate_test_vectors(
        PathBuf::from(DATA_DIR).join("valid_params_128"),
        VALID_LWE_DIMENSION,
        VALID_GLWE_DIMENSION,
        VALID_POLYNOMIAL_SIZE,
        VALID_GAUSSIAN_LWE_NOISE_STDDEV,
        VALID_GAUSSIAN_GLWE_NOISE_STDDEV,
        VALID_PBS_DECOMPOSITION_BASE_LOG,
        VALID_PBS_DECOMPOSITION_LEVEL_COUNT,
        VALID_KS_DECOMPOSITION_BASE_LOG,
        VALID_KS_DECOMPOSITION_LEVEL_COUNT,
        ENCODING,
    );

    generate_test_vectors(
        PathBuf::from(DATA_DIR).join("toy_params"),
        TOY_LWE_DIMENSION,
        TOY_GLWE_DIMENSION,
        TOY_POLYNOMIAL_SIZE,
        TOY_GAUSSIAN_LWE_NOISE_STDDEV,
        TOY_GAUSSIAN_GLWE_NOISE_STDDEV,
        TOY_PBS_DECOMPOSITION_BASE_LOG,
        TOY_PBS_DECOMPOSITION_LEVEL_COUNT,
        TOY_KS_DECOMPOSITION_BASE_LOG,
        TOY_KS_DECOMPOSITION_LEVEL_COUNT,
        ENCODING,
    );
}
