use serde::Serialize;
use std::fs::{self, File, read_dir, remove_file};
use std::path::{Path, PathBuf};
use std::error::Error;
use std::fmt;

use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::core_crypto::commons::math::random::Seed;
use tfhe::core_crypto::prelude::*;
use tfhe_csprng::generators::SoftwareRandomGenerator;

// --- CONSTANTS AND PARAMETERS (SCREAMING_SNAKE_CASE) ---
// If you modify the content of these parameters, don't forget to also update `data/README.md`
const RAND_SEED: u128 = 0x74666865;

const MSG_A: u64 = 4;
const MSG_B: u64 = 3;

// Valid (secure) parameters
const VALID_LWE_DIMENSION: LweDimension = LweDimension(833);
const VALID_GLWE_DIMENSION: GlweDimension = GlweDimension(1);
const VALID_POLYNOMIAL_SIZE: PolynomialSize = PolynomialSize(2048);
const VALID_GAUSSIAN_LWE_NOISE_STDDEV: f64 = 3.6158408373309336e-06;
const VALID_GAUSSIAN_GLWE_NOISE_STDDEV: f64 = 2.845267479601915e-15;
const VALID_PBS_DECOMPOSITION_BASE_LOG: DecompositionBaseLog = DecompositionBaseLog(23);
const VALID_PBS_DECOMPOSITION_LEVEL_COUNT: DecompositionLevelCount = DecompositionLevelCount(1);
const VALID_KS_DECOMPOSITION_BASE_LOG: DecompositionBaseLog = DecompositionBaseLog(3);
const VALID_KS_DECOMPOSITION_LEVEL_COUNT: DecompositionLevelCount = DecompositionLevelCount(5);

// Toy (insecure, fast) parameters for testing
const TOY_LWE_DIMENSION: LweDimension = LweDimension(10);
const TOY_GLWE_DIMENSION: GlweDimension = GlweDimension(1);
const TOY_POLYNOMIAL_SIZE: PolynomialSize = PolynomialSize(256);
const TOY_GAUSSIAN_LWE_NOISE_STDDEV: f64 = 0.;
const TOY_GAUSSIAN_GLWE_NOISE_STDDEV: f64 = 0.;
const TOY_PBS_DECOMPOSITION_BASE_LOG: DecompositionBaseLog = DecompositionBaseLog(24);
const TOY_PBS_DECOMPOSITION_LEVEL_COUNT: DecompositionLevelCount = DecompositionLevelCount(1);
const TOY_KS_DECOMPOSITION_BASE_LOG: DecompositionBaseLog = DecompositionBaseLog(37);
const TOY_KS_DECOMPOSITION_LEVEL_COUNT: DecompositionLevelCount = DecompositionLevelCount(1);

// Encoding definition
const ENCODING: Encoding = Encoding {
    ciphertext_modulus: CiphertextModulus::new_native(),
    msg_bits: 4,
};

// Look-Up Table (LUT) functions
// Example function: x -> (x * 2) & 0b1111 (for 4 message bits)
const SPEC_LUT: fn(u64) -> u64 = |x| (x * 2) & (1u64 << ENCODING.msg_bits).checked_sub(1).unwrap_or(0);
// Identity function: x -> x
const ID_LUT: fn(u64) -> u64 = |x| x;

const DATA_DIR: &str = "./data";

/// Custom error type for file and serialization operations.
#[derive(Debug)]
enum TestVectorError {
    Io(std::io::Error),
    Serialization(ciborium::ser::Error<std::io::Error>),
}

impl fmt::Display for TestVectorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TestVectorError::Io(err) => write!(f, "IO error: {}", err),
            TestVectorError::Serialization(err) => write!(f, "Serialization error: {}", err),
        }
    }
}

impl Error for TestVectorError {}

impl From<std::io::Error> for TestVectorError {
    fn from(err: std::io::Error) -> Self {
        TestVectorError::Io(err)
    }
}

impl From<ciborium::ser::Error<std::io::Error>> for TestVectorError {
    fn from(err: ciborium::ser::Error<std::io::Error>) -> Self {
        TestVectorError::Serialization(err)
    }
}

/// Defines the encoding properties for the homomorphic encryption scheme.
struct Encoding {
    ciphertext_modulus: CiphertextModulus<u64>,
    msg_bits: usize,
}

impl Encoding {
    /// Calculates the number of bits used for padding between message and modulus.
    fn log_delta(&self) -> usize {
        self.ciphertext_modulus.into_modulus_log().0 - self.msg_bits - 1
    }

    /// Calculates the modulus of the message space (e.g., 2^msg_bits).
    const fn msg_modulus(&self) -> usize {
        1 << self.msg_bits
    }

    /// Encodes a message into a plaintext value suitable for encryption.
    /// The message is shifted left by `log_delta` to occupy the most significant bits.
    fn encode(&self, msg: u64) -> Plaintext<u64> {
        Plaintext(msg << self.log_delta())
    }

    /// Decodes a plaintext back into the original message by using a signed decomposer
    /// to extract the most significant bits.
    fn decode(&self, plaintext: Plaintext<u64>) -> u64 {
        let decomposer = SignedDecomposer::new(
            // Use msg_bits + 1 to account for the most significant bit being the message
            DecompositionBaseLog(self.msg_bits + 1),
            DecompositionLevelCount(1),
        );
        let decoded = decomposer.decode_plaintext(plaintext);

        decoded.0
    }

    /// Generates a Look-Up Table (LUT) as a GLWE Ciphertext, where the
    /// polynomial coefficients encode the function 'f'.
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

/// Converts a modulus-switched LWE ciphertext (represented lazily in u64)
/// to a standard LWE ciphertext (in u64) using the power-of-two encoding.
/// **NOTE:** The container type is kept as u64 for consistency with the rest of the code.
fn modswitched_to_lwe(
    modswitched: &LazyStandardModulusSwitchedLweCiphertext<u64, u64, Vec<u64>>,
) -> LweCiphertextOwned<u64> {
    let log_modulus = modswitched.log_modulus().0;
    let shift = u64::BITS as usize - log_modulus;

    let cont: Vec<u64> = modswitched
        .mask()
        .chain(std::iter::once(modswitched.body()))
        // The coefficients are converted to use the power of two encoding (shifted left)
        .map(|coeff| coeff << shift)
        .collect();

    LweCiphertext::from_container(
        cont,
        CiphertextModulus::new(1 << log_modulus),
    )
}

/// Serializes data to a CBOR file in the specified path.
fn store_data<Data: Serialize, P: AsRef<Path>>(
    path: P,
    data: &Data,
    name: &str,
) -> Result<(), TestVectorError> {
    let mut path = path.as_ref().to_path_buf();
    path.push(format!("{}.cbor", name));

    let mut file = File::create(path)?;
    ciborium::ser::into_writer(data, &mut file)?;
    Ok(())
}

/// Generates and stores the complete set of FHE test vectors (keys and ciphertexts).
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
) -> Result<(), TestVectorError> {
    let path = path.as_ref();
    fs::create_dir_all(path)?;

    // 1. Setup Generators
    let mut secret_generator =
        SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(RAND_SEED));
    let mut encryption_generator = EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(
        Seed(RAND_SEED),
        &mut DeterministicSeeder::<SoftwareRandomGenerator>::new(Seed(RAND_SEED)),
    );

    let lwe_noise_distribution = Gaussian::from_standard_dev(StandardDev(lwe_noise_stddev), 0.);
    let glwe_noise_distribution = Gaussian::from_standard_dev(StandardDev(glwe_noise_stddev), 0.);
    
    // Calculate equivalent LWE dimension for GLWE for DRY principle
    let large_lwe_size = glwe_dimension
        .to_equivalent_lwe_dimension(polynomial_size)
        .to_lwe_size();

    // 2. Key Generation
    let glwe_secret_key: GlweSecretKey<Vec<u64>> =
        GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let large_lwe_secret_key = glwe_secret_key.as_lwe_secret_key();
    store_data(path, &large_lwe_secret_key, "large_lwe_secret_key")?;

    let small_lwe_secret_key: LweSecretKey<Vec<u64>> =
        LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_generator);
    store_data(path, &small_lwe_secret_key, "small_lwe_secret_key")?;

    // 3. Simple Encryptions and Operations (Large LWE)
    let plaintext_a = encoding.encode(MSG_A);
    let lwe_a = allocate_and_encrypt_new_lwe_ciphertext(
        &large_lwe_secret_key,
        plaintext_a,
        glwe_noise_distribution, // Using GLWE noise distribution for the large LWE key
        encoding.ciphertext_modulus,
        &mut encryption_generator,
    );
    store_data(path, &lwe_a, "lwe_a")?;

    let plaintext_b = encoding.encode(MSG_B);
    let lwe_b = allocate_and_encrypt_new_lwe_ciphertext(
        &large_lwe_secret_key,
        plaintext_b,
        glwe_noise_distribution,
        encoding.ciphertext_modulus,
        &mut encryption_generator,
    );
    store_data(path, &lwe_b, "lwe_b")?;

    // LWE addition: lwe_sum = lwe_a + lwe_b
    let mut lwe_sum = LweCiphertext::new(
        0u64,
        large_lwe_size,
        encoding.ciphertext_modulus,
    );
    lwe_ciphertext_add(&mut lwe_sum, &lwe_a, &lwe_b);
    let decrypted_sum = decrypt_lwe_ciphertext(&large_lwe_secret_key, &lwe_sum);
    let res = encoding.decode(decrypted_sum);

    assert_eq!(res, MSG_A + MSG_B, "LWE addition test failed.");
    store_data(path, &lwe_sum, "lwe_sum")?;

    // LWE cleartext multiplication: lwe_prod = lwe_a * MSG_B
    let mut lwe_prod = LweCiphertext::new(
        0u64,
        large_lwe_size,
        encoding.ciphertext_modulus,
    );
    lwe_ciphertext_cleartext_mul(&mut lwe_prod, &lwe_a, Cleartext(MSG_B));
    let decrypted_prod = decrypt_lwe_ciphertext(&large_lwe_secret_key, &lwe_prod);
    let res = encoding.decode(decrypted_prod);

    assert_eq!(res, MSG_A * MSG_B, "LWE cleartext multiplication test failed.");
    store_data(path, &lwe_prod, "lwe_prod")?;

    // 4. Key Switching (KS)
    // Keyswitch key from large_lwe_secret_key to small_lwe_secret_key
    let ksk = allocate_and_generate_new_lwe_keyswitch_key(
        &large_lwe_secret_key,
        &small_lwe_secret_key,
        ks_decomp_base_log,
        ks_decomp_level_count,
        lwe_noise_distribution,
        encoding.ciphertext_modulus,
        &mut encryption_generator,
    );
    store_data(path, &ksk, "ksk")?;

    let mut lwe_ks = LweCiphertext::new(
        0u64,
        lwe_dimension.to_lwe_size(),
        encoding.ciphertext_modulus,
    );
    keyswitch_lwe_ciphertext(&ksk, &lwe_a, &mut lwe_ks);

    let decrypted_ks = decrypt_lwe_ciphertext(&small_lwe_secret_key, &lwe_ks);
    let res = encoding.decode(decrypted_ks);

    assert_eq!(res, MSG_A, "Key switching test failed.");
    store_data(path, &lwe_ks, "lwe_ks")?;

    // 5. Programmable Bootstrapping (PBS)
    // Bootstrap key from small_lwe_secret_key to glwe_secret_key
    let bsk = par_allocate_and_generate_new_lwe_bootstrap_key(
        &small_lwe_secret_key,
        &glwe_secret_key,
        pbs_decomp_base_log,
        pbs_decomp_level_count,
        glwe_noise_distribution,
        encoding.ciphertext_modulus,
        &mut encryption_generator,
    );
    store_data(path, &bsk, "bsk")?;

    // Convert BSK to Fourier domain for faster computation
    let mut fourier_bsk = FourierLweBootstrapKey::new(
        bsk.input_lwe_dimension(),
        bsk.glwe_size(),
        bsk.polynomial_size(),
        bsk.decomposition_base_log(),
        bsk.decomposition_level_count(),
    );
    par_convert_standard_lwe_bootstrap_key_to_fourier(&bsk, &mut fourier_bsk);

    // Modulus switch LWE sample (lwe_ks is on small_lwe_secret_key)
    let lwe_in_ms =
        LweCiphertext::from_container(lwe_ks.as_ref().to_vec(), lwe_ks.ciphertext_modulus());
    let log_modulus = polynomial_size.to_blind_rotation_input_modulus_log();

    // The modulus switching operation for Blind Rotation
    let modswitched: LazyStandardModulusSwitchedLweCiphertext<u64, u64, Vec<u64>> =
        lwe_ciphertext_modulus_switch(lwe_in_ms, log_modulus);
    let lwe_ms = modswitched_to_lwe(&modswitched);
    store_data(path, &lwe_ms, "lwe_ms")?;

    // --- PBS with Identity LUT ---
    let mut id_lut = encoding.encode_lut(glwe_dimension, polynomial_size, ID_LUT);

    // Blind Rotation (BR)
    blind_rotate_assign(&modswitched, &mut id_lut, &fourier_bsk);
    store_data(path, &id_lut, "glwe_after_id_br")?;

    // Extract one LWE sample from the resulting GLWE (to complete the PBS)
    let mut lwe_pbs_id = LweCiphertext::new(
        0u64,
        large_lwe_size,
        encoding.ciphertext_modulus,
    );

    extract_lwe_sample_from_glwe_ciphertext(&id_lut, &mut lwe_pbs_id, MonomialDegree(0));

    let decrypted_pbs_id = decrypt_lwe_ciphertext(&large_lwe_secret_key, &lwe_pbs_id);
    let res = encoding.decode(decrypted_pbs_id);

    assert_eq!(res, MSG_A, "Identity PBS test failed.");
    store_data(path, &lwe_pbs_id, "lwe_after_id_pbs")?;

    // --- PBS with Specific LUT (x -> 2x) ---
    let mut spec_lut = encoding.encode_lut(glwe_dimension, polynomial_size, SPEC_LUT);

    // Blind Rotation (BR)
    blind_rotate_assign(&modswitched, &mut spec_lut, &fourier_bsk);
    store_data(path, &spec_lut, "glwe_after_spec_br")?;

    // Extract one LWE sample from the resulting GLWE (to complete the PBS)
    let mut lwe_pbs_spec = LweCiphertext::new(
        0u64,
        large_lwe_size,
        encoding.ciphertext_modulus,
    );

    extract_lwe_sample_from_glwe_ciphertext(&spec_lut, &mut lwe_pbs_spec, MonomialDegree(0));

    let decrypted_pbs_spec = decrypt_lwe_ciphertext(&large_lwe_secret_key, &lwe_pbs_spec);
    let res = encoding.decode(decrypted_pbs_spec);

    assert_eq!(res, SPEC_LUT(MSG_A), "Specific PBS test failed.");
    store_data(path, &lwe_pbs_spec, "lwe_after_spec_pbs")?;

    Ok(())
}

/// Cleans the directory by removing all files and subdirectories,
/// except for a potential README.md file at the root.
fn rm_dir_except_readme<P: AsRef<Path>>(dir: P) -> Result<(), std::io::Error> {
    let dir = dir.as_ref();

    // Check if the directory exists before proceeding
    if dir.exists() {
        for entry_result in read_dir(dir)? {
            let entry = entry_result?;
            let path = entry.path();

            // Skip the README.md file at the root.
            if entry.file_name() == "README.md" {
                continue;
            }

            if path.is_dir() {
                fs::remove_dir_all(&path)?;
            } else {
                remove_file(&path)?;
            }
        }
    }
    Ok(())
}

fn main() -> Result<(), TestVectorError> {
    // Attempt to clean the data directory
    rm_dir_except_readme(DATA_DIR)?;

    let data_dir_path = PathBuf::from(DATA_DIR);

    // Generate test vectors with 'valid' secure parameters
    generate_test_vectors(
        data_dir_path.join("valid_params_128"),
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
    )?;

    // Generate test vectors with 'toy' insecure parameters
    generate_test_vectors(
        data_dir_path.join("toy_params"),
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
    )?;

    println!("Successfully generated all FHE test vectors!");

    Ok(())
}
