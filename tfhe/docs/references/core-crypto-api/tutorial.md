# Tutorial

## Using the `core_crypto` primitives

Welcome to this tutorial about `TFHE-rs` `core_crypto` module.

### Setting up TFHE-rs to use the `core_crypto` module

To use `TFHE-rs`, it first has to be added as a dependency in the `Cargo.toml`:

```toml
tfhe = { version = "~1.5.4" }
```

### Commented code to double a 2-bit message in a leveled fashion and using a PBS with the `core_crypto` module.

As a complete example showing the usage of some common primitives of the `core_crypto` APIs, the following Rust code homomorphically computes 2 \* 3 using two different methods. First using a cleartext multiplication and then using a PBS.

```rust
use tfhe::core_crypto::prelude::*;

pub fn main() {
    // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    // computations
    // Define the parameters for a 4 bits message able to hold the doubled 2 bits message
    let small_lwe_dimension = LweDimension(742);
    let glwe_dimension = GlweDimension(1);
    let polynomial_size = PolynomialSize(2048);
    let lwe_noise_distribution =
        Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
    let glwe_noise_distribution =
        Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
    let pbs_base_log = DecompositionBaseLog(23);
    let pbs_level = DecompositionLevelCount(1);
    let ciphertext_modulus = CiphertextModulus::new_native();

    // Request the best seeder possible, starting with hardware entropy sources and falling back to
    // /dev/random on Unix systems if enabled via cargo features
    let mut boxed_seeder = new_seeder();
    // Get a mutable reference to the seeder as a trait object from the Box returned by new_seeder
    let seeder = boxed_seeder.as_mut();

    // Create a generator which uses a CSPRNG to generate secret keys
    let mut secret_generator =
        SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    // Create a generator which uses two CSPRNGs to generate public masks and secret encryption
    // noise
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    println!("Generating keys...");

    // Generate an LweSecretKey with binary coefficients
    let small_lwe_sk =
        LweSecretKey::generate_new_binary(small_lwe_dimension, &mut secret_generator);

    // Generate a GlweSecretKey with binary coefficients
    let glwe_sk =
        GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);

    // Create a copy of the GlweSecretKey re-interpreted as an LweSecretKey
    let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

    // Generate the bootstrapping key, we use the parallel variant for performance reason
    let std_bootstrapping_key = par_allocate_and_generate_new_lwe_bootstrap_key(
        &small_lwe_sk,
        &glwe_sk,
        pbs_base_log,
        pbs_level,
        glwe_noise_distribution,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    // Create the empty bootstrapping key in the Fourier domain
    let mut fourier_bsk = FourierLweBootstrapKey::new(
        std_bootstrapping_key.input_lwe_dimension(),
        std_bootstrapping_key.glwe_size(),
        std_bootstrapping_key.polynomial_size(),
        std_bootstrapping_key.decomposition_base_log(),
        std_bootstrapping_key.decomposition_level_count(),
    );

    // Use the conversion function (a memory optimized version also exists but is more complicated
    // to use) to convert the standard bootstrapping key to the Fourier domain
    convert_standard_lwe_bootstrap_key_to_fourier(&std_bootstrapping_key, &mut fourier_bsk);
    // We don't need the standard bootstrapping key anymore
    drop(std_bootstrapping_key);

    // Our 4 bits message space
    let message_modulus = 1u64 << 4;

    // Our input message
    let input_message = 3u64;

    // Delta used to encode 4 bits of message + a bit of padding on u64
    let delta = (1_u64 << 63) / message_modulus;

    // Apply our encoding
    let plaintext = Plaintext(input_message * delta);

    // Allocate a new LweCiphertext and encrypt our plaintext
    let lwe_ciphertext_in: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
        &small_lwe_sk,
        plaintext,
        lwe_noise_distribution,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    // Compute a cleartext multiplication by 2
    let mut cleartext_multiplication_ct = lwe_ciphertext_in.clone();
    println!("Performing cleartext multiplication...");
    lwe_ciphertext_cleartext_mul(
        &mut cleartext_multiplication_ct,
        &lwe_ciphertext_in,
        Cleartext(2),
    );

    // Decrypt the cleartext multiplication result
    let cleartext_multiplication_plaintext: Plaintext<u64> =
        decrypt_lwe_ciphertext(&small_lwe_sk, &cleartext_multiplication_ct);

    // Create a SignedDecomposer to perform the rounding of the decrypted plaintext
    // We pass a DecompositionBaseLog of 5 and a DecompositionLevelCount of 1 indicating we want to
    // round the 5 MSB, 1 bit of padding plus our 4 bits of message
    let signed_decomposer =
        SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));

    // Round and remove our encoding
    let cleartext_multiplication_result: u64 =
        signed_decomposer.closest_representable(cleartext_multiplication_plaintext.0) / delta;

    println!("Checking result...");
    assert_eq!(6, cleartext_multiplication_result);
    println!(
        "Cleartext multiplication result is correct! \
        Expected 6, got {cleartext_multiplication_result}"
    );

    // Now we will use a PBS to compute the same multiplication, it is NOT the recommended way of
    // doing this operation in terms of performance as it's much more costly than a multiplication
    // with a cleartext, however it resets the noise in a ciphertext to a nominal level and allows
    // to evaluate arbitrary functions so depending on your use case it can be a better fit.

    // Generate the accumulator for our multiplication by 2 using a simple closure
    let accumulator: GlweCiphertextOwned<u64> = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        message_modulus as usize,
        ciphertext_modulus,
        delta,
        |x: u64| 2 * x,
    );

    // Allocate the LweCiphertext to store the result of the PBS
    let mut pbs_multiplication_ct = LweCiphertext::new(
        0u64,
        big_lwe_sk.lwe_dimension().to_lwe_size(),
        ciphertext_modulus,
    );
    println!("Computing PBS...");
    programmable_bootstrap_lwe_ciphertext(
        &lwe_ciphertext_in,
        &mut pbs_multiplication_ct,
        &accumulator,
        &fourier_bsk,
    );

    // Decrypt the PBS multiplication result
    let pbs_multiplication_plaintext: Plaintext<u64> =
        decrypt_lwe_ciphertext(&big_lwe_sk, &pbs_multiplication_ct);

    // Round and remove our encoding
    let pbs_multiplication_result: u64 =
        signed_decomposer.closest_representable(pbs_multiplication_plaintext.0) / delta;

    println!("Checking result...");
    assert_eq!(6, pbs_multiplication_result);
    println!(
        "Multiplication via PBS result is correct! Expected 6, got {pbs_multiplication_result}"
    );
}
```
