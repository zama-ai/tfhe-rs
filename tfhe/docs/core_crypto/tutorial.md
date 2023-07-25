# Tutorial

## Using the `core_crypto` primitives

Welcome to this tutorial about `TFHE-rs` `core_crypto` module.

### Setting up TFHE-rs to use the `core_crypto` module

To use `TFHE-rs`, it first has to be added as a dependency in the `Cargo.toml`:

```toml
tfhe = { version = "0.3.0", features = [ "x86_64-unix" ] }
```

This enables the `x86_64-unix` feature to have efficient implementations of various algorithms for `x86_64` CPUs on a Unix-like system. The 'unix' suffix indicates that the `UnixSeeder`, which uses `/dev/random` to generate random numbers, is activated as a fallback if no hardware number generator is available (like `rdseed` on `x86_64` or if the [`Randomization Services`](https://developer.apple.com/documentation/security/1399291-secrandomcopybytes?language=objc) on Apple platforms are not available). To avoid having the `UnixSeeder` as a potential fallback or to run on non-Unix systems (e.g., Windows), the `x86_64` feature is sufficient.

For Apple Silicon, the `aarch64-unix` or `aarch64` feature should be enabled. `aarch64` is not supported on Windows as it's currently missing an entropy source required to seed the [CSPRNGs](https://en.wikipedia.org/wiki/Cryptographically\_secure\_pseudorandom\_number\_generator) used in `TFHE-rs`.

In short: For `x86_64`-based machines running Unix-like OSes:

```toml
tfhe = { version = "0.3.0", features = ["x86_64-unix"] }
```

For Apple Silicon or aarch64-based machines running Unix-like OSes:

```toml
tfhe = { version = "0.3.0", features = ["aarch64-unix"] }
```

For `x86_64`-based machines with the [`rdseed instruction`](https://en.wikipedia.org/wiki/RDRAND) running Windows:

```toml
tfhe = { version = "0.3.0", features = ["x86_64"] }
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
    let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
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
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    // Create a generator which uses two CSPRNGs to generate public masks and secret encryption
    // noise
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

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
        glwe_modular_std_dev,
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
        lwe_modular_std_dev,
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

    // Here we will define a helper function to generate an accumulator for a PBS
    fn generate_accumulator<F>(
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
        message_modulus: usize,
        ciphertext_modulus: CiphertextModulus<u64>,
        delta: u64,
        f: F,
    ) -> GlweCiphertextOwned<u64>
    where
        F: Fn(u64) -> u64,
    {
        // N/(p/2) = size of each block, to correct noise from the input we introduce the notion of
        // box, which manages redundancy to yield a denoised value for several noisy values around
        // a true input value.
        let box_size = polynomial_size.0 / message_modulus;

        // Create the accumulator
        let mut accumulator_u64 = vec![0_u64; polynomial_size.0];

        // Fill each box with the encoded denoised value
        for i in 0..message_modulus {
            let index = i * box_size;
            accumulator_u64[index..index + box_size]
                .iter_mut()
                .for_each(|a| *a = f(i as u64) * delta);
        }

        let half_box_size = box_size / 2;

        // Negate the first half_box_size coefficients to manage negacyclicity and rotate
        for a_i in accumulator_u64[0..half_box_size].iter_mut() {
            *a_i = (*a_i).wrapping_neg();
        }

        // Rotate the accumulator
        accumulator_u64.rotate_left(half_box_size);

        let accumulator_plaintext = PlaintextList::from_container(accumulator_u64);

        let accumulator =
            allocate_and_trivially_encrypt_new_glwe_ciphertext(
                glwe_size,
                &accumulator_plaintext,
                ciphertext_modulus,
            );

        accumulator
    }

    // Generate the accumulator for our multiplication by 2 using a simple closure
    let accumulator: GlweCiphertextOwned<u64> = generate_accumulator(
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
        "Mulitplication via PBS result is correct! Expected 6, got {pbs_multiplication_result}"
    );
}
```
