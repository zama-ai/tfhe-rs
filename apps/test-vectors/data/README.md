# Test vectors for TFHE
These test vectors are generated using [TFHE-rs](https://github.com/zama-ai/tfhe-rs), with the git tag `tfhe-test-vectors-0.2.0`.

They are TFHE-rs objects serialized in the [cbor format](https://cbor.io/). You can deserialize them using any cbor library for the language of your choice. For example, using the [cbor2](https://pypi.org/project/cbor2/) program, run: `cbor2 --pretty toy_params/lwe_a.cbor`.

You will find 2 folders with test vectors for different parameter sets:
- `valid_params_128`: valid classical PBS parameters using a gaussian noise distribution, providing 128bits of security in the IND-CPA model and a bootstrapping probability of failure of 2^{-64}.
- `toy_params`: insecure parameters that yield smaller values

The values are generated for the keyswitch -> bootstrap (KS-PBS) atomic pattern. The cleartext inputs are 2 values, A and B defined below.

All the random values are generated from a fixed seed, that can be found in the `RAND_SEED` constant below. The PRNG used is the one based on the AES block cipher in counter mode, from tfhe `tfhe-csprng` crate.

The programmable bootstrap is applied twice, with 2 different lut, the identity lut and a specific one (currently a x2 operation)

## Vectors
The following values are generated:

### Keys
| name                   | description                                                                           | TFHE-rs type                |
|------------------------|---------------------------------------------------------------------------------------|-----------------------------|
| `large_lwe_secret_key` | Encryption secret key, before the KS and after the PBS                                | `LweSecretKey<Vec<u64>>`    |
| `small_lwe_secret_key` | Secret key encrypting ciphertexts between the KS and the PBS                          | `LweSecretKey<Vec<u64>>`    |
| `ksk`                  | The keyswitching key to convert a ct from the large key to the small one              | `LweKeyswitchKey<Vec<u64>>` |
| `bsk`                  | the bootstrapping key to perform a programmable bootstrap on the keyswitched ciphertext | `LweBootstrapKey<Vec<u64>>` |


### Ciphertexts
| name                 | description                                                                                                  | TFHE-rs type               | Cleartext    |
|----------------------|--------------------------------------------------------------------------------------------------------------|----------------------------|--------------|
| `lwe_a`              | Lwe encryption of A                                                                                          | `LweCiphertext<Vec<u64>>`  | `A`          |
| `lwe_b`              | Lwe encryption of B                                                                                          | `LweCiphertext<Vec<u64>>`  | `B`          |
| `lwe_sum`            | Lwe encryption of A plus lwe encryption of B                                                                 | `LweCiphertext<Vec<u64>>`  | `A+B`        |
| `lwe_prod`           | Lwe encryption of A times cleartext B                                                                        | `LweCiphertext<Vec<u64>>`  | `A*B`        |
| `lwe_ms`             | The lwe ciphertext after the modswitch part of the PBS ([note](#non-native-encoding))                        | `LweCiphertext<Vec<u64>>`  | `A`          |
| `lwe_ks`             | The lwe ciphertext after the keyswitch                                                                       | `LweCiphertext<Vec<u64>>`  | `A`          |
| `glwe_after_id_br`   | The glwe returned by the application of the identity blind rotation on the mod switched ciphertexts.         | `GlweCiphertext<Vec<u64>>` | rot id LUT   |
| `lwe_after_id_pbs`   | The lwe returned by the application of the sample extract operation on the output of the id blind rotation   | `LweCiphertext<Vec<u64>>`  | `A`          |
| `glwe_after_spec_br` | The glwe returned by the application of the spec blind rotation on the mod switched ciphertexts.             | `GlweCiphertext<Vec<u64>>` | rot spec LUT |
| `lwe_after_spec_pbs` | The lwe returned by the application of the sample extract operation on the output of the spec blind rotation | `LweCiphertext<Vec<u64>>`  | `spec(A)`    |

### Encodings
#### Non native encoding
Warning: TFHE-rs uses a specific encoding for non native (ie: u32, u64) power of two ciphertext modulus. This encoding puts the encoded value in the high bits of the native integer.
For example, the value 37 with a modulus of 64 will be encoded as `0b1001010000000000000000000000000000000000000000000000000000000000`. This matters for the post modswitch lwe ciphertext.

#### Ciphertext modulus
The ciphertext modulus encoding use a specific value for the native modulus: 0. For example, if values are stored on u64 integers, 0 means a ciphertext modulus of 2^64.

## Operations

| name                    | inputs                                                            | outputs                |
|-------------------------|-------------------------------------------------------------------|------------------------|
| large secret key gen    | PARAMS, RAND_SEED                                                 | `large_lwe_secret_key` |
| small secret key gen    | PARAMS, RAND_SEED                                                 | `small_lwe_secret_key` |
| keyswitch key gen       | PARAMS, RAND_SEED, `large_lwe_secret_key`, `small_lwe_secret_key` | `ksk`                  |
| bootstrap key gen       | PARAMS, RAND_SEED, `small_lwe_secret_key`, `large_lwe_secret_key` | `bsk`                  |
| encryption A            | A, `large_lwe_secret_key`                                         | `lwe_a`                |
| encryption B            | B, `large_lwe_secret_key`                                         | `lwe_b`                |
| `E(A)+E(B)`             | `lwe_a`, `lwe_b`                                                  | `lwe_sum`              |
| `E(A)*B`                | `lwe_a`, B                                                        | `lwe_prod`             |
| keyswitch               | `lwe_a`, `ksk`                                                    | `lwe_ks`               |
| modulus switch          | `lwe_ks`                                                          | `lwe_ms`               |
| blind rotation id lut   | ID_LUT, `lwe_ms`, `bsk`                                           | `glwe_after_id_br`     |
| sample extract id lut   | `glwe_after_id_br`                                                | `lwe_after_id_pbs`     |
| blind rotation spec lut | SPEC_LUT, `lwe_ms`, `bsk`                                         | `glwe_after_spec_br`   |
| sample extract spec lut | `glwe_after_spec_br`                                              | `lwe_after_spec_pbs`   |

## Parameters

```rust
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

const CIPHERTEXT_MODULUS: CiphertextModulus<u64> = CiphertextModulus::new_native();
const MSG_BITS: usize = 4;

const SPEC_LUT: fn(u64) -> u64 = |x| (x * 2) % (1u64 << MSG_BITS);
const ID_LUT: fn(u64) -> u64 = |x| x;
```
