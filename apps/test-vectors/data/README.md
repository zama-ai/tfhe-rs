# Test vectors for TFHE
These test vectors are generated using [TFHE-rs](https://github.com/zama-ai/tfhe-rs), with the git tag `tfhe-test-vectors-0.2.0`.

They are TFHE-rs objects serialized in the [cbor format](https://cbor.io/). These can be deserialized using any cbor library for any programming languages. For example, using the [cbor2](https://pypi.org/project/cbor2/) program, the command to run is: `cbor2 --pretty toy_params/lwe_a.cbor`.

There are 2 folders with test vectors for different parameter sets:
- `valid_params_128`: valid classical PBS parameters using a Gaussian noise distribution, providing 128-bits of security in the IND-CPA model (i.e., the probability of failure is smaller than 2^{-64}).
- `toy_params`: insecure parameters that yield smaller values to simplify the bit comparison of the results.

The values are generated to compute a keyswitch (KS) followed by a bootstrap (PBS). The cleartext inputs are 2 values, A and B defined below.

All the random values are generated from a fixed seed, that can be found in the `RAND_SEED` constant below. The PRNG used is the one based on the AES block cipher in counter mode, from tfhe `tfhe-csprng` crate.

The bootstrap is applied twice, with 2 different lut, the identity lut and a specific one computing the double of the input value (i.e., f(x) = 2*x).

## Vectors
The following values are generated:

### Keys
| name                   | description                                                                             | TFHE-rs type                |
|------------------------|-----------------------------------------------------------------------------------------|-----------------------------|
| `large_lwe_secret_key` | Encryption secret key, used before the KS and after the PBS                                  | `LweSecretKey<Vec<u64>>`    |
| `small_lwe_secret_key` | Secret key encrypting ciphertexts between the KS and the PBS                            | `LweSecretKey<Vec<u64>>`    |
| `ksk`                  | The keyswitching key to convert a ct from the large key to the small one                | `LweKeyswitchKey<Vec<u64>>` |
| `bsk`                  | the bootstrapping key to perform a programmable bootstrap on the keyswitched ciphertext | `LweBootstrapKey<Vec<u64>>` |


### Ciphertexts
| name                 | description                                                                                         | TFHE-rs type               | Cleartext            |
|----------------------|-----------------------------------------------------------------------------------------------------|----------------------------|----------------------|
| `lwe_a`              | LWE Ciphertext encrypting A                                                                         | `LweCiphertext<Vec<u64>>`  | `A`                  |
| `lwe_b`              | LWE Ciphertext encrypting B                                                                         | `LweCiphertext<Vec<u64>>`  | `B`                  |
| `lwe_sum`            | LWE Ciphertext encrypting the addition of the LWE encryption of $A$ and the LWE encryption of $B$                                                | `LweCiphertext<Vec<u64>>`  | `A+B`                |
| `lwe_prod`           | LWE Ciphertext encrypting the scalar product of the LWE encryption of A and the cleartext B                                                       | `LweCiphertext<Vec<u64>>`  | `A*B`                |
| `lwe_ms`             | LWE Ciphertext encrypting A after a Modulus Switch from q to 2*N ([note](#non-native-encoding))     | `LweCiphertext<Vec<u64>>`  | `A`                  |
| `lwe_ks`             | LWE Ciphertext encrypting A after a keyswitch from `large_lwe_secret_key` to `small_lwe_secret_key` | `LweCiphertext<Vec<u64>>`  | `A`                  |
| `glwe_after_id_br`   | GLWE Ciphertext encrypting A after the application of the identity blind rotation on `lwe_ms`       | `GlweCiphertext<Vec<u64>>` | rotation of id LUT   |
| `lwe_after_id_pbs`   | LWE Ciphertext encrypting A after the sample extract operation on `glwe_after_id_br`                | `LweCiphertext<Vec<u64>>`  | `A`                  |
| `glwe_after_spec_br` | GLWE Ciphertext encrypting spec(A) after the application of the spec blind rotation on `lwe_ms`     | `GlweCiphertext<Vec<u64>>` | rotation of spec LUT |
| `lwe_after_spec_pbs` | LWE Ciphertext encrypting spec(A) after the sample extract operation on `glwe_after_spec_br`        | `LweCiphertext<Vec<u64>>`  | `spec(A)`            |

Ciphertexts with the `_karatsuba` suffix are generated using the Karatsuba polynomial multiplication algorithm in the blind rotation, while default ciphertexts are generated using an FFT multiplication.
Since Karatsuba operates purely on integers, it produces deterministic results regardless of the platform or compiler, making it easier to reproduce bit exact results.

### Encodings
#### Native encoding 
Standard ciphertexts use 32 bit or 64 bit siphertext modulus as this is the size of the cpu register.
For example taking a ciphertext modulus $q = 2^{64}$, a cleartext modulus $t = 2^{4}$, and a corresponding scaling factor $\Delta = 2^{59}$ (as a padding bit is used in the encoding), the cleartext integer value $m = 11$ is encoded as `0b0101100000000000000000000000000000000000000000000000000000000000`.

_Note:_ in the CBOR files, the structure contains a list of integers called `"data"`, representing the coefficients of the ciphertext(s) or the secret key bits.  This may be followed by additional parameter information, such as the `"ciphertext_modulus"`: the ciphertext modulus equals on of the native moduli (u32 or u64), the modulus is set to 0 in the CBOR file. For example, if values are stored on u64 integers, 0 would indicate a ciphertext modulus of $2^{64}$.
<pre>```
{
    "data": [
        11232563232213207535,
        ...
        9571800994433015103
    ],
    "ciphertext_modulus": {
        "modulus": 0,
        "scalar_bits": 64
    }
}
```</pre>

#### Non native encoding
Warning: TFHE-rs uses a specific encoding for non native power of two ciphertext modulus. After the modulus switching operation one ends up with values modulo 2N, i.e. with a non native power of two ciphertext modulus (different from 32 or 64). These values will however still be stored in 32-bit/64-bit integers as that is the native size of CPU registers. To achieve this TFHE-rs uses a specific encoding that puts the encoded value in the high bits of the native integer. This has to be taken into account when working with ciphertexts that are the output of a modulus switching operation.
For example the value 37 with a modulus of 64 will be encoded in the 6 highest bits of the 64-bit value, hence this value is encoded as `0b10010100000000000000000000000000000000000000000000000000000000000`.
In the CBOR file the modulus parameter will indicate the ciphertext modulus value.

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
