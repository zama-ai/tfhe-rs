# tfhe-rs backwards compatibility test corpus
This folder contains historical data types from **TFHE-rs** that have been versioned and serialized.
The goal is to detect in TFHE-rs CI when the version of a type should be updated because a breaking change has been added.

The messages are serialized using cbor and bincode because they both support large arrays and are vulnerable to different sets of breaking changes. Each message is stored with a set of metadata to verify that the values are loaded correctly.

# Usage
## Pulling the data with git-lfs
Backward data are stored with LFS and are not pulled by default. To pull them, simply run
```
make pull_backward_compat_data
```
You need to have `git-lfs` installed on your system.

## Backward compatibility test
From TFHE-rs root folder, run the following command
```
make test_backward_compatibility
```
This test will load the data stored in this folder, try to convert them to the latest version and check their correctness. This will automatically pull LFS data if needed.

## Data generation
First you need to make sure that you have pulled the LFS data (see above).

To re-generate the data, run the binary target for this project: `cargo run --release`. The prng is seeded with a fixed seed, so the data should be identical.

## Adding a test for an existing type
To add a new test for a type that is already tested, you need to create a const global variable with the metadata for that test. The type of metadata depends on the type being tested (for example, the metadata for a test of the `ClientKey` from the `high_level_api` is `HlClientKey`). Then go to the `data_vvv.rs` file (where "vvv" is the TFHE-rs version of the tested data) and update the `gen_xxx_data` method (where "xxx" is the API layer of your test (hl, shortint, integer,...)). In this method, create the object you want to test and serialize it using the `store_versioned_test` macro. Add the metadata of your test to the vector returned by this method.

The test will be automatically selected when you run TFHE-rs `make test_backward_compatibility`.

### Example
```rust
// 1. Define the metadata associated with the test
const HL_CT1_TEST: HlCiphertextTest = HlCiphertextTest {
    test_filename: Cow::Borrowed("ct1"),
    key_filename: Cow::Borrowed("client_key.cbor"),
    compressed: false,
    compact: false,
    clear_value: 0,
};

impl TfhersVersion for V0_6 {
    // ...
    // Impl of trait
    // ...

    fn gen_hl_data() -> Vec<TestMetadata> {
            // ...
            // Init code and generation of other tests
            // ...

            // 2. Create the type
            let ct1 = fheint8::encrypt(HL_CT1_TEST.clear_value, &hl_client_key);

            // 3. Store it
            store_versioned_test!(&ct1, &dir, &HL_CT1_TEST.test_filename);

            // 4. Return the metadata
            vec![
                TestMetadata::HlCiphertext(HL_CT1_TEST),
                // ...
                // Metadata for other tests
                // ...
        ]

    }

```

## Adding tests for a new type

### In this folder
To add a test for a type that has not yet been tested, you should create a new type that implements the `TestType` trait. The type should also store the metadata needed for the test, and be serializable. By convention, its name should start with the API layer being tested. The metadata can be anything that can be used to check that the correct value is retrieved after deserialization. However, it should not use a TFHE-rs internal type.

Once the type is created, it should be added to the `TestMetadata` enum. You can then add a new testcase using the procedure in the previous paragraph.

#### Example
```rust
// We use `Cow` for strings so that we can define them statically in this crate and load them
// dynamically in the test driver.
// Note that this type do not use anything from TFHE-rs
#derive(Serialize, Deserialize, Clone, Debug)]
pub struct HlCiphertextTest {
    pub test_filename: Cow<'static, str>,
    pub key_filename: Cow<'static, str>,
    pub compressed: bool,
    pub compact: bool,
    pub clear_value: u64,
}

impl TestType for HlCiphertextTest {
    fn module(&self) -> String {
        HL_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "FheUint".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Display)]
pub enum TestMetadata {
    // Hl
    HlCiphertext(HlCiphertextTest),
    // ...
    // All other supported types
    // ...
}
```

### In TFHE-rs
In TFHE-rs, you should update the test driver (in `tests/backward_compatibility/`) to handle your new test type. To do this, create a function that loads and unversionizes the message, and then checks its value against the metadata provided:

#### Example
```rust
/// Test HL ciphertext: loads the ciphertext and compares the decrypted value with the one in the
/// metadata.
pub fn test_hl_ciphertext(
    dir: &Path,
    test: &HlCiphertextTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let key_file = dir.join(&*test.key_filename);
    let key = ClientKey::unversionize(
        load_versioned_auxiliary(key_file).map_err(|e| test.failure(e, format))?,
    )
    .map_err(|e| test.failure(e, format))?;

    let server_key = key.generate_server_key();
    set_server_key(server_key);

    let ct = if test.compressed {
        let compressed: CompressedFheUint8 = load_and_unversionize(dir, test, format)?;
        compressed.decompress()
    } else if test.compact {
        let compact: CompactFheUint8 = load_and_unversionize(dir, test, format)?;
        compact.expand().unwrap()
    } else {
        load_and_unversionize(dir, test, format)?
    };

    let clear: u8 = ct.decrypt(&key);

    if clear != (test.clear_value as u8) {
        Err(test.failure(
            format!(
                "Invalid {} decrypted cleartext:\n Expected :\n{:?}\nGot:\n{:?}",
                format, clear, test.clear_value
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

// ...
// Other tests
// ...

impl TestedModule for Hl {
    const METADATA_FILE: &'static str = "high_level_api.ron";

    fn run_test<P: AsRef<Path>>(
        test_dir: P,
        testcase: &Testcase,
        format: DataFormat,
    ) -> TestResult {
        #[allow(unreachable_patterns)]
        match &testcase.metadata {
            TestMetadata::HlCiphertext(test) => {
                test_hl_ciphertext(test_dir.as_ref(), test, format).into()
            }
            // ...
            // Match other tests
            // ...
            _ => {
                println!("WARNING: missing test: {:?}", testcase.metadata)
                TestResult::Skipped(testcase.skip())
            }
        }
    }
}
```

## Adding a new tfhe-rs release
To add data for a new released version of tfhe-rs, you should first add a dependency to that version in the `Cargo.toml` of this project. This dependency should only be enabled with the `generate` feature to avoid conflicts during testing.

You should then implement the `TfhersVersion` trait for this version. You can use the code in `data_0_6.rs` as an example.

## Using the test data
The data is stored using git-lfs, but they are not pulled by default. You need to pull them by running:
```
make pull_backward_compat_data
```

To be able to parse the metadata and check if the loaded data is valid, you should add this crate as a dependency with the `load` feature enabled.
