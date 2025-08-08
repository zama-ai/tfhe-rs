use std::fs::remove_dir_all;
use std::thread;
use tfhe_backward_compat_data::data_0_10::V0_10;
use tfhe_backward_compat_data::data_0_11::V0_11;
use tfhe_backward_compat_data::data_0_8::V0_8;
use tfhe_backward_compat_data::data_1_0::V1_0;
use tfhe_backward_compat_data::data_1_1::V1_1;
use tfhe_backward_compat_data::data_1_3::V1_3;
use tfhe_backward_compat_data::data_1_4::V1_4;
use tfhe_backward_compat_data::generate::{store_metadata, TfhersVersion, PRNG_SEED};
use tfhe_backward_compat_data::{data_dir, Testcase, HL_MODULE_NAME, SHORTINT_MODULE_NAME};

fn gen_all_data<Vers: TfhersVersion>() -> Vec<Testcase> {
    Vers::seed_prng(PRNG_SEED);

    let shortint_tests = Vers::gen_shortint_data();

    let mut tests: Vec<Testcase> = shortint_tests
        .iter()
        .map(|metadata| Testcase {
            tfhe_version_min: Vers::VERSION_NUMBER.to_string(),
            tfhe_module: SHORTINT_MODULE_NAME.to_string(),
            metadata: metadata.clone(),
        })
        .collect();

    let hl_tests = Vers::gen_hl_data();

    tests.extend(hl_tests.iter().map(|metadata| Testcase {
        tfhe_version_min: Vers::VERSION_NUMBER.to_string(),
        tfhe_module: HL_MODULE_NAME.to_string(),
        metadata: metadata.clone(),
    }));

    tests
}

fn main() {
    let root_dir = env!("CARGO_MANIFEST_DIR");
    let data_dir_path = data_dir(root_dir);
    remove_dir_all(&data_dir_path).unwrap();

    let handler_v0_8 = thread::spawn(gen_all_data::<V0_8>);
    let handler_v0_10 = thread::spawn(gen_all_data::<V0_10>);
    let handler_v0_11 = thread::spawn(gen_all_data::<V0_11>);
    let handler_v1_0 = thread::spawn(gen_all_data::<V1_0>);
    let handler_v1_1 = thread::spawn(gen_all_data::<V1_1>);
    let handler_v1_3 = thread::spawn(gen_all_data::<V1_3>);
    let handler_v1_4 = thread::spawn(gen_all_data::<V1_4>);

    let mut testcases = vec![];

    testcases.extend_from_slice(&handler_v0_8.join().unwrap());
    testcases.extend_from_slice(&handler_v0_10.join().unwrap());
    testcases.extend_from_slice(&handler_v0_11.join().unwrap());
    testcases.extend_from_slice(&handler_v1_0.join().unwrap());
    testcases.extend_from_slice(&handler_v1_1.join().unwrap());
    testcases.extend_from_slice(&handler_v1_3.join().unwrap());
    testcases.extend_from_slice(&handler_v1_4.join().unwrap());

    let shortint_testcases: Vec<Testcase> = testcases
        .iter()
        .filter(|test| test.tfhe_module == SHORTINT_MODULE_NAME)
        .cloned()
        .collect();

    store_metadata(&shortint_testcases, data_dir_path.join("shortint.ron"));

    let high_level_api_testcases: Vec<Testcase> = testcases
        .iter()
        .filter(|test| test.tfhe_module == HL_MODULE_NAME)
        .cloned()
        .collect();

    store_metadata(
        &high_level_api_testcases,
        data_dir_path.join("high_level_api.ron"),
    );
}
