use benchmark::utilities::{write_to_json_unchecked, OperatorType};
use benchmark_spec::TestResult;
use std::path::Path;
use tfhe::boolean::parameters::{DEFAULT_PARAMETERS, PARAMETERS_ERROR_PROB_2_POW_MINUS_165};
use tfhe::boolean::{client_key, server_key};

fn client_server_key_sizes(results_file: &Path) {
    let boolean_params_vec = [
        (DEFAULT_PARAMETERS, "DEFAULT_PARAMETERS"),
        (PARAMETERS_ERROR_PROB_2_POW_MINUS_165, "TFHE_LIB_PARAMETERS"),
    ];

    let mut benchmark_test_result = TestResult::from_path(results_file);

    let operator = OperatorType::Atomic;

    println!("Generating boolean (ClientKey, ServerKey)");
    for (i, (params, params_name)) in boolean_params_vec.iter().enumerate() {
        println!(
            "Generating [{} / {}] : {}",
            i + 1,
            boolean_params_vec.len(),
            params_name.to_lowercase()
        );

        let cks = client_key::ClientKey::new(params);
        let sks = server_key::ServerKey::new(&cks);
        let ksk_size = sks.key_switching_key_size_bytes();
        let test_name = format!("boolean_key_sizes_{params_name}_ksk");

        benchmark_test_result.write_result(&test_name, ksk_size);
        write_to_json_unchecked::<u32, _>(
            &test_name,
            *params,
            *params_name,
            "KSK",
            &operator,
            0,
            vec![],
        );

        println!(
            "Element in KSK: {}, size in bytes: {}",
            sks.key_switching_key_size_elements(),
            ksk_size,
        );

        let bsk_size = sks.bootstrapping_key_size_bytes();
        let test_name = format!("boolean_key_sizes_{params_name}_bsk");

        benchmark_test_result.write_result(&test_name, bsk_size);
        write_to_json_unchecked::<u32, _>(
            &test_name,
            *params,
            *params_name,
            "BSK",
            &operator,
            0,
            vec![],
        );

        println!(
            "Element in BSK: {}, size in bytes: {}",
            sks.bootstrapping_key_size_elements(),
            bsk_size,
        );
    }
}

fn main() {
    let work_dir = std::env::current_dir().unwrap();
    let mut new_work_dir = work_dir;
    new_work_dir.push("tfhe-benchmark");
    std::env::set_current_dir(new_work_dir).unwrap();

    let results_file = Path::new("boolean_key_sizes.csv");
    client_server_key_sizes(results_file)
}
