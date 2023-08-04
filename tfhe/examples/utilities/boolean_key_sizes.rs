#[path = "../../benches/utilities.rs"]
mod utilities;
use crate::utilities::{write_to_json, OperatorType};

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use tfhe::boolean::parameters::{DEFAULT_PARAMETERS, PARAMETERS_ERROR_PROB_2_POW_MINUS_165};
use tfhe::boolean::{client_key, server_key};

fn write_result(file: &mut File, name: &str, value: usize) {
    let line = format!("{name},{value}\n");
    let error_message = format!("cannot write {name} result into file");
    file.write_all(line.as_bytes()).expect(&error_message);
}

fn client_server_key_sizes(results_file: &Path) {
    let boolean_params_vec = vec![
        (DEFAULT_PARAMETERS, "DEFAULT_PARAMETERS"),
        (PARAMETERS_ERROR_PROB_2_POW_MINUS_165, "TFHE_LIB_PARAMETERS"),
    ];
    File::create(results_file).expect("create results file failed");
    let mut file = OpenOptions::new()
        .append(true)
        .open(results_file)
        .expect("cannot open results file");

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

        write_result(&mut file, &test_name, ksk_size);
        write_to_json::<u32, _>(
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

        write_result(&mut file, &test_name, bsk_size);
        write_to_json::<u32, _>(
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
    new_work_dir.push("tfhe");
    std::env::set_current_dir(new_work_dir).unwrap();

    let results_file = Path::new("boolean_key_sizes.csv");
    client_server_key_sizes(results_file)
}
