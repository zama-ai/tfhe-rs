use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use tfhe::boolean::parameters::{DEFAULT_PARAMETERS, TFHE_LIB_PARAMETERS};
use tfhe::boolean::{client_key, server_key};
use tfhe::shortint::keycache::{NamedParam, KEY_CACHE};
use tfhe::shortint::parameters::{
    PARAM_MESSAGE_1_CARRY_1, PARAM_MESSAGE_2_CARRY_2, PARAM_MESSAGE_3_CARRY_3,
    PARAM_MESSAGE_4_CARRY_4,
};

fn write_result(file: &mut File, name: &str, value: usize) {
    let line = format!("{},{}\n", name, value);
    let error_message = format!("cannot write {} result into file", name);
    file.write(line.as_bytes()).expect(&error_message);
}

fn client_server_keys_size(results_file: &Path) {
    let boolean_params_vec = vec![
        (DEFAULT_PARAMETERS, "default"),
        (TFHE_LIB_PARAMETERS, "tfhe_lib"),
    ];
    let shortint_params_vec = vec![
        PARAM_MESSAGE_1_CARRY_1,
        PARAM_MESSAGE_2_CARRY_2,
        PARAM_MESSAGE_3_CARRY_3,
        PARAM_MESSAGE_4_CARRY_4,
    ];
    File::create(results_file).expect("create results file failed");
    let mut file = OpenOptions::new()
        .append(true)
        .open(results_file)
        .expect("cannot open results file");

    println!("Generating boolean (ClientKey, ServerKey)");
    for (i, (params, name)) in boolean_params_vec.iter().enumerate() {
        println!(
            "Generating [{} / {}] : {}",
            i + 1,
            boolean_params_vec.len(),
            name
        );

        let cks = client_key::ClientKey::new(&params);
        let sks = server_key::ServerKey::new(&cks);
        let ksk_size = sks.key_switching_key.as_ref().len() * std::mem::size_of::<u64>();
        write_result(&mut file, &format!("boolean_{}_{}", name, "ksk"), ksk_size);
        println!(
            "Element in KSK: {}, size in bytes: {}",
            sks.key_switching_key.as_ref().len(),
            ksk_size,
        );

        // Fft refactor was not completed, so hack it
        let raw_bsk_data = sks.bootstrapping_key.clone().data();
        let bsk_size = raw_bsk_data.as_ref().len() * std::mem::size_of::<concrete_fft::c64>();
        write_result(&mut file, &format!("boolean_{}_{}", name, "bsk"), bsk_size);
        println!(
            "Element in BSK: {}, size in bytes: {}",
            raw_bsk_data.as_ref().len(),
            bsk_size,
        );
    }

    println!("Generating shortint (ClientKey, ServerKey)");
    for (i, params) in shortint_params_vec.iter().enumerate() {
        println!(
            "Generating [{} / {}] : {}",
            i + 1,
            shortint_params_vec.len(),
            params.name()
        );

        let keys = KEY_CACHE.get_from_param(params.clone());

        // Client keys don't have public access to members, but the keys in there are small anyways
        // let cks = keys.client_key();
        let sks = keys.server_key();
        let ksk_size = sks.key_switching_key.as_ref().len() * std::mem::size_of::<u64>();
        write_result(
            &mut file,
            &format!("shortint_{}_ksk", params.name().to_lowercase()),
            ksk_size,
        );
        println!(
            "Element in KSK: {}, size in bytes: {}",
            sks.key_switching_key.as_ref().len(),
            ksk_size,
        );

        // Fft refactor was not completed, so hack it
        let raw_bsk_data = sks.bootstrapping_key.clone().data();
        let bsk_size = raw_bsk_data.as_ref().len() * std::mem::size_of::<concrete_fft::c64>();
        write_result(
            &mut file,
            &format!("shortint_{}_bsk", params.name().to_lowercase()),
            bsk_size,
        );
        println!(
            "Element in BSK: {}, size in bytes: {}",
            raw_bsk_data.as_ref().len(),
            bsk_size,
        );

        // Clear keys as we go to avoid filling the RAM
        KEY_CACHE.clear_in_memory_cache()
    }
}

fn main() {
    let work_dir = std::env::current_dir().unwrap();
    println!("work_dir: {}", std::env::current_dir().unwrap().display());
    // Change workdir so that the location of the keycache matches the one for tests
    let mut new_work_dir = work_dir;
    new_work_dir.push("tfhe");
    std::env::set_current_dir(new_work_dir).unwrap();

    let results_file = Path::new("keys_size.csv");
    client_server_keys_size(results_file)
}
