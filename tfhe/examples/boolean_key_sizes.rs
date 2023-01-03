use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use tfhe::boolean::parameters::{DEFAULT_PARAMETERS, TFHE_LIB_PARAMETERS};
use tfhe::boolean::{client_key, server_key};

fn write_result(file: &mut File, name: &str, value: usize) {
    let line = format!("{name},{value}\n");
    let error_message = format!("cannot write {name} result into file");
    file.write_all(line.as_bytes()).expect(&error_message);
}

fn client_server_key_sizes(results_file: &Path) {
    let boolean_params_vec = vec![
        (DEFAULT_PARAMETERS, "default"),
        (TFHE_LIB_PARAMETERS, "tfhe_lib"),
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

        let cks = client_key::ClientKey::new(params);
        let sks = server_key::ServerKey::new(&cks);
        let ksk_size = sks.key_switching_key_size_bytes();
        write_result(&mut file, &format!("boolean_{}_{}", name, "ksk"), ksk_size);
        println!(
            "Element in KSK: {}, size in bytes: {}",
            sks.key_switching_key_size_elements(),
            ksk_size,
        );

        let bsk_size = sks.bootstrapping_key_size_bytes();
        write_result(&mut file, &format!("boolean_{}_{}", name, "bsk"), bsk_size);
        println!(
            "Element in BSK: {}, size in bytes: {}",
            sks.bootstrapping_key_size_elements(),
            bsk_size,
        );
    }
}

fn main() {
    let work_dir = std::env::current_dir().unwrap();
    println!("work_dir: {}", std::env::current_dir().unwrap().display());
    // Change workdir so that the location of the keycache matches the one for tests
    let mut new_work_dir = work_dir;
    new_work_dir.push("tfhe");
    std::env::set_current_dir(new_work_dir).unwrap();

    let results_file = Path::new("boolean_key_sizes.csv");
    client_server_key_sizes(results_file)
}
