use tfhe::shortint::keycache::{FileStorage, NamedParam, PersistentStorage};

use tfhe::shortint::gen_keys;
use tfhe::shortint::parameters::ALL_PARAMETER_VEC;

fn client_server_keys() {
    let file_storage = FileStorage::new("keys/shortint/client_server".to_string());

    println!("Generating (ClientKey, ServerKey)");
    for (i, params) in ALL_PARAMETER_VEC.iter().copied().enumerate() {
        println!(
            "Generating [{} / {}] : {}",
            i,
            ALL_PARAMETER_VEC.len(),
            params.name()
        );
        let client_server_keys = gen_keys(params);
        file_storage.store(params, &client_server_keys);
    }
}

fn main() {
    client_server_keys()
}
