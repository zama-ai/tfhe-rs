use tfhe::shortint::keycache::{NamedParam, KEY_CACHE};
use tfhe::shortint::parameters::{
    Parameters, PARAM_MESSAGE_1_CARRY_1, PARAM_MESSAGE_2_CARRY_2, PARAM_MESSAGE_3_CARRY_3,
    PARAM_MESSAGE_4_CARRY_4,
};

fn client_server_keys_size() {
    let params_vec = vec![
        PARAM_MESSAGE_1_CARRY_1,
        PARAM_MESSAGE_2_CARRY_2,
        PARAM_MESSAGE_3_CARRY_3,
        PARAM_MESSAGE_4_CARRY_4,
    ];

    println!("Generating shortint (ClientKey, ServerKey)");
    for (i, params) in params_vec.iter().enumerate() {
        println!(
            "Generating [{} / {}] : {}",
            i + 1,
            params_vec.len(),
            params.name()
        );

        let keys = KEY_CACHE.get_from_param(params.clone());

        // Client keys don't have public access to members, but the keys in there are small anyways
        // let cks = keys.client_key();
        let sks = keys.server_key();

        println!(
            "Element in KSK: {}, size in bytes: {}",
            sks.key_switching_key.as_ref().len(),
            sks.key_switching_key.as_ref().len() * std::mem::size_of::<u64>(),
        );

        // Fft refactor was not completed, so hack it
        let raw_bsk_data = sks.bootstrapping_key.clone().data();

        println!(
            "Element in BSK: {}, size in bytes: {}",
            raw_bsk_data.as_ref().len(),
            raw_bsk_data.as_ref().len() * std::mem::size_of::<concrete_fft::c64>(),
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

    client_server_keys_size()
}
