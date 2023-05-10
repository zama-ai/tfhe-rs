use tfhe::shortint::keycache::{NamedParam, KEY_CACHE, KEY_CACHE_WOPBS};
use tfhe::shortint::parameters::parameters_wopbs_message_carry::{
    WOPBS_PARAM_MESSAGE_1_CARRY_1, WOPBS_PARAM_MESSAGE_2_CARRY_2, WOPBS_PARAM_MESSAGE_3_CARRY_3,
    WOPBS_PARAM_MESSAGE_4_CARRY_4,
};
use tfhe::shortint::parameters::{
    ClassicPBSParameters, WopbsParameters, ALL_PARAMETER_VEC, PARAM_MESSAGE_1_CARRY_1,
    PARAM_MESSAGE_2_CARRY_2, PARAM_MESSAGE_3_CARRY_3, PARAM_MESSAGE_4_CARRY_4,
};

fn client_server_keys() {
    println!("Generating shortint (ClientKey, ServerKey)");
    for (i, params) in ALL_PARAMETER_VEC.iter().copied().enumerate() {
        println!(
            "Generating [{} / {}] : {}",
            i + 1,
            ALL_PARAMETER_VEC.len(),
            params.name()
        );

        let start = std::time::Instant::now();

        let _ = KEY_CACHE.get_from_param(params);

        let stop = start.elapsed().as_secs();

        println!("Generation took {stop} seconds");

        // Clear keys as we go to avoid filling the RAM
        KEY_CACHE.clear_in_memory_cache()
    }

    const WOPBS_PARAMS: [(ClassicPBSParameters, WopbsParameters); 4] = [
        (PARAM_MESSAGE_1_CARRY_1, WOPBS_PARAM_MESSAGE_1_CARRY_1),
        (PARAM_MESSAGE_2_CARRY_2, WOPBS_PARAM_MESSAGE_2_CARRY_2),
        (PARAM_MESSAGE_3_CARRY_3, WOPBS_PARAM_MESSAGE_3_CARRY_3),
        (PARAM_MESSAGE_4_CARRY_4, WOPBS_PARAM_MESSAGE_4_CARRY_4),
    ];

    println!("Generating woPBS keys");
    for (i, (params_shortint, params_wopbs)) in WOPBS_PARAMS.iter().copied().enumerate() {
        println!(
            "Generating [{} / {}] : {}, {}",
            i + 1,
            WOPBS_PARAMS.len(),
            params_shortint.name(),
            params_wopbs.name(),
        );

        let start = std::time::Instant::now();

        let _ = KEY_CACHE_WOPBS.get_from_param((params_shortint, params_wopbs));

        let stop = start.elapsed().as_secs();

        println!("Generation took {stop} seconds");

        // Clear keys as we go to avoid filling the RAM
        KEY_CACHE_WOPBS.clear_in_memory_cache()
    }
}

fn main() {
    let work_dir = std::env::current_dir().unwrap();
    println!("work_dir: {}", std::env::current_dir().unwrap().display());
    // Change workdir so that the location of the keycache matches the one for tests
    let mut new_work_dir = work_dir;
    new_work_dir.push("tfhe");
    std::env::set_current_dir(new_work_dir).unwrap();

    client_server_keys()
}
