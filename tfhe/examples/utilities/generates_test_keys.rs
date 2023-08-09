use clap::{Arg, ArgAction, Command};
use tfhe::keycache::NamedParam;
use tfhe::shortint::keycache::{KEY_CACHE, KEY_CACHE_WOPBS};
use tfhe::shortint::parameters::parameters_wopbs_message_carry::{
    WOPBS_PARAM_MESSAGE_1_CARRY_1_KS_PBS, WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    WOPBS_PARAM_MESSAGE_3_CARRY_3_KS_PBS, WOPBS_PARAM_MESSAGE_4_CARRY_4_KS_PBS,
};
use tfhe::shortint::parameters::{
    ClassicPBSParameters, WopbsParameters, ALL_MULTI_BIT_PARAMETER_VEC, ALL_PARAMETER_VEC,
    PARAM_MESSAGE_1_CARRY_1_KS_PBS, PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
};

fn client_server_keys() {
    let matches = Command::new("test key gen")
        .arg(
            Arg::new("multi_bit_only")
                .long("multi-bit-only")
                .help("Set to generate only multi bit keys, otherwise only PBS and WoPBS keys are generated")
                .action(ArgAction::SetTrue),
        )
        .get_matches();

    // If set using the command line flag "--ladner-fischer" this algorithm will be used in
    // additions
    let multi_bit_only: bool = matches.get_flag("multi_bit_only");

    if multi_bit_only {
        println!("Generating shortint multibit (ClientKey, ServerKey)");
        for (i, params) in ALL_MULTI_BIT_PARAMETER_VEC.iter().copied().enumerate() {
            println!(
                "Generating [{} / {}] : {}",
                i + 1,
                ALL_MULTI_BIT_PARAMETER_VEC.len(),
                params.name()
            );

            let start = std::time::Instant::now();

            let _ = KEY_CACHE.get_from_param(params.with_non_deterministic_execution());

            let stop = start.elapsed().as_secs();

            println!("Generation took {stop} seconds");

            // Clear keys as we go to avoid filling the RAM
            KEY_CACHE.clear_in_memory_cache()
        }
    } else {
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
            (
                PARAM_MESSAGE_1_CARRY_1_KS_PBS,
                WOPBS_PARAM_MESSAGE_1_CARRY_1_KS_PBS,
            ),
            (
                PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            ),
            (
                PARAM_MESSAGE_3_CARRY_3_KS_PBS,
                WOPBS_PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            ),
            (
                PARAM_MESSAGE_4_CARRY_4_KS_PBS,
                WOPBS_PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            ),
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
