use clap::{Arg, ArgAction, Command};
use tfhe::boolean;
use tfhe::boolean::parameters::{BooleanParameters, DEFAULT_PARAMETERS, DEFAULT_PARAMETERS_KS_PBS};
use tfhe::keycache::NamedParam;
use tfhe::shortint::keycache::{KEY_CACHE, KEY_CACHE_KSK, KEY_CACHE_WOPBS};
use tfhe::shortint::parameters::key_switching::{
    ShortintKeySwitchingParameters, PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS,
};
use tfhe::shortint::parameters::multi_bit::{
    MultiBitPBSParameters, PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
};
use tfhe::shortint::parameters::parameters_compact_pk::{
    PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS, PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS,
};
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
                .action(ArgAction::SetTrue)
                .exclusive(true),
        )
        .arg(
            Arg::new("coverage_only")
                .long("coverage-only")
                .help("Set to generate only coverage keys, a very small subset of keys")
                .action(ArgAction::SetTrue)
                .exclusive(true),
        )
        .get_matches();

    // If set using the command line flag "--ladner-fischer" this algorithm will be used in
    // additions
    let multi_bit_only: bool = matches.get_flag("multi_bit_only");
    let coverage_only: bool = matches.get_flag("coverage_only");

    if multi_bit_only {
        generate_pbs_multi_bit_keys(&ALL_MULTI_BIT_PARAMETER_VEC);
    } else if coverage_only {
        println!("Generating keys (ClientKey, ServerKey) for coverage");

        const PBS_PARAMS: [ClassicPBSParameters; 5] = [
            PARAM_MESSAGE_1_CARRY_1_KS_PBS,
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS,
            PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS,
        ];

        generate_pbs_keys(&PBS_PARAMS);

        const MULTI_BIT_PARAMS: [MultiBitPBSParameters; 2] = [
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
        ];

        generate_pbs_multi_bit_keys(&MULTI_BIT_PARAMS);

        const KSK_PARAMS: [(
            ClassicPBSParameters,
            ClassicPBSParameters,
            ShortintKeySwitchingParameters,
        ); 2] = [
            (
                PARAM_MESSAGE_1_CARRY_1_KS_PBS,
                PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS,
            ),
            (
                PARAM_MESSAGE_1_CARRY_1_KS_PBS,
                PARAM_MESSAGE_3_CARRY_3_KS_PBS,
                PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS,
            ),
        ];

        generate_ksk_keys(&KSK_PARAMS);

        const WOPBS_PARAMS: [(ClassicPBSParameters, WopbsParameters); 1] = [(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        )];
        generate_wopbs_keys(&WOPBS_PARAMS);

        const BOOLEAN_PARAMS: [BooleanParameters; 2] =
            [DEFAULT_PARAMETERS, DEFAULT_PARAMETERS_KS_PBS];
        generate_boolean_keys(&BOOLEAN_PARAMS);
    } else {
        generate_pbs_keys(&ALL_PARAMETER_VEC);

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

        generate_wopbs_keys(&WOPBS_PARAMS);
    }
}

fn generate_pbs_keys(params: &[ClassicPBSParameters]) {
    println!("Generating shortint (ClientKey, ServerKey)");

    for (i, param) in params.iter().copied().enumerate() {
        println!(
            "Generating [{} / {}] : {}",
            i + 1,
            params.len(),
            param.name()
        );

        let start = std::time::Instant::now();

        let _ = KEY_CACHE.get_from_param(param);

        let stop = start.elapsed().as_secs();

        println!("Generation took {stop} seconds");

        // Clear keys as we go to avoid filling the RAM
        KEY_CACHE.clear_in_memory_cache()
    }
}

fn generate_pbs_multi_bit_keys(params: &[MultiBitPBSParameters]) {
    println!("Generating shortint multibit (ClientKey, ServerKey)");

    for (i, param) in params.iter().copied().enumerate() {
        println!(
            "Generating [{} / {}] : {}",
            i + 1,
            params.len(),
            param.name()
        );

        let start = std::time::Instant::now();

        let _ = KEY_CACHE.get_from_param(param.with_non_deterministic_execution());

        let stop = start.elapsed().as_secs();

        println!("Generation took {stop} seconds");

        // Clear keys as we go to avoid filling the RAM
        KEY_CACHE.clear_in_memory_cache()
    }
}

fn generate_ksk_keys(
    params: &[(
        ClassicPBSParameters,
        ClassicPBSParameters,
        ShortintKeySwitchingParameters,
    )],
) {
    println!("Generating shortint Key Switching keys (ClientKey, ServerKey)");

    for (i, (param_1, param_2, param_ksk)) in params.iter().copied().enumerate() {
        println!(
            "Generating [{} / {}] : {}__{}__{}",
            i + 1,
            params.len(),
            param_1.name(),
            param_2.name(),
            param_ksk.name()
        );

        let start = std::time::Instant::now();

        let _ = KEY_CACHE_KSK.get_from_param((param_1, param_2, param_ksk));

        let stop = start.elapsed().as_secs();

        println!("Generation took {stop} seconds");

        // Clear keys as we go to avoid filling the RAM
        KEY_CACHE_KSK.clear_in_memory_cache()
    }
}

fn generate_wopbs_keys(params: &[(ClassicPBSParameters, WopbsParameters)]) {
    println!("Generating woPBS keys");

    for (i, (params_shortint, params_wopbs)) in params.iter().copied().enumerate() {
        println!(
            "Generating [{} / {}] : {}, {}",
            i + 1,
            params.len(),
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

fn generate_boolean_keys(params: &[BooleanParameters]) {
    println!("Generating boolean (ClientKey, ServerKey)");

    for (i, param) in params.iter().copied().enumerate() {
        println!(
            "Generating [{} / {}] : {}",
            i + 1,
            params.len(),
            param.name()
        );

        let start = std::time::Instant::now();

        let _ = boolean::keycache::KEY_CACHE.get_from_param(param);

        let stop = start.elapsed().as_secs();

        println!("Generation took {stop} seconds");

        // Clear keys as we go to avoid filling the RAM
        boolean::keycache::KEY_CACHE.clear_in_memory_cache()
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
