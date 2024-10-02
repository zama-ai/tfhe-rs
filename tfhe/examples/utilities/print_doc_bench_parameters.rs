use tfhe::keycache::NamedParam;
use tfhe::shortint::parameters::classic::gaussian::p_fail_2_minus_64::ks_pbs::{
    PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64, PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64, PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
};
use tfhe::shortint::parameters::classic::tuniform::p_fail_2_minus_64::ks_pbs::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use tfhe::shortint::parameters::compact_public_key_only::p_fail_2_minus_64::ks_pbs::PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use tfhe::shortint::parameters::key_switching::p_fail_2_minus_64::ks_pbs::PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use tfhe::shortint::parameters::multi_bit::p_fail_2_minus_64::ks_pbs_gpu::{
    PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
};

pub fn main() {
    println!("CPU Integer parameters:\n");
    println!("{}", PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64.name());
    println!("{PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64:?}");

    println!("\n\n===========================================================================\n\n");

    println!("CUDA GPU Integer parameters:\n");
    println!(
        "{}",
        PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64.name()
    );
    println!("{PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64:?}");

    println!("\n\n===========================================================================\n\n");

    println!("CPU PBS parameters:\n");
    for param in [
        PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    ] {
        let bits = (param.message_modulus.0 * param.carry_modulus.0).ilog2();
        println!("Precision {bits} bits");
        println!("{}", param.name());
        println!("{param:?}\n");
    }

    println!("\n===========================================================================\n\n");

    println!("CUDA GPU PBS parameters:\n");
    for param in [
        PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
        PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    ] {
        let bits = (param.message_modulus.0 * param.carry_modulus.0).ilog2();
        println!("Precision {bits} bits");
        println!("{}", param.name());
        println!("{param:?}\n");
    }

    println!("\n===========================================================================\n\n");

    println!("ZK POK parameters:\n");

    println!("Compact Public Key parameters (encryption + ZK):");
    println!(
        "{}",
        stringify!(PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64)
    );
    println!("{PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64:?}\n");

    println!("Corresponding compute FHE parameters:");
    println!(
        "{}",
        stringify!(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64)
    );
    println!("{PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64:?}\n");

    println!("Keyswitch from encryption + ZK to compute parameters:");
    println!(
        "{}",
        stringify!(PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64)
    );
    println!("{PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64:?}");
}
