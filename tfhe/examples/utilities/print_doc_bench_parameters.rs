use tfhe::keycache::NamedParam;
use tfhe::shortint::parameters::{
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};

pub fn main() {
    println!("CPU Integer parameters:\n");
    println!("{}", PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.name());
    println!("{PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:?}");

    println!("\n\n===========================================================================\n\n");

    println!("CUDA GPU Integer parameters:\n");
    println!(
        "{}",
        PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.name()
    );
    println!("{PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:?}");

    println!("\n\n===========================================================================\n\n");

    println!("CPU PBS parameters:\n");
    let param = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let bits = (param.message_modulus.0 * param.carry_modulus.0).ilog2();
    println!("Precision {bits} bits");
    println!("{}", param.name());
    println!("{param:?}\n");

    println!("\n===========================================================================\n\n");

    println!("CUDA GPU PBS parameters:\n");
    let param = PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let bits = (param.message_modulus.0 * param.carry_modulus.0).ilog2();
    println!("Precision {bits} bits");
    println!("{}", param.name());
    println!("{param:?}\n");

    println!("\n===========================================================================\n\n");

    println!("ZK POK parameters:\n");

    println!("Compact Public Key parameters (encryption + ZK):");
    println!(
        "{}",
        stringify!(PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
    );
    println!("{PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:?}\n");

    println!("Corresponding compute FHE parameters:");
    println!(
        "{}",
        stringify!(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
    );
    println!("{PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:?}\n");

    println!("Keyswitch from encryption + ZK to compute parameters:");
    println!(
        "{}",
        stringify!(PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
    );
    println!("{PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:?}");
}
