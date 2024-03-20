use tfhe::prelude::*;
use tfhe::*;


pub fn main() {

    let config = ConfigBuilder::default().build();

    let (cks, sks) = generate_keys(config);

    let a = FheUint32::encrypt(42u32, &cks);
    let b = FheUint32::encrypt(69u32, &cks);

    set_server_key(sks);


    // Negation
    let c = -&a;
    let neg_32_count = get_pbs_count();
    reset_pbs_count();

    // Add / Sub
    let c = &a + &b;
    let add_32_count = get_pbs_count();
    reset_pbs_count();

    // Mul
    let c = &a * &b;
    let mul_32_count = get_pbs_count();
    reset_pbs_count();

    // Equal / Not Equal
    let c = &a.eq(&b);
    let eq_32_count = get_pbs_count();
    reset_pbs_count();

    // Comparisons
    let c = &a.gt(&b);
    let gt_32_count = get_pbs_count();
    reset_pbs_count();

    // Max / Min
    let c = &a.max(&b);
    let max_32_count = get_pbs_count();
    reset_pbs_count();

    // Bitwise operations
    let c = &a & &b;
    let and_32_count = get_pbs_count();
    reset_pbs_count();

    //         Div / Rem
    let c = &a % &b;
    let mod_32_count = get_pbs_count();
    reset_pbs_count();

    // Left / Right Shifts
    let c = &a << &b;
    let shift_32_count = get_pbs_count();
    reset_pbs_count();

    //    Left / Right Rotations
    let c = &a.rotate_right(&b);
    let rotate_32_count = get_pbs_count();
    reset_pbs_count();

    println!("neg_32_count: {neg_32_count}");
    println!("add_32_count: {add_32_count}");
    println!("mul_32_count: {mul_32_count}");
    println!("eq_32_count: {eq_32_count}");
    println!("gt_32_count: {gt_32_count}");
    println!("max_32_count: {max_32_count}");
    println!("and_32_count: {and_32_count}");
    println!("mod_32_count: {mod_32_count}");
    println!("shift_32_count: {shift_32_count}");
    println!("and_32_count: {rotate_32_count}");



     let config = ConfigBuilder::default().build();

    let (cks, sks) = generate_keys(config);

    let a = FheUint64::encrypt(42u64, &cks);
    let b = FheUint64::encrypt(69u64, &cks);

    set_server_key(sks);


    // Negation
    let c = -&a;
    let neg_64_count = get_pbs_count();
    reset_pbs_count();

    // Add / Sub
    let c = &a + &b;
    let add_64_count = get_pbs_count();
    reset_pbs_count();

    // Mul
    let c = &a * &b;
    let mul_64_count = get_pbs_count();
    reset_pbs_count();

    // Equal / Not Equal
    let c = &a.eq(&b);
    let eq_64_count = get_pbs_count();
    reset_pbs_count();

    // Comparisons
    let c = &a.gt(&b);
    let gt_64_count = get_pbs_count();
    reset_pbs_count();

    // Max / Min
    let c = &a.max(&b);
    let max_64_count = get_pbs_count();
    reset_pbs_count();

    // Bitwise operations
    let c = &a & &b;
    let and_64_count = get_pbs_count();
    reset_pbs_count();

    //         Div / Rem
    let c = &a % &b;
    let mod_64_count = get_pbs_count();
    reset_pbs_count();

    // Left / Right Shifts
    let c = &a << &b;
    let shift_64_count = get_pbs_count();
    reset_pbs_count();

    //    Left / Right Rotations
    let c = &a.rotate_right(&b);
    let rotate_64_count = get_pbs_count();
    reset_pbs_count();

    println!("neg_64_count: {neg_64_count}");
    println!("add_64_count: {add_64_count}");
    println!("mul_64_count: {mul_64_count}");
    println!("eq_64_count: {eq_64_count}");
    println!("gt_64_count: {gt_64_count}");
    println!("max_64_count: {max_64_count}");
    println!("and_64_count: {and_64_count}");
    println!("mod_64_count: {mod_64_count}");
    println!("shift_64_count: {shift_64_count}");
    println!("and_64_count: {rotate_64_count}");




    assert!(false);
}


// pub fn count_all_pbs(){



//     let (cks, sks) = generate_keys(config);

//     let a = FheUint32::encrypt(42, &cks);
//     let b = FheUint32::encrypt(69, &cks);

//     set_server_key(sks);

//     let c = &a * &b;
//     let mul_32_count = get_pbs_count();

//     reset_pbs_count();
//     let d = &a & &b;
//     let and_32_count = get_pbs_count();
// }
