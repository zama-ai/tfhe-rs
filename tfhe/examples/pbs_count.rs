use tfhe::prelude::*;
use tfhe::*;

pub fn main() {
    let config = ConfigBuilder::default().build();

    let (cks, sks) = generate_keys(config);

    let a = FheUint32::encrypt(42u32, &cks);
    let b = FheUint32::encrypt(69u32, &cks);

    set_server_key(sks);

    let c = &a * &b;
    let mul_32_count = get_pbs_count();

    reset_pbs_count();
    let d = &a & &b;
    let and_32_count = get_pbs_count();

    println!("mul_32_count: {mul_32_count}");
    println!("and_32_count: {and_32_count}");

    let c_dec: u32 = c.decrypt(&cks);
    let d_dec: u32 = d.decrypt(&cks);

    assert_eq!(42 * 69, c_dec);
    assert_eq!(42 & 69, d_dec);
}
