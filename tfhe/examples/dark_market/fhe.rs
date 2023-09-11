use std::time::Instant;
use tfhe::integer::ciphertext::RadixCiphertext;
use tfhe::integer::{ClientKey, ServerKey};

use crate::NUMBER_OF_BLOCKS;

fn vector_sum(server_key: &ServerKey, orders: &mut [RadixCiphertext]) -> RadixCiphertext {
    let mut total_volume = server_key.create_trivial_zero_radix(NUMBER_OF_BLOCKS);
    for order in orders {
        server_key.smart_add_assign(&mut total_volume, order);
    }
    total_volume
}

fn fill_orders(
    server_key: &ServerKey,
    orders: &mut [RadixCiphertext],
    total_volume: RadixCiphertext,
) {
    let mut volume_left_to_transact = total_volume;
    for order in orders {
        let mut filled_amount = server_key.smart_min(&mut volume_left_to_transact, order);
        server_key.smart_sub_assign(&mut volume_left_to_transact, &mut filled_amount);
        *order = filled_amount;
    }
}

/// FHE implementation of the volume matching algorithm.
///
/// Matches the given encrypted [sell_orders] with encrypted [buy_orders] using the given
/// [server_key]. The amount of the orders that are successfully filled is written over the original
/// order count.
pub fn volume_match(
    sell_orders: &mut [RadixCiphertext],
    buy_orders: &mut [RadixCiphertext],
    server_key: &ServerKey,
) {
    println!("Calculating total sell and buy volumes...");
    let time = Instant::now();

    let mut total_sell_volume = vector_sum(server_key, sell_orders);
    let mut total_buy_volume = vector_sum(server_key, buy_orders);

    println!(
        "Total sell and buy volumes are calculated in {:?}",
        time.elapsed()
    );

    println!("Calculating total volume to be matched...");
    let time = Instant::now();
    let total_volume = server_key.smart_min(&mut total_sell_volume, &mut total_buy_volume);
    println!(
        "Calculated total volume to be matched in {:?}",
        time.elapsed()
    );

    println!("Filling orders...");
    let time = Instant::now();
    fill_orders(server_key, sell_orders, total_volume.clone());
    fill_orders(server_key, buy_orders, total_volume);
    println!("Filled orders in {:?}", time.elapsed());
}

pub fn tester(
    client_key: &ClientKey,
    server_key: &ServerKey,
    input_sell_orders: &[u16],
    input_buy_orders: &[u16],
    expected_filled_sells: &[u16],
    expected_filled_buys: &[u16],
    fhe_function: fn(&mut [RadixCiphertext], &mut [RadixCiphertext], &ServerKey),
) {
    let encrypt = |pt: u16| client_key.encrypt_radix(pt as u64, NUMBER_OF_BLOCKS);

    let mut encrypted_sell_orders = input_sell_orders
        .iter()
        .cloned()
        .map(encrypt)
        .collect::<Vec<RadixCiphertext>>();
    let mut encrypted_buy_orders = input_buy_orders
        .iter()
        .cloned()
        .map(encrypt)
        .collect::<Vec<RadixCiphertext>>();

    println!("Running FHE implementation...");
    let time = Instant::now();
    fhe_function(
        &mut encrypted_sell_orders,
        &mut encrypted_buy_orders,
        server_key,
    );
    println!("Ran FHE implementation in {:?}", time.elapsed());

    let decrypt = |ct| client_key.decrypt_radix::<u64>(ct) as u16;

    let decrypted_filled_sells: Vec<u16> = encrypted_sell_orders.iter().map(decrypt).collect();
    let decrypted_filled_buys: Vec<u16> = encrypted_buy_orders.iter().map(decrypt).collect();

    assert_eq!(decrypted_filled_sells, expected_filled_sells);
    assert_eq!(decrypted_filled_buys, expected_filled_buys);
}
