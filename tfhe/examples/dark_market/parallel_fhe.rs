use std::time::Instant;

use rayon::prelude::*;

use tfhe::integer::ciphertext::RadixCiphertext;
use tfhe::integer::ServerKey;

use crate::NUMBER_OF_BLOCKS;

// Calculate the element sum of the given vector in parallel
fn vector_sum(server_key: &ServerKey, orders: Vec<RadixCiphertext>) -> RadixCiphertext {
    orders.into_par_iter().reduce(
        || server_key.create_trivial_zero_radix(NUMBER_OF_BLOCKS),
        |mut acc: RadixCiphertext, mut ele: RadixCiphertext| {
            server_key.smart_add_parallelized(&mut acc, &mut ele)
        },
    )
}

fn fill_orders(
    server_key: &ServerKey,
    orders: &mut [RadixCiphertext],
    total_volume: RadixCiphertext,
) {
    let mut volume_left_to_transact = total_volume;
    for order in orders {
        let mut filled_amount =
            server_key.smart_min_parallelized(&mut volume_left_to_transact, order);
        server_key.smart_sub_assign_parallelized(&mut volume_left_to_transact, &mut filled_amount);
        *order = filled_amount;
    }
}

/// FHE implementation of the volume matching algorithm.
///
/// This version of the algorithm utilizes parallelization to speed up the computation.
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
    // Total sell and buy volumes can be calculated in parallel because they have no dependency on
    // each other.
    let (mut total_sell_volume, mut total_buy_volume) = rayon::join(
        || vector_sum(server_key, sell_orders.to_owned()),
        || vector_sum(server_key, buy_orders.to_owned()),
    );
    println!(
        "Total sell and buy volumes are calculated in {:?}",
        time.elapsed()
    );

    println!("Calculating total volume to be matched...");
    let time = Instant::now();
    let total_volume =
        server_key.smart_min_parallelized(&mut total_sell_volume, &mut total_buy_volume);
    println!(
        "Calculated total volume to be matched in {:?}",
        time.elapsed()
    );

    println!("Filling orders...");
    let time = Instant::now();
    rayon::join(
        || fill_orders(server_key, sell_orders, total_volume.clone()),
        || fill_orders(server_key, buy_orders, total_volume.clone()),
    );
    println!("Filled orders in {:?}", time.elapsed());
}
