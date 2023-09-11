use std::time::Instant;

use rayon::prelude::*;

use tfhe::integer::ciphertext::RadixCiphertext;
use tfhe::integer::ServerKey;

use crate::NUMBER_OF_BLOCKS;

fn compute_prefix_sum(server_key: &ServerKey, arr: &[RadixCiphertext]) -> Vec<RadixCiphertext> {
    if arr.is_empty() {
        return arr.to_vec();
    }
    let mut prefix_sum: Vec<RadixCiphertext> = (0..arr.len().next_power_of_two())
        .into_par_iter()
        .map(|i| {
            if i < arr.len() {
                arr[i].clone()
            } else {
                server_key.create_trivial_zero_radix(NUMBER_OF_BLOCKS)
            }
        })
        .collect();
    for d in 0..prefix_sum.len().ilog2() {
        prefix_sum
            .par_chunks_exact_mut(2_usize.pow(d + 1))
            .for_each(move |chunk| {
                let length = chunk.len();
                let mut left = chunk.get((length - 1) / 2).unwrap().clone();
                server_key.smart_add_assign_parallelized(chunk.last_mut().unwrap(), &mut left)
            });
    }
    let last = prefix_sum.last().unwrap().clone();
    *prefix_sum.last_mut().unwrap() = server_key.create_trivial_zero_radix(NUMBER_OF_BLOCKS);
    for d in (0..prefix_sum.len().ilog2()).rev() {
        prefix_sum
            .par_chunks_exact_mut(2_usize.pow(d + 1))
            .for_each(move |chunk| {
                let length = chunk.len();
                let temp = chunk.last().unwrap().clone();
                let mut mid = chunk.get((length - 1) / 2).unwrap().clone();
                server_key.smart_add_assign_parallelized(chunk.last_mut().unwrap(), &mut mid);
                chunk[(length - 1) / 2] = temp;
            });
    }
    prefix_sum.push(last);
    prefix_sum[1..=arr.len()].to_vec()
}

fn fill_orders(
    server_key: &ServerKey,
    total_orders: &RadixCiphertext,
    orders: &mut [RadixCiphertext],
    prefix_sum_arr: &[RadixCiphertext],
) {
    orders
        .into_par_iter()
        .enumerate()
        .for_each(move |(i, order)| {
            server_key.smart_add_assign_parallelized(
                order,
                &mut server_key.smart_mul_parallelized(
                    &mut server_key
                        .smart_ge_parallelized(&mut order.clone(), &mut total_orders.clone()),
                    &mut server_key.smart_sub_parallelized(
                        &mut server_key.smart_sub_parallelized(
                            &mut total_orders.clone(),
                            &mut server_key.smart_min_parallelized(
                                &mut total_orders.clone(),
                                &mut prefix_sum_arr
                                    .get(i - 1)
                                    .unwrap_or(
                                        &server_key.create_trivial_zero_radix(NUMBER_OF_BLOCKS),
                                    )
                                    .clone(),
                            ),
                        ),
                        &mut order.clone(),
                    ),
                ),
            );
        });
}

/// FHE implementation of the volume matching algorithm.
///
/// In this function, the implemented algorithm is modified to utilize more concurrency.
///
/// Matches the given encrypted [sell_orders] with encrypted [buy_orders] using the given
/// [server_key]. The amount of the orders that are successfully filled is written over the original
/// order count.
pub fn volume_match(
    sell_orders: &mut [RadixCiphertext],
    buy_orders: &mut [RadixCiphertext],
    server_key: &ServerKey,
) {
    println!("Creating prefix sum arrays...");
    let time = Instant::now();
    let (prefix_sum_sell_orders, prefix_sum_buy_orders) = rayon::join(
        || compute_prefix_sum(server_key, sell_orders),
        || compute_prefix_sum(server_key, buy_orders),
    );
    println!("Created prefix sum arrays in {:?}", time.elapsed());

    let zero = server_key.create_trivial_zero_radix(NUMBER_OF_BLOCKS);

    let total_buy_orders = prefix_sum_buy_orders.last().unwrap_or(&zero);

    let total_sell_orders = prefix_sum_sell_orders.last().unwrap_or(&zero);

    println!("Matching orders...");
    let time = Instant::now();
    rayon::join(
        || {
            fill_orders(
                server_key,
                total_sell_orders,
                buy_orders,
                &prefix_sum_buy_orders,
            )
        },
        || {
            fill_orders(
                server_key,
                total_buy_orders,
                sell_orders,
                &prefix_sum_sell_orders,
            )
        },
    );
    println!("Matched orders in {:?}", time.elapsed());
}
