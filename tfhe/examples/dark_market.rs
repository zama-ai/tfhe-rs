use std::time::Instant;

use rayon::prelude::*;

use tfhe::integer::ciphertext::RadixCiphertextBig;
use tfhe::integer::keycache::IntegerKeyCache;
use tfhe::integer::ServerKey;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

/// The number of blocks to be used in the Radix.
const NUMBER_OF_BLOCKS: usize = 8;

/// Plain implementation of the volume matching algorithm.
///
/// Matches the given [sell_orders] with [buy_orders].
/// The amount of the orders that are successfully filled is written over the original order count.
fn volume_match_plain(sell_orders: &mut [u16], buy_orders: &mut [u16]) {
    let total_sell_volume: u16 = sell_orders.iter().sum();
    let total_buy_volume: u16 = buy_orders.iter().sum();

    let total_volume = std::cmp::min(total_buy_volume, total_sell_volume);

    let mut volume_left_to_transact = total_volume;
    for sell_order in sell_orders.iter_mut() {
        let filled_amount = std::cmp::min(volume_left_to_transact, *sell_order);
        *sell_order = filled_amount;
        volume_left_to_transact -= filled_amount;
    }

    let mut volume_left_to_transact = total_volume;
    for buy_order in buy_orders.iter_mut() {
        let filled_amount = std::cmp::min(volume_left_to_transact, *buy_order);
        *buy_order = filled_amount;
        volume_left_to_transact -= filled_amount;
    }
}

/// FHE implementation of the volume matching algorithm.
///
/// Matches the given encrypted [sell_orders] with encrypted [buy_orders] using the given [server_key].
/// The amount of the orders that are successfully filled is written over the original order count.
fn volume_match_fhe(
    sell_orders: &mut [RadixCiphertextBig],
    buy_orders: &mut [RadixCiphertextBig],
    server_key: &ServerKey,
) {
    println!("Calculating total sell and buy volumes...");
    let time = Instant::now();
    let mut total_sell_volume = server_key.create_trivial_zero_radix(NUMBER_OF_BLOCKS);
    for sell_order in sell_orders.iter_mut() {
        server_key.smart_add_assign(&mut total_sell_volume, sell_order);
    }

    let mut total_buy_volume = server_key.create_trivial_zero_radix(NUMBER_OF_BLOCKS);
    for buy_order in buy_orders.iter_mut() {
        server_key.smart_add_assign(&mut total_buy_volume, buy_order);
    }
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

    let fill_orders = |orders: &mut [RadixCiphertextBig]| {
        let mut volume_left_to_transact = total_volume.clone();
        for mut order in orders.iter_mut() {
            let mut filled_amount = server_key.smart_min(&mut volume_left_to_transact, &mut order);
            server_key.smart_sub_assign(&mut volume_left_to_transact, &mut filled_amount);
            *order = filled_amount;
        }
    };

    println!("Filling orders...");
    let time = Instant::now();
    fill_orders(sell_orders);
    fill_orders(buy_orders);
    println!("Filled orders in {:?}", time.elapsed());
}

/// FHE implementation of the volume matching algorithm.
///
/// This version of the algorithm utilizes parallelization to speed up the computation.
///
/// Matches the given encrypted [sell_orders] with encrypted [buy_orders] using the given [server_key].
/// The amount of the orders that are successfully filled is written over the original order count.
fn volume_match_fhe_parallelized(
    sell_orders: &mut [RadixCiphertextBig],
    buy_orders: &mut [RadixCiphertextBig],
    server_key: &ServerKey,
) {
    // Calculate the element sum of the given vector in parallel
    let parallel_vector_sum = |vec: &mut [RadixCiphertextBig]| {
        vec.to_vec().into_par_iter().reduce(
            || server_key.create_trivial_zero_radix(NUMBER_OF_BLOCKS),
            |mut acc: RadixCiphertextBig, mut ele: RadixCiphertextBig| {
                server_key.smart_add_parallelized(&mut acc, &mut ele)
            },
        )
    };

    println!("Calculating total sell and buy volumes...");
    let time = Instant::now();
    // Total sell and buy volumes can be calculated in parallel because they have no dependency on each other.
    let (mut total_sell_volume, mut total_buy_volume) = rayon::join(
        || parallel_vector_sum(sell_orders),
        || parallel_vector_sum(buy_orders),
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

    let fill_orders = |orders: &mut [RadixCiphertextBig]| {
        let mut volume_left_to_transact = total_volume.clone();
        for mut order in orders.iter_mut() {
            let mut filled_amount =
                server_key.smart_min_parallelized(&mut volume_left_to_transact, &mut order);
            server_key
                .smart_sub_assign_parallelized(&mut volume_left_to_transact, &mut filled_amount);
            *order = filled_amount;
        }
    };
    println!("Filling orders...");
    let time = Instant::now();
    rayon::join(|| fill_orders(sell_orders), || fill_orders(buy_orders));
    println!("Filled orders in {:?}", time.elapsed());
}

/// FHE implementation of the volume matching algorithm.
///
/// In this function, the implemented algorithm is modified to utilize more concurrency.
///
/// Matches the given encrypted [sell_orders] with encrypted [buy_orders] using the given [server_key].
/// The amount of the orders that are successfully filled is written over the original order count.
fn volume_match_fhe_modified(
    sell_orders: &mut [RadixCiphertextBig],
    buy_orders: &mut [RadixCiphertextBig],
    server_key: &ServerKey,
) {
    let compute_prefix_sum = |arr: &[RadixCiphertextBig]| {
        if arr.is_empty() {
            return arr.to_vec();
        }
        let mut prefix_sum: Vec<RadixCiphertextBig> = (0..arr.len().next_power_of_two())
            .into_par_iter()
            .map(|i| {
                if i < arr.len() {
                    arr[i].clone()
                } else {
                    server_key.create_trivial_zero_radix(NUMBER_OF_BLOCKS)
                }
            })
            .collect();
        for d in 0..(prefix_sum.len().ilog2() as u32) {
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
        for d in (0..(prefix_sum.len().ilog2() as u32)).rev() {
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
    };

    println!("Creating prefix sum arrays...");
    let time = Instant::now();
    let (prefix_sum_sell_orders, prefix_sum_buy_orders) = rayon::join(
        || compute_prefix_sum(sell_orders),
        || compute_prefix_sum(buy_orders),
    );
    println!("Created prefix sum arrays in {:?}", time.elapsed());

    let fill_orders = |total_orders: &RadixCiphertextBig,
                       orders: &mut [RadixCiphertextBig],
                       prefix_sum_arr: &[RadixCiphertextBig]| {
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
    };

    let total_buy_orders = &mut prefix_sum_buy_orders
        .last()
        .unwrap_or(&server_key.create_trivial_zero_radix(NUMBER_OF_BLOCKS))
        .clone();

    let total_sell_orders = &mut prefix_sum_sell_orders
        .last()
        .unwrap_or(&server_key.create_trivial_zero_radix(NUMBER_OF_BLOCKS))
        .clone();

    println!("Matching orders...");
    let time = Instant::now();
    rayon::join(
        || fill_orders(total_sell_orders, buy_orders, &prefix_sum_buy_orders),
        || fill_orders(total_buy_orders, sell_orders, &prefix_sum_sell_orders),
    );
    println!("Matched orders in {:?}", time.elapsed());
}

/// Runs the given [tester] function with the test cases for volume matching algorithm.
fn run_test_cases<F: Fn(&[u16], &[u16], &[u16], &[u16])>(tester: F) {
    println!("Testing empty sell orders...");
    tester(
        &vec![],
        &(1..11).map(|i| i).collect::<Vec<_>>(),
        &vec![],
        &(1..11).map(|_| 0).collect::<Vec<_>>(),
    );
    println!();

    println!("Testing empty buy orders...");
    tester(
        &(1..11).map(|i| i).collect::<Vec<_>>(),
        &vec![],
        &(1..11).map(|_| 0).collect::<Vec<_>>(),
        &vec![],
    );
    println!();

    println!("Testing exact matching of sell and buy orders...");
    tester(
        &(1..11).map(|i| i).collect::<Vec<_>>(),
        &(1..11).map(|i| i).collect::<Vec<_>>(),
        &(1..11).map(|i| i).collect::<Vec<_>>(),
        &(1..11).map(|i| i).collect::<Vec<_>>(),
    );
    println!();

    println!("Testing the case where there are more buy orders than sell orders...");
    tester(
        &(1..11).map(|_| 10).collect::<Vec<_>>(),
        &vec![200],
        &(1..11).map(|_| 10).collect::<Vec<_>>(),
        &vec![100],
    );
    println!();

    println!("Testing the case where there are more sell orders than buy orders...");
    tester(
        &vec![200],
        &(1..11).map(|_| 10).collect::<Vec<_>>(),
        &vec![100],
        &(1..11).map(|_| 10).collect::<Vec<_>>(),
    );
    println!();

    println!("Testing maximum input size for sell and buy orders...");
    tester(
        &(1..=500).map(|_| 100).collect::<Vec<_>>(),
        &(1..=500).map(|_| 100).collect::<Vec<_>>(),
        &(1..=500).map(|_| 100).collect::<Vec<_>>(),
        &(1..=500).map(|_| 100).collect::<Vec<_>>(),
    );
    println!();
}

/// Runs the test cases for the plain implementation of the volume matching algorithm.
fn test_volume_match_plain() {
    let tester = |input_sell_orders: &[u16],
                  input_buy_orders: &[u16],
                  expected_filled_sells: &[u16],
                  expected_filled_buys: &[u16]| {
        let mut sell_orders = input_sell_orders.to_vec();
        let mut buy_orders = input_buy_orders.to_vec();

        println!("Running plain implementation...");
        let time = Instant::now();
        volume_match_plain(&mut sell_orders, &mut buy_orders);
        println!("Ran plain implementation in {:?}", time.elapsed());

        assert_eq!(sell_orders, expected_filled_sells);
        assert_eq!(buy_orders, expected_filled_buys);
    };

    println!("Running test cases for the plain implementation");
    run_test_cases(tester);
}

/// Runs the test cases for the fhe implementation of the volume matching algorithm.
///
/// [parallelized] indicates whether the fhe implementation should be run in parallel.
fn test_volume_match_fhe(
    fhe_function: fn(&mut [RadixCiphertextBig], &mut [RadixCiphertextBig], &ServerKey),
) {
    let working_dir = std::env::current_dir().unwrap();
    std::env::set_current_dir(working_dir.join("tfhe")).unwrap();

    println!("Generating keys...");
    let time = Instant::now();
    let (client_key, server_key) = IntegerKeyCache.get_from_params(PARAM_MESSAGE_2_CARRY_2);
    println!("Keys generated in {:?}", time.elapsed());

    let tester = |input_sell_orders: &[u16],
                  input_buy_orders: &[u16],
                  expected_filled_sells: &[u16],
                  expected_filled_buys: &[u16]| {
        let mut encrypted_sell_orders = input_sell_orders
            .iter()
            .cloned()
            .map(|pt| client_key.encrypt_radix(pt as u64, NUMBER_OF_BLOCKS))
            .collect::<Vec<RadixCiphertextBig>>();
        let mut encrypted_buy_orders = input_buy_orders
            .iter()
            .cloned()
            .map(|pt| client_key.encrypt_radix(pt as u64, NUMBER_OF_BLOCKS))
            .collect::<Vec<RadixCiphertextBig>>();

        println!("Running FHE implementation...");
        let time = Instant::now();
        fhe_function(
            &mut encrypted_sell_orders,
            &mut encrypted_buy_orders,
            &server_key,
        );
        println!("Ran FHE implementation in {:?}", time.elapsed());

        let decrypted_filled_sells = encrypted_sell_orders
            .iter()
            .map(|ct| client_key.decrypt_radix::<u64, _>(ct) as u16)
            .collect::<Vec<u16>>();
        let decrypted_filled_buys = encrypted_buy_orders
            .iter()
            .map(|ct| client_key.decrypt_radix::<u64, _>(ct) as u16)
            .collect::<Vec<u16>>();

        assert_eq!(decrypted_filled_sells, expected_filled_sells);
        assert_eq!(decrypted_filled_buys, expected_filled_buys);
    };

    println!("Running test cases for the FHE implementation");
    run_test_cases(tester);
}

fn main() {
    for argument in std::env::args() {
        if argument == "fhe-modified" {
            println!("Running modified fhe version");
            test_volume_match_fhe(volume_match_fhe_modified);
            println!();
        }
        if argument == "fhe-parallel" {
            println!("Running parallelized fhe version");
            test_volume_match_fhe(volume_match_fhe_parallelized);
            println!();
        }
        if argument == "plain" {
            println!("Running plain version");
            test_volume_match_plain();
            println!();
        }
        if argument == "fhe" {
            println!("Running fhe version");
            test_volume_match_fhe(volume_match_fhe);
            println!();
        }
    }
}
