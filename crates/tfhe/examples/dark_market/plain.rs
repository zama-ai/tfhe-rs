use std::time::Instant;

fn fill_orders(orders: &mut [u16], total_volume: u16) {
    let mut volume_left_to_transact = total_volume;
    for order in orders {
        let filled_amount = std::cmp::min(volume_left_to_transact, *order);
        *order = filled_amount;
        volume_left_to_transact -= filled_amount;
    }
}

/// Plain implementation of the volume matching algorithm.
///
/// Matches the given [sell_orders] with [buy_orders].
/// The amount of the orders that are successfully filled is written over the original order count.
pub fn volume_match(sell_orders: &mut [u16], buy_orders: &mut [u16]) {
    let total_sell_volume: u16 = sell_orders.iter().sum();
    let total_buy_volume: u16 = buy_orders.iter().sum();

    let total_volume = std::cmp::min(total_buy_volume, total_sell_volume);

    fill_orders(sell_orders, total_volume);
    fill_orders(buy_orders, total_volume);
}

pub fn tester(
    input_sell_orders: &[u16],
    input_buy_orders: &[u16],
    expected_filled_sells: &[u16],
    expected_filled_buys: &[u16],
    function: fn(&mut [u16], &mut [u16]),
) {
    let mut sell_orders = input_sell_orders.to_vec();
    let mut buy_orders = input_buy_orders.to_vec();

    println!("Running plain implementation...");
    let time = Instant::now();
    function(&mut sell_orders, &mut buy_orders);
    println!("Ran plain implementation in {:?}", time.elapsed());

    assert_eq!(sell_orders, expected_filled_sells);
    assert_eq!(buy_orders, expected_filled_buys);
}
