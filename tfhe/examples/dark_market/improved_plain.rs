fn compute_prefix_sum(arr: &[u16]) -> Vec<u16> {
    let mut sum = 0;
    arr.iter()
        .map(|a| {
            sum += a;
            sum
        })
        .collect()
}

fn fill_orders(total_orders: u16, orders: &mut [u16], prefix_sum_arr: &[u16]) {
    for (i, order) in orders.iter_mut().enumerate() {
        let previous_prefix_sum = if i == 0 { 0 } else { prefix_sum_arr[i - 1] };

        *order = (total_orders as i64 - previous_prefix_sum as i64)
            .max(0)
            .min(*order as i64) as u16;
    }
}

pub fn volume_match(sell_orders: &mut [u16], buy_orders: &mut [u16]) {
    let prefix_sum_sell_orders = compute_prefix_sum(sell_orders);

    let prefix_sum_buy_orders = compute_prefix_sum(buy_orders);

    let total_buy_orders = *prefix_sum_buy_orders.last().unwrap_or(&0);

    let total_sell_orders = *prefix_sum_sell_orders.last().unwrap_or(&0);

    fill_orders(total_sell_orders, buy_orders, &prefix_sum_buy_orders);
    fill_orders(total_buy_orders, sell_orders, &prefix_sum_sell_orders);
}
