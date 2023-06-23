# Dark Market Tutorial

In this tutorial, we are going to build a dark market application using TFHE-rs. A dark market is a marketplace where
buy and sell orders are not visible to the public before they are filled. Different algorithms aim to
solve this problem, we are going to implement the algorithm defined [in this paper](https://eprint.iacr.org/2022/923.pdf) with TFHE-rs.

We will first implement the algorithm in plain Rust and then we will see how to use TFHE-rs to
implement the same algorithm with FHE.

In addition, we will also implement a modified version of the algorithm that allows for more concurrent operations which
improves the performance in hardware where there are multiple cores.

## Specifications

#### Inputs:

* A list of sell orders where each sell order is only defined in volume terms, it is assumed that the price is fetched
  from a different source.
* A list of buy orders where each buy order is only defined in volume terms, it is assumed that the price is fetched
  from a different source.

#### Input constraints:

* The sell and buy orders are within the range [1,100].
* The maximum number of sell and buy orders is 500, respectively.

#### Outputs:

There is no output returned at the end of the algorithm. Instead, the algorithm makes changes on the given input lists.
The number of filled orders is written over the original order count in the respective lists. If it is not possible to
fill the orders, the order count is set to zero.

#### Example input and output:

##### Example 1:

|        | Sell               | Buy       |
|--------|--------------------|-----------|
| Input  | [ 5, 12, 7, 4, 3 ] | [ 19, 2 ] |
| Output | [ 5, 12, 4, 0, 0 ] | [ 19, 2 ] |

Last three indices of the filled sell orders are zero because there is no buy orders to match them.

##### Example 2:

|        | Sell              | Buy                  |
|--------|-------------------|----------------------|
| Input  | [ 3, 1, 1, 4, 2 ] | [ 5, 3, 3, 2, 4, 1 ] |
| Output | [ 3, 1, 1, 4, 2 ] | [ 5, 3, 3, 0, 0, 0 ] |

Last three indices of the filled buy orders are zero because there is no sell orders to match them.

## Plain Implementation

1. Calculate the total sell volume and the total buy volume.

```rust
let total_sell_volume: u16 = sell_orders.iter().sum();
let total_buy_volume: u16 = buy_orders.iter().sum();
```

2. Find the total volume that will be transacted. In the paper, this amount is calculated with the formula:

```
(total_sell_volume > total_buy_volume) * (total_buy_volume − total_sell_volume) + total_sell_volume
```

When closely observed, we can see that this formula can be replaced with the `min` function. Therefore, we calculate this
value by taking the minimum of the total sell volume and the total buy volume.

```rust
let total_volume = std::cmp::min(total_buy_volume, total_sell_volume);
```

3. Beginning with the first item, start filling the sell orders one by one. We apply the `min` function replacement also
   here.

```rust
let mut volume_left_to_transact = total_volume;
for sell_order in sell_orders.iter_mut() {
    let filled_amount = std::cmp::min(volume_left_to_transact, *sell_order);
    *sell_order = filled_amount;
    volume_left_to_transact -= filled_amount;
}
```

The number of orders that are filled is indicated by modifying the input list. For example, if the first sell order is
1000 and the total volume is 500, then the first sell order will be modified to 500 and the second sell order will be
modified to 0.

4. Do the fill operation also for the buy orders.

```rust
let mut volume_left_to_transact = total_volume;
for buy_order in buy_orders.iter_mut() {
    let filled_amount = std::cmp::min(volume_left_to_transact, *buy_order);
    *buy_order = filled_amount;
    volume_left_to_transact -= filled_amount;
}
```

#### The complete algorithm in plain Rust:

```rust
fn volume_match_plain(sell_orders: &mut Vec<u16>, buy_orders: &mut Vec<u16>) {
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
```

## FHE Implementation

For the FHE implementation, we first start with finding the right bit size for our algorithm to work without
overflows.

The variables that are declared in the algorithm and their maximum values are described in the table below:

| Variable                | Maximum Value | Bit Size |
|-------------------------|---------------|----------|
| total_sell_volume       | 50000         | 16       |
| total_buy_volume        | 50000         | 16       |
| total_volume            | 50000         | 16       |
| volume_left_to_transact | 50000         | 16       |
| sell_order              | 100           | 7        |
| buy_order               | 100           | 7        |

As we can observe from the table, we need **16 bits of message space** to be able to run the algorithm without
overflows. TFHE-rs provides different presets for the different bit sizes. Since we need 16 bits of message, we are
going to use the `integer` module to implement the algorithm.

Here are the input types of our algorithm:

* `sell_orders` is of type `Vec<tfhe::integer::RadixCipherText>`
* `buy_orders` is of type `Vec<tfhe::integer::RadixCipherText>`
* `server_key` is of type `tfhe::integer::ServerKey`

Now, we can start implementing the algorithm with FHE:

1. Calculate the total sell volume and the total buy volume.

```rust
let mut total_sell_volume = server_key.create_trivial_zero_radix(NUMBER_OF_BLOCKS);
for sell_order in sell_orders.iter_mut() {
    server_key.smart_add_assign(&mut total_sell_volume, sell_order);
}

let mut total_buy_volume = server_key.create_trivial_zero_radix(NUMBER_OF_BLOCKS);
for buy_order in buy_orders.iter_mut() {
    server_key.smart_add_assign(&mut total_buy_volume, buy_order);
}
```

2. Find the total volume that will be transacted by taking the minimum of the total sell volume and the total buy
   volume.

```rust
let total_volume = server_key.smart_min(&mut total_sell_volume, &mut total_buy_volume);
```

3. Beginning with the first item, start filling the sell and buy orders one by one. We can create `fill_orders` closure to 
reduce code duplication since the code for filling buy orders and sell orders are the same.

```rust
let fill_orders = |orders: &mut [RadixCiphertext]| {
    let mut volume_left_to_transact = total_volume.clone();
    for mut order in orders.iter_mut() {
        let mut filled_amount = server_key.smart_min(&mut volume_left_to_transact, &mut order);
        server_key.smart_sub_assign(&mut volume_left_to_transact, &mut filled_amount);
        *order = filled_amount;
    }
};

fill_orders(sell_orders);
fill_orders(buy_orders);
```

#### The complete algorithm in TFHE-rs:

```rust
const NUMBER_OF_BLOCKS: usize = 8;

fn volume_match_fhe(
    sell_orders: &mut [RadixCiphertext],
    buy_orders: &mut [RadixCiphertext],
    server_key: &ServerKey,
) {
    let mut total_sell_volume = server_key.create_trivial_zero_radix(NUMBER_OF_BLOCKS);
    for sell_order in sell_orders.iter_mut() {
        server_key.smart_add_assign(&mut total_sell_volume, sell_order);
    }

    let mut total_buy_volume = server_key.create_trivial_zero_radix(NUMBER_OF_BLOCKS);
    for buy_order in buy_orders.iter_mut() {
        server_key.smart_add_assign(&mut total_buy_volume, buy_order);
    }

    let total_volume = server_key.smart_min(&mut total_sell_volume, &mut total_buy_volume);

    let fill_orders = |orders: &mut [RadixCiphertext]| {
        let mut volume_left_to_transact = total_volume.clone();
        for mut order in orders.iter_mut() {
            let mut filled_amount = server_key.smart_min(&mut volume_left_to_transact, &mut order);
            server_key.smart_sub_assign(&mut volume_left_to_transact, &mut filled_amount);
            *order = filled_amount;
        }
    };

    fill_orders(sell_orders);
    fill_orders(buy_orders);
}

```

### Optimizing the implementation

* TFHE-rs provides parallelized implementations of the operations. We can use these parallelized
  implementations to speed up the algorithm. For example, we can use `smart_add_assign_parallelized` instead of 
  `smart_add_assign`.

* We can parallelize vector sum with Rayon and `reduce` operation.
```rust
let parallel_vector_sum = |vec: &mut [RadixCiphertext]| {
    vec.to_vec().into_par_iter().reduce(
        || server_key.create_trivial_zero_radix(NUMBER_OF_BLOCKS),
        |mut acc: RadixCiphertext, mut ele: RadixCiphertext| { 
            server_key.smart_add_parallelized(&mut acc, &mut ele)
        },
    )
};
```

* We can run vector summation on `buy_orders` and `sell_orders` in parallel since these operations do not depend on each other.
```rust
let (mut total_sell_volume, mut total_buy_volume) =
    rayon::join(|| vector_sum(sell_orders), || vector_sum(buy_orders));
```

* We can match sell and buy orders in parallel since the matching does not depend on each other.
```rust
rayon::join(|| fill_orders(sell_orders), || fill_orders(buy_orders));
```

#### Optimized algorithm
```rust
fn volume_match_fhe_parallelized(
    sell_orders: &mut [RadixCiphertext],
    buy_orders: &mut [RadixCiphertext],
    server_key: &ServerKey,
) {
    let parallel_vector_sum = |vec: &mut [RadixCiphertext]| {
        vec.to_vec().into_par_iter().reduce(
            || server_key.create_trivial_zero_radix(NUMBER_OF_BLOCKS),
            |mut acc: RadixCiphertext, mut ele: RadixCiphertext| {
                server_key.smart_add_parallelized(&mut acc, &mut ele)
            },
        )
    };

    let (mut total_sell_volume, mut total_buy_volume) = rayon::join(
        || parallel_vector_sum(sell_orders),
        || parallel_vector_sum(buy_orders),
    );

    let total_volume =
        server_key.smart_min_parallelized(&mut total_sell_volume, &mut total_buy_volume);

    let fill_orders = |orders: &mut [RadixCiphertext]| {
        let mut volume_left_to_transact = total_volume.clone();
        for mut order in orders.iter_mut() {
            let mut filled_amount =
                server_key.smart_min_parallelized(&mut volume_left_to_transact, &mut order);
            server_key
                .smart_sub_assign_parallelized(&mut volume_left_to_transact, &mut filled_amount);
            *order = filled_amount;
        }
    };
    
    rayon::join(|| fill_orders(sell_orders), || fill_orders(buy_orders));
}
```

## Modified Algorithm

When observed closely, there is only a small amount of concurrency introduced in the `fill_orders` part of the algorithm.
The reason is that the `volume_left_to_transact` is shared between all the orders and should be modified sequentially. 
This means that the orders cannot be filled in parallel. If we can somehow remove this dependency, we can fill the orders in parallel.

In order to do so, we closely observe the function of `volume_left_to_transact` variable in the algorithm. We can see that it is being used to check whether we can fill the current order or not.
Instead of subtracting the current order value from `volume_left_to_transact` in each loop, we can add this value to the next order
index and check the availability by comparing the current order value with the total volume. If the current order value
(now representing the sum of values before this order plus this order) is smaller than the total number of matching orders,
we can safely fill all the orders and continue the loop. If not, we should partially fill the orders with what is left from
matching orders. 

We will call the new list the "prefix sum" of the array. 

The new version for the plain `fill_orders` is as follows:
```rust
let fill_orders = |orders: &mut [u64], prefix_sum: &[u64], total_orders: u64|{
    orders.iter().for_each(|order : &mut u64| {
        if (total_orders >= prefix_sum[i]) {
            continue;
        } else if total_orders >= prefix_sum.get(i-1).unwrap_or(0) {
            *order = total_orders - prefix_sum.get(i-1).unwrap_or(0);
        } else {
            *order = 0;
        }
    });
};
```

To write this new function we need transform the conditional code into a mathematical expression since FHE does not support conditional operations.
```rust

let fill_orders = |orders: &mut [u64], prefix_sum: &[u64], total_orders: u64| {
    orders.iter().for_each(|order| : &mut){
        *order = *order + ((total_orders >= prefix_sum - std::cmp::min(total_orders, prefix_sum.get(i - 1).unwrap_or(&0).clone()) - *order);
    }
};
```

New `fill_order` function requires a prefix sum array. We are going to calculate this prefix sum array in parallel 
with the algorithm described [here](https://developer.nvidia.com/gpugems/gpugems3/part-vi-gpu-computing/chapter-39-parallel-prefix-sum-scan-cuda).

The sample code in the paper is written in CUDA. When we try to implement the algorithm in Rust we see that the compiler does not allow us to do so.
The reason for that is while the algorithm does not access the same array element in any of the threads(the index calculations using `d` and `k` values never overlap), 
Rust compiler cannot understand this and does not let us share the same array between threads. 
So we modify how the algorithm is implemented, but we don't change the algorithm itself.

Here is the modified version of the algorithm in TFHE-rs:
```rust
fn volume_match_fhe_modified(
    sell_orders: &mut [RadixCiphertext],
    buy_orders: &mut [RadixCiphertext],
    server_key: &ServerKey,
) {
    let compute_prefix_sum = |arr: &[RadixCiphertext]| {
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
        // Up sweep
        for d in 0..(prefix_sum.len().ilog2() as u32) {
            prefix_sum
                .par_chunks_exact_mut(2_usize.pow(d + 1))
                .for_each(move |chunk| {
                    let length = chunk.len();
                    let mut left = chunk.get((length - 1) / 2).unwrap().clone();
                    server_key.smart_add_assign_parallelized(chunk.last_mut().unwrap(), &mut left)
                });
        }
        // Down sweep
        let last = prefix_sum.last().unwrap().clone();
        *prefix_sum.last_mut().unwrap() = server_key.create_trivial_zero_radix(NUMBER_OF_BLOCKS);
        for d in (0..(prefix_sum.len().ilog2() as u32)).rev() {
            prefix_sum
                .par_chunks_exact_mut(2_usize.pow(d + 1))
                .for_each(move |chunk| {
                    let length = chunk.len();
                    let t = chunk.last().unwrap().clone();
                    let mut left = chunk.get((length - 1) / 2).unwrap().clone();
                    server_key.smart_add_assign_parallelized(chunk.last_mut().unwrap(), &mut left);
                    chunk[(length - 1) / 2] = t;
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

    let fill_orders = |total_orders: &RadixCiphertext,
                        orders: &mut [RadixCiphertext],
                        prefix_sum_arr: &[RadixCiphertext]| {
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
```

## Running the tutorial

The plain, FHE and parallel FHE implementations can be run by providing respective arguments as described below.

```bash
# Runs FHE implementation
cargo run --release --package tfhe --example dark_market --features="integer internal-keycache" -- fhe

# Runs parallelized FHE implementation
cargo run --release --package tfhe --example dark_market --features="integer internal-keycache" -- fhe-parallel

# Runs modified FHE implementation
cargo run --release --package tfhe --example dark_market --features="integer internal-keycache" -- fhe-modified

# Runs plain implementation
cargo run --release --package tfhe --example dark_market --features="integer internal-keycache" -- plain

# Multiple implementations can be run within same instance
cargo run --release --package tfhe --example dark_market --features="integer internal-keycache" -- plain fhe-parallel
```

## Conclusion

In this tutorial, we've learned how to implement the volume matching algorithm described [in this paper](https://eprint.iacr.org/2022/923.pdf) in plain Rust and in TFHE-rs. 
We've identified the right bit size for our problem at hand, used operations defined in `TFHE-rs`, and introduced concurrency to the algorithm to increase its performance.
