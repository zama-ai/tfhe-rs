use std::time::Instant;

use tfhe::integer::ciphertext::RadixCiphertext;
use tfhe::integer::keycache::IntegerKeyCache;
use tfhe::integer::ServerKey;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

mod fhe;
mod improved_parallel_fhe;
mod parallel_fhe;
mod plain;

/// The number of blocks to be used in the Radix.
const NUMBER_OF_BLOCKS: usize = 8;

#[allow(clippy::type_complexity)]
fn test_cases() -> Vec<(String, (Vec<u16>, Vec<u16>, Vec<u16>, Vec<u16>))> {
    vec![
        (
            "empty sell orders".to_owned(),
            (vec![], (1..11).collect::<Vec<_>>(), vec![], vec![0; 10]),
        ),
        (
            "empty buy orders".to_owned(),
            ((1..11).collect::<Vec<_>>(), vec![], vec![0; 10], vec![]),
        ),
        (
            "exact matching of sell and buy orders".to_owned(),
            (
                (1..11).collect::<Vec<_>>(),
                (1..11).collect::<Vec<_>>(),
                (1..11).collect::<Vec<_>>(),
                (1..11).collect::<Vec<_>>(),
            ),
        ),
        (
            "a case where there are more buy orders than sell orders".to_owned(),
            (vec![10; 10], vec![200], vec![10; 10], vec![100]),
        ),
        (
            "a case where there are more sell orders than buy orders".to_owned(),
            (vec![200], vec![10; 10], vec![100], vec![10; 10]),
        ),
        (
            "maximum input size for sell and buy orders".to_owned(),
            (
                vec![100; 499],
                vec![100; 499],
                vec![100; 499],
                vec![100; 499],
            ),
        ),
    ]
}

/// Runs the given [tester] function with the test cases for volume matching algorithm.
fn run_test_cases(tester: impl Fn(&[u16], &[u16], &[u16], &[u16])) {
    for (test_name, test_case) in &test_cases() {
        println!("Testing {test_name}...");
        tester(&test_case.0, &test_case.1, &test_case.2, &test_case.3);
        println!();
    }
}

/// Runs the test cases for the fhe implementation of the volume matching algorithm.
///
/// [parallelized] indicates whether the fhe implementation should be run in parallel.
fn test_volume_match_fhe(
    fhe_function: fn(&mut [RadixCiphertext], &mut [RadixCiphertext], &ServerKey),
) {
    println!("Generating keys...");
    let time = Instant::now();
    let (client_key, server_key) = IntegerKeyCache.get_from_params(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    println!("Keys generated in {:?}", time.elapsed());

    println!("Running test cases for the FHE implementation");
    run_test_cases(|a, b, c, d| fhe::tester(&client_key, &server_key, a, b, c, d, fhe_function));
}

fn main() {
    for argument in std::env::args() {
        if argument == "plain" {
            println!("Running plain version");
            run_test_cases(plain::tester);
            println!();
        }
            println!();
        }
        if argument == "fhe" {
            println!("Running fhe version");
            test_volume_match_fhe(fhe::volume_match);
            println!();
        }
        if argument == "fhe-parallel" {
            println!("Running parallelized fhe version");
            test_volume_match_fhe(parallel_fhe::volume_match);
            println!();
        }
        if argument == "fhe-improved" {
            println!("Running improved parallelized fhe fhe version");
            test_volume_match_fhe(improved_parallel_fhe::volume_match);
            println!();
        }
    }
}
