//! This program uses the concrete csprng to generate an infinite stream of random bytes on
//! the program stdout. It can also generate a fixed number of bytes by passing a value along the
//! optional argument `--bytes_total`. For testing purpose.
use clap::{value_parser, Arg, Command};
#[cfg(feature = "generator_x86_64_aesni")]
use tfhe_csprng::generators::AesniRandomGenerator as ActivatedRandomGenerator;
#[cfg(feature = "generator_aarch64_aes")]
use tfhe_csprng::generators::NeonAesRandomGenerator as ActivatedRandomGenerator;
use tfhe_csprng::generators::RandomGenerator;
#[cfg(all(
    not(feature = "generator_x86_64_aesni"),
    not(feature = "generator_aarch64_aes"),
    feature = "generator_fallback"
))]
use tfhe_csprng::generators::SoftwareRandomGenerator as ActivatedRandomGenerator;

use std::io::prelude::*;
use std::io::{stdout, StdoutLock};
#[cfg(target_os = "macos")]
use tfhe_csprng::seeders::AppleSecureEnclaveSeeder as ActivatedSeeder;
#[cfg(all(
    not(target_os = "macos"),
    target_arch = "x86_64",
    target_feature = "rdseed"
))]
use tfhe_csprng::seeders::RdseedSeeder as ActivatedSeeder;
use tfhe_csprng::seeders::Seeder;
#[cfg(all(
    not(target_os = "macos"),
    not(all(target_arch = "x86_64", target_feature = "rdseed")),
    target_family = "unix"
))]
use tfhe_csprng::seeders::UnixSeeder as ActivatedSeeder;

fn write_bytes(
    buffer: &mut [u8],
    generator: &mut ActivatedRandomGenerator,
    stdout: &mut StdoutLock<'_>,
) -> std::io::Result<()> {
    buffer.iter_mut().zip(generator).for_each(|(b, g)| *b = g);
    stdout.write_all(buffer)
}

fn infinite_bytes_generation(
    buffer: &mut [u8],
    generator: &mut ActivatedRandomGenerator,
    stdout: &mut StdoutLock<'_>,
) {
    while write_bytes(buffer, generator, stdout).is_ok() {}
}

fn bytes_generation(
    bytes_total: usize,
    buffer: &mut [u8],
    generator: &mut ActivatedRandomGenerator,
    stdout: &mut StdoutLock<'_>,
) {
    let quotient = bytes_total / buffer.len();
    let remaining = bytes_total % buffer.len();

    for _ in 0..quotient {
        write_bytes(buffer, generator, stdout).unwrap();
    }

    write_bytes(&mut buffer[0..remaining], generator, stdout).unwrap()
}

pub fn main() {
    let matches = Command::new(
        "Generate a stream of random numbers, specify no flags for infinite generation",
    )
    .arg(
        Arg::new("bytes_total")
            .short('b')
            .long("bytes_total")
            .value_parser(value_parser!(usize))
            .help("Total number of bytes that has to be generated"),
    )
    .get_matches();

    // Ugly hack to be able to use UnixSeeder
    #[cfg(all(
        not(target_os = "macos"),
        not(all(target_arch = "x86_64", target_feature = "rdseed")),
        target_family = "unix"
    ))]
    let new_seeder = || ActivatedSeeder::new(0);
    #[cfg(not(all(
        not(target_os = "macos"),
        not(all(target_arch = "x86_64", target_feature = "rdseed")),
        target_family = "unix"
    )))]
    let new_seeder = || ActivatedSeeder::new();

    let mut seeder = new_seeder();
    let seed = seeder.seed();
    // Don't print on std out
    eprintln!("seed={seed:?}");
    let mut generator = ActivatedRandomGenerator::new(seed);
    let stdout = stdout();
    let mut buffer = [0u8; 16];

    // lock stdout as there is a single thread running
    let mut stdout = stdout.lock();

    match matches.get_one::<usize>("bytes_total") {
        Some(&total) => {
            bytes_generation(total, &mut buffer, &mut generator, &mut stdout);
        }
        None => {
            infinite_bytes_generation(&mut buffer, &mut generator, &mut stdout);
        }
    };
}
