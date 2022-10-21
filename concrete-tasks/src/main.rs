#[macro_use]
extern crate lazy_static;
use clap::{App, AppSettings, Arg};
use log::LevelFilter;
use simplelog::{ColorChoice, CombinedLogger, Config, TermLogger, TerminalMode};
use std::collections::HashMap;
use std::env::consts::OS;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;

mod build;
mod check;
mod chore;
mod doc;
mod test;
mod utils;

// -------------------------------------------------------------------------------------------------
// CONSTANTS
// -------------------------------------------------------------------------------------------------
lazy_static! {
    static ref DRY_RUN: AtomicBool = AtomicBool::new(false);
    static ref ROOT_DIR: PathBuf = utils::project_root();
    static ref ENV_TARGET_NATIVE: utils::Environment = {
        let mut env = HashMap::new();
        env.insert("RUSTFLAGS", "-Ctarget-cpu=native");
        env
    };
}

// -------------------------------------------------------------------------------------------------
// MACROS
// -------------------------------------------------------------------------------------------------

#[macro_export]
macro_rules! cmd {
    ($cmd: literal) => {
        $crate::utils::execute($cmd, None, Some(&*$crate::ROOT_DIR))
    };
    (<$env: ident> $cmd: literal) => {
        $crate::utils::execute($cmd, Some(&*$env), Some(&*$crate::ROOT_DIR))
    };
}

// -------------------------------------------------------------------------------------------------
// MAIN
// -------------------------------------------------------------------------------------------------

fn main() -> Result<(), std::io::Error> {
    // We check whether the current os is supported
    if !(OS == "linux" || OS == "macos") {
        panic!("Concrete tasks are only supported on linux and macos.")
    }

    // We parse the input args
    let matches = App::new("concrete-tasks")
        .about("Performs concrete plumbing tasks")
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .help("Prints debug messages"),
        )
        .arg(
            Arg::with_name("dry-run")
                .long("dry-run")
                .help("Do not execute the commands"),
        )
        .subcommand(App::new("test").about("Executes all available tests in native mode"))
        .subcommand(App::new("cov").about("Computes test coverage in native mode"))
        .subcommand(App::new("build").about("Builds the crates in all available mode"))
        .subcommand(App::new("check").about("Performs all the available checks"))
        .subcommand(App::new("test_toplevel").about("Tests the `concrete` crate in native mode"))
        .subcommand(App::new("test_crates").about("Tests all the crates in native mode"))
        .subcommand(
            App::new("test_and_cov_crates")
                .about("Compute tests coverage of all crates in native mode"),
        )
        .subcommand(App::new("test_book_boolean").about("Test the book for concrete-boolean"))
        .subcommand(App::new("build_debug_crates").about("Build all the crates in debug mode"))
        .subcommand(App::new("build_release_crates").about("Build all the crates in release mode"))
        .subcommand(App::new("build_simd_crates").about("Build all the crates in simd mode"))
        .subcommand(App::new("build_benches").about("Build the benchmarks in release mode"))
        .subcommand(App::new("check_doc").about("Checks that the doc compiles without warnings"))
        .subcommand(App::new("check_clippy").about("Checks that clippy runs without warnings"))
        .subcommand(App::new("check_fmt").about("Checks that rustfmt runs without warnings"))
        .subcommand(App::new("chore_format").about("Format the codebase with rustfmt"))
        .setting(AppSettings::ArgRequiredElseHelp)
        .get_matches();

    // We initialize the logger with proper verbosity
    let verb = if matches.is_present("verbose") {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    CombinedLogger::init(vec![TermLogger::new(
        verb,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )])
    .unwrap();

    // We set the dry-run mode if present
    if matches.is_present("dry-run") {
        DRY_RUN.store(true, Relaxed);
    }

    // We execute the task.
    if matches.subcommand_matches("test").is_some() {
        test::crates()?;
    }
    if matches.subcommand_matches("cov").is_some() {
        test::cov_crates()?;
    }
    if matches.subcommand_matches("build").is_some() {
        build::debug::benches()?;
        build::debug::crates()?;
        build::debug::doctests()?;
        build::debug::tests()?;
        build::release::benches()?;
        build::release::crates()?;
        build::release::doctests()?;
        build::release::tests()?;
        build::simd::benches()?;
        build::simd::crates()?;
        build::simd::doctests()?;
        build::simd::tests()?;
    }
    if matches.subcommand_matches("check").is_some() {
        check::doc()?;
        check::clippy()?;
        check::fmt()?;
    }
    if matches.subcommand_matches("test_toplevel").is_some() {
        test::toplevel()?;
    }
    if matches.subcommand_matches("test_crates").is_some() {
        test::crates()?;
    }
    if matches.subcommand_matches("test_and_cov_crates").is_some() {
        test::cov_crates()?;
    }
    if matches.subcommand_matches("test_book_boolean").is_some() {
        doc::test_book_boolean()?;
    }
    if matches.subcommand_matches("build_debug_crates").is_some() {
        build::debug::crates()?;
    }
    if matches.subcommand_matches("build_release_crates").is_some() {
        build::release::crates()?;
    }
    if matches.subcommand_matches("build_simd_crates").is_some() {
        build::simd::crates()?;
    }
    if matches.subcommand_matches("build_benches").is_some() {
        build::release::benches()?;
    }
    if matches.subcommand_matches("check_doc").is_some() {
        check::doc()?;
    }
    if matches.subcommand_matches("check_clippy").is_some() {
        check::clippy()?;
    }
    if matches.subcommand_matches("check_fmt").is_some() {
        check::fmt()?;
    }
    if matches.subcommand_matches("chore_format").is_some() {
        chore::format()?;
    }

    Ok(())
}
