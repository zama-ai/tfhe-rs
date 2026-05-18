mod cli;
mod dump;
mod parse;

use benchmark_spec::BenchmarkMetric;
use clap::Parser;
use cli::Cli;
use dump::{append_points, write_series};
use parse::{ParseOutcome, parse_key_gen_time, parse_object_sizes, recursive_parse};
use std::process::ExitCode;
use tfhe_benchmark_parser::model::{Point, Series};

fn run_parse(args: &Cli) -> anyhow::Result<ParseOutcome> {
    if args.object_sizes {
        println!("Parsing key sizes results... ");
        return parse_object_sizes(&args.input_results_file, args.backend);
    }

    if args.key_gen {
        println!("Parsing key generation time results... ");
        return parse_key_gen_time(&args.input_results_file, args.backend);
    }

    println!("Parsing benchmark results... ");
    if args.bench_type == BenchmarkMetric::Throughput {
        println!("Throughput computation enabled");
    }

    recursive_parse(
        &args.input_results_file,
        args.bench_type,
        args.walk_subdirs,
        &args.name_suffix,
        args.backend,
    )
}

fn write_output(args: &Cli, points: Vec<Point>) -> anyhow::Result<()> {
    if args.append_results {
        append_points(points, &args.output_file)
    } else {
        let series = Series {
            database: args.database.clone(),
            hardware: args.hardware.clone(),
            project_version: args.project_version.clone(),
            branch: args.branch.clone(),
            insert_date: args.bench_date.clone(),
            commit_date: args.commit_date.clone(),
            points,
        };
        write_series(&series, &args.output_file)
    }
}

fn main() -> ExitCode {
    let args = Cli::parse();

    let outcome = match run_parse(&args) {
        Ok(outcome) => outcome,
        Err(err) => {
            eprintln!("Error: {err:#}");
            return ExitCode::from(1);
        }
    };

    println!("Parsing results done");
    println!(
        "Dump parsed results into '{}' ... ",
        args.output_file.display()
    );

    if let Err(err) = write_output(&args, outcome.points) {
        eprintln!("Error: {err:#}");
        return ExitCode::from(1);
    }

    println!("Done");

    if !outcome.failures.is_empty() {
        println!("Parsing failed for some results");
        println!("-------------------------------");
        for failure in &outcome.failures {
            println!("[{}] {}", failure.source, failure.error);
        }
        return ExitCode::from(1);
    }

    ExitCode::SUCCESS
}
