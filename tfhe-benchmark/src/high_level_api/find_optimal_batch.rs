use crate::high_level_api::bench_wait::BenchWait;
use crate::high_level_api::benchmark_op::BenchmarkOp;
use cpu_time::ProcessTime;
use criterion::black_box;
use rand::thread_rng;
use rayon::prelude::*;
use std::time::{Duration, Instant};
use tfhe::prelude::FheWait;
use tfhe::ClientKey;

struct MeasureConfig {
    pub target_ratio: f64,
    pub long_target_ratio: f64,
    pub starting_batch_size: usize,
    pub minimum_time_per_batch: Duration,
    pub duration_threshold_for_long_test: Duration,
}

impl MeasureConfig {
    pub fn default() -> Self {
        Self {
            target_ratio: 0.95,
            long_target_ratio: 0.80,
            starting_batch_size: 8,
            minimum_time_per_batch: Duration::from_secs(3),
            duration_threshold_for_long_test: Duration::from_secs(30),
        }
    }
}

#[inline(never)]
fn measure_batch<FheType, Op>(
    op: &Op,
    client_key: &ClientKey,
    batch: usize,
    minimum_time_per_batch: Duration,
) -> (f64, Duration)
where
    Op: BenchmarkOp<FheType> + Sync,
    FheType: FheWait + Send + Sync,
{
    let inputs = (0..batch)
        .into_par_iter()
        .map(|_| op.setup_inputs(client_key, &mut thread_rng()))
        .collect::<Vec<_>>();

    let run = || {
        inputs.par_iter().take(batch).for_each(|input| {
            let res = op.execute(input);
            res.wait_bench();
            black_box(res);
        });
    };

    // The method to compute CPU usage is based on the ratio between CPU time and wall-clock time.
    // During the function’s execution, this allows us to determine the optimal batch size.
    let cpu_start = ProcessTime::now();
    let wall_start = Instant::now();
    // At least run for 3 seconds (like warmup time of criterion) to get a stable measurement,
    // especially for smaller batches like add or gt for example
    while wall_start.elapsed() < minimum_time_per_batch {
        run();
    }
    let wall = wall_start.elapsed();
    let cpu = cpu_start.elapsed();

    (cpu.as_secs_f64() / wall.as_secs_f64(), wall)
}

#[inline(never)]
pub fn find_optimal_batch<FheType, Op>(op: &Op, client_key: &ClientKey) -> usize
where
    Op: BenchmarkOp<FheType> + Sync,
    FheType: FheWait + Send + Sync,
{
    let cores = num_cpus::get() as f64;
    let measure_config = MeasureConfig::default();

    // We multiply by cores because we don't divide the ratio between CPU time and WALL time by the
    // number of cores to have a real ratio
    let target = cores * measure_config.target_ratio;
    let long_target = cores * measure_config.long_target_ratio;

    let mut low;
    let mut high = measure_config.starting_batch_size;
    let mut last_usage = 0.0;

    loop {
        let (usage, duration) =
            measure_batch(op, client_key, high, measure_config.minimum_time_per_batch);

        println!(
            "Batch {:>4} → {:.2}% CPU in {:?}",
            high,
            (usage / cores) * 100.0,
            duration
        );

        if usage >= target {
            return high;
        }

        let improvement = (usage - last_usage).abs() / last_usage;
        if improvement < 0.05
            && duration >= measure_config.duration_threshold_for_long_test
            && last_usage > long_target
        {
            return high;
        }

        low = high;
        last_usage = usage;
        high *= 2;

        if high > 131072 {
            break;
        }
    }
    low
}
