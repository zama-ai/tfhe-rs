use criterion::Criterion;
use std::env;
use std::sync::OnceLock;
#[cfg(feature = "gpu")]
use tfhe::core_crypto::gpu::{get_number_of_gpus, get_number_of_sms};
#[cfg(feature = "integer")]
use tfhe::prelude::*;

pub use tfhe_benchmark_parser::{write_to_json, write_to_json_unchecked, OperatorType};

const FAST_BENCH_BIT_SIZES: [usize; 1] = [64];
#[cfg(not(feature = "gpu"))]
const BENCH_BIT_SIZES: [usize; 8] = [2, 8, 16, 32, 40, 64, 128, 256];
#[cfg(feature = "gpu")]
const BENCH_BIT_SIZES: [usize; 7] = [8, 16, 32, 40, 64, 128, 256];
const HPU_BENCH_BIT_SIZES: [usize; 5] = [8, 16, 32, 64, 128];
const MULTI_BIT_CPU_SIZES: [usize; 5] = [8, 16, 32, 40, 64];
const BENCH_BIT_SIZES_DOCUMENTATION: [usize; 5] = [8, 16, 32, 64, 128];

#[derive(Default)]
pub enum BitSizesSet {
    #[default]
    Fast,
    All,
    Documentation,
}

impl BitSizesSet {
    pub fn from_env() -> Result<Self, String> {
        let raw_value = env::var("__TFHE_RS_BENCH_BIT_SIZES_SET").unwrap_or("fast".to_string());
        match raw_value.to_lowercase().as_str() {
            "fast" => Ok(BitSizesSet::Fast),
            "all" => Ok(BitSizesSet::All),
            "documentation" => Ok(BitSizesSet::Documentation),
            _ => Err(format!("bit sizes set '{raw_value}' is not supported")),
        }
    }
}

/// User configuration in which benchmarks must be run.
#[derive(Default)]
pub struct EnvConfig {
    pub is_multi_bit: bool,
    pub bit_sizes_set: BitSizesSet,
}

impl EnvConfig {
    pub fn new() -> Self {
        let is_multi_bit = matches!(
            get_param_type(),
            ParamType::MultiBit | ParamType::MultiBitDocumentation
        );

        EnvConfig {
            is_multi_bit,
            bit_sizes_set: BitSizesSet::from_env().unwrap(),
        }
    }

    /// Get precisions values to benchmark.
    pub fn bit_sizes(&self) -> Vec<usize> {
        let bit_sizes_set = match self.bit_sizes_set {
            BitSizesSet::Fast => return FAST_BENCH_BIT_SIZES.to_vec(),
            BitSizesSet::All => BENCH_BIT_SIZES.to_vec(),
            BitSizesSet::Documentation => return BENCH_BIT_SIZES_DOCUMENTATION.to_vec(),
        };

        if self.is_multi_bit {
            if cfg!(feature = "gpu") {
                BENCH_BIT_SIZES.to_vec()
            } else {
                MULTI_BIT_CPU_SIZES.to_vec()
            }
        } else if cfg!(feature = "hpu") {
            HPU_BENCH_BIT_SIZES.to_vec()
        } else {
            bit_sizes_set
        }
    }
}

pub static PARAM_TYPE: OnceLock<ParamType> = OnceLock::new();

pub enum ParamType {
    Classical,
    MultiBit,
    // Variants dedicated to documentation illustration.
    ClassicalDocumentation,
    MultiBitDocumentation,
}

impl ParamType {
    pub fn from_env() -> Result<Self, String> {
        let raw_value = env::var("__TFHE_RS_PARAM_TYPE").unwrap_or("classical".to_string());
        match raw_value.to_lowercase().as_str() {
            "classical" => Ok(ParamType::Classical),
            "multi_bit" => Ok(ParamType::MultiBit),
            "classical_documentation" => Ok(ParamType::ClassicalDocumentation),
            "multi_bit_documentation" => Ok(ParamType::MultiBitDocumentation),
            _ => Err(format!("parameters type '{raw_value}' is not supported")),
        }
    }
}

pub fn get_param_type() -> &'static ParamType {
    PARAM_TYPE.get_or_init(|| ParamType::from_env().unwrap())
}

pub fn get_bench_gpu_instances() -> Option<usize> {
    env::var("__TFHE_RS_BENCH_GPU_PROCESS_COUNT").ok().map(|v| {
        v.parse::<usize>().unwrap_or_else(|_| {
            panic!("__TFHE_RS_BENCH_GPU_PROCESS_COUNT must be a positive integer, got '{v}'")
        })
    })
}

/// Multi-process barrier that ensures num_instances processes
/// start at the same time
#[cfg(target_os = "linux")]
pub fn bench_sync_barrier(num_instances: usize) {
    use std::ffi::CString;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    const BARRIER_TIMEOUT_SECS: u64 = 120;
    const MUTEX_NAME_PREFIX: &str = "tfhe_bench";

    // Three POSIX semaphores are used for synchronization
    // The first one is used to make sure the processes increment the
    // counter and get the value of the counter atomically .
    let sem_mutex = CString::new(format!("/{MUTEX_NAME_PREFIX}_mutex")).unwrap();
    let sem_arrive = CString::new(format!("/{MUTEX_NAME_PREFIX}_arrive")).unwrap();
    let sem_gate = CString::new(format!("/{MUTEX_NAME_PREFIX}_gate")).unwrap();

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let deadline_t = now + Duration::from_secs(BARRIER_TIMEOUT_SECS);
    let deadline = libc::timespec {
        tv_sec: deadline_t.as_secs() as libc::time_t,
        tv_nsec: deadline_t.subsec_nanos() as libc::c_long,
    };

    let open_sem = |name: &CString, init: u32| {
        let sem = unsafe { libc::sem_open(name.as_ptr(), libc::O_CREAT, 0o600u32, init) };
        assert!(
            sem != libc::SEM_FAILED,
            "sem_open({:?}) failed: {}",
            name,
            std::io::Error::last_os_error()
        );
        sem
    };

    let timed_wait = |sem: *mut libc::sem_t, label: &str| {
        let ret = unsafe { libc::sem_timedwait(sem, &deadline) };
        if ret != 0 {
            panic!(
                "bench_sync_barrier: timed out on '{label}' after {BARRIER_TIMEOUT_SECS}s \
                 (__TFHE_RS_BENCH_GPU_PROCESS_COUNT={num_instances}). \
                 If semaphores are stale from a prior crash, clean up with: \
                 rm -f /dev/shm/sem.{MUTEX_NAME_PREFIX}_*\n\
                 OS error: {}",
                std::io::Error::last_os_error()
            );
        }
    };

    let mutex = open_sem(&sem_mutex, 1);
    let arrive = open_sem(&sem_arrive, 0);
    let gate = open_sem(&sem_gate, 0);

    // Process 0 to arrive doesn't need to wait
    // Processes 1..N to arrive need to wait
    timed_wait(mutex, "mutex");
    // Each process posts to the arrive semaphore, incrementing its value
    unsafe { libc::sem_post(arrive) };
    // The last process to post to "arrive" will read a value equal to "num_instances"
    // The other processes read a lower value. "mutex" ensures
    // the post + get_value are atomic
    let mut count = 0i32;
    unsafe { libc::sem_getvalue(arrive, &mut count) };

    // Once a process has posted to arrive and got the value (atomic)
    // it allows the other processes to do the same
    unsafe { libc::sem_post(mutex) };

    // The last process reads the "num_instances" value from arrive.
    // it must then tell the others to continue work. if it doesn't
    // the other processes will time out at the "gate"
    if count as usize == num_instances {
        for _ in 0..num_instances {
            // Open the gate
            unsafe { libc::sem_post(gate) };
        }
    }

    // Every process waits at the gate. If it doesn't open in a certain time, then we panic
    timed_wait(gate, "gate");

    // Clean up
    unsafe {
        libc::sem_close(mutex);
        libc::sem_close(arrive);
        libc::sem_close(gate);
        libc::sem_unlink(sem_mutex.as_ptr());
        libc::sem_unlink(sem_arrive.as_ptr());
        libc::sem_unlink(sem_gate.as_ptr());
    }
}

/// Generate a number of threads to use to saturate current machine for throughput measurements.
pub fn throughput_num_threads(num_block: usize, op_pbs_count: u64) -> u64 {
    let ref_block_count = 32; // Represent a ciphertext of 64 bits for 2_2 parameters set
    let block_multiplicator = (ref_block_count as f64 / num_block as f64).ceil().min(1.0);
    // Some operations with a high serial workload (e.g. division) would yield an operation
    // loading value so low that the number of elements in the end wouldn't be meaningful.
    let minimum_loading = if num_block < 64 { 1.0 } else { 0.015 };

    #[cfg(feature = "gpu")]
    {
        let num_sms_per_gpu = get_number_of_sms();
        let total_num_sm = num_sms_per_gpu * get_number_of_gpus();

        let total_blocks_per_sm = 4u64; // Assume each SM can handle 4 blocks concurrently
        let min_num_waves = 4u64; //Enforce at least 4 waves in the GPU
        let block_factor = ((2.0f64 * num_block as f64) / 4.0f64).ceil() as u64;
        let elements_per_wave = total_blocks_per_sm * total_num_sm as u64 / block_factor;
        // We need to enable the new load for pbs benches and for sizes larger than 16 blocks in
        // demanding operations for the rest of operations we maintain a minimum of 200
        // elements
        let min_elements = if op_pbs_count == 1
            || (op_pbs_count > (num_block * num_block) as u64 && num_block >= 16)
        {
            elements_per_wave * min_num_waves
        } else {
            200u64
        };
        let operation_loading = ((total_num_sm as u64 / op_pbs_count) as f64).max(minimum_loading);
        let elements = (total_num_sm as f64 * block_multiplicator * operation_loading) as u64;
        elements.min(min_elements) // This threshold is useful for operation
                                   // with both a small number of
                                   // block and low PBs count.
    }
    #[cfg(not(any(feature = "gpu")))]
    {
        let num_threads = rayon::current_num_threads() as f64;
        let operation_loading = (num_threads / (op_pbs_count as f64)).max(minimum_loading);
        // Add 20% more to maximum threads available.
        ((num_threads + (num_threads * 0.2)) * block_multiplicator.min(1.0) * operation_loading)
            as u64
    }
}

// Given an `Op` this returns how many more ops should be done in parallel
// to saturate the CPU and have a better throughput measurement
#[cfg(all(feature = "integer", feature = "pbs-stats"))]
pub fn hlapi_throughput_num_ops<Op>(op: Op, cks: &tfhe::ClientKey) -> usize
where
    Op: FnOnce(),
{
    tfhe::reset_pbs_count();
    let t = std::time::Instant::now();
    op();
    let time_for_op = t.elapsed();
    let pbs_count_for_op = tfhe::get_pbs_count();

    let a = tfhe::FheBool::encrypt(true, cks);
    let b = tfhe::FheBool::encrypt(true, cks);
    let t = std::time::Instant::now();
    let _ = a & b;
    let time_for_single_pbs = t.elapsed();

    // Round-up with nano seconds
    let pbs_time_in_ms =
        time_for_single_pbs.as_millis() + u128::from(time_for_single_pbs.as_nanos() != 0);

    // Theoretical time if the op was just 1 layer of PBS all in parallel
    let time_if_full_occupancy =
        pbs_count_for_op.div_ceil(rayon::current_num_threads() as u64) as u128 * pbs_time_in_ms;

    // Then find how many ops we should do to have full occupancy
    let factor = time_for_op.as_millis().div_ceil(time_if_full_occupancy);

    factor as usize
}

/// This function aims to prevent the setup function from running.
/// `Gag` is used here to suppress the temporary output noise from Criterion.
/// We use a minimal Criterion configuration to retrieve information about the current filter setup.
/// The function returns a boolean indicating whether the current `bench_id` should be executed or
/// not.
pub fn will_this_bench_run(bench_group: &str, bench_id: &str) -> bool {
    let mut c = Criterion::default()
        .configure_from_args()
        .sample_size(10)
        .output_directory(&std::env::temp_dir())
        .warm_up_time(std::time::Duration::from_nanos(1))
        .measurement_time(std::time::Duration::from_nanos(1))
        .without_plots();
    let mut will_run = false;
    {
        use gag::Gag;
        let _print_gag = Gag::stdout().unwrap();
        let _err_gag = Gag::stderr().unwrap();
        c.benchmark_group(bench_group)
            .bench_function(bench_id, |b| {
                b.iter(|| {
                    will_run = true;
                });
            });
    }
    will_run
}

#[cfg(feature = "gpu")]
mod cuda_utils {
    use tfhe::core_crypto::entities::{
        LweBootstrapKeyOwned, LweKeyswitchKeyOwned, LweMultiBitBootstrapKeyOwned,
        LwePackingKeyswitchKeyOwned,
    };
    use tfhe::core_crypto::gpu::lwe_bootstrap_key::{
        CudaLweBootstrapKey, CudaModulusSwitchNoiseReductionConfiguration,
    };
    use tfhe::core_crypto::gpu::lwe_keyswitch_key::CudaLweKeyswitchKey;
    use tfhe::core_crypto::gpu::lwe_multi_bit_bootstrap_key::CudaLweMultiBitBootstrapKey;
    use tfhe::core_crypto::gpu::lwe_packing_keyswitch_key::CudaLwePackingKeyswitchKey;
    use tfhe::core_crypto::gpu::vec::{CudaVec, GpuIndex};
    use tfhe::core_crypto::gpu::{get_number_of_gpus, CudaStreams};
    use tfhe::core_crypto::prelude::{Numeric, UnsignedInteger};

    pub const GPU_MAX_SUPPORTED_POLYNOMIAL_SIZE: usize = 16384;

    /// Get vector of CUDA streams that can be directly used for throughput benchmarks in
    /// core_crypto layer.
    pub fn cuda_local_streams_core() -> Vec<CudaStreams> {
        (0..get_number_of_gpus())
            .map(|i| CudaStreams::new_single_gpu(GpuIndex::new(i)))
            .collect::<Vec<_>>()
    }

    /// Computing keys in their CPU flavor.
    pub struct CpuKeys<T: UnsignedInteger> {
        ksk: Option<LweKeyswitchKeyOwned<T>>,
        pksk: Option<LwePackingKeyswitchKeyOwned<T>>,
        bsk: Option<LweBootstrapKeyOwned<T>>,
        multi_bit_bsk: Option<LweMultiBitBootstrapKeyOwned<T>>,
    }

    impl<T: UnsignedInteger> CpuKeys<T> {
        pub fn builder() -> CpuKeysBuilder<T> {
            CpuKeysBuilder::new()
        }
    }

    pub struct CpuKeysBuilder<T: UnsignedInteger> {
        ksk: Option<LweKeyswitchKeyOwned<T>>,
        pksk: Option<LwePackingKeyswitchKeyOwned<T>>,
        bsk: Option<LweBootstrapKeyOwned<T>>,
        multi_bit_bsk: Option<LweMultiBitBootstrapKeyOwned<T>>,
    }

    impl<T: UnsignedInteger> CpuKeysBuilder<T> {
        pub fn new() -> CpuKeysBuilder<T> {
            Self {
                ksk: None,
                pksk: None,
                bsk: None,
                multi_bit_bsk: None,
            }
        }

        pub fn keyswitch_key(mut self, ksk: LweKeyswitchKeyOwned<T>) -> CpuKeysBuilder<T> {
            self.ksk = Some(ksk);
            self
        }

        pub fn packing_keyswitch_key(
            mut self,
            pksk: LwePackingKeyswitchKeyOwned<T>,
        ) -> CpuKeysBuilder<T> {
            self.pksk = Some(pksk);
            self
        }

        pub fn bootstrap_key(mut self, bsk: LweBootstrapKeyOwned<T>) -> CpuKeysBuilder<T> {
            self.bsk = Some(bsk);
            self
        }

        pub fn multi_bit_bootstrap_key(
            mut self,
            mb_bsk: LweMultiBitBootstrapKeyOwned<T>,
        ) -> CpuKeysBuilder<T> {
            self.multi_bit_bsk = Some(mb_bsk);
            self
        }

        pub fn build(self) -> CpuKeys<T> {
            CpuKeys {
                ksk: self.ksk,
                pksk: self.pksk,
                bsk: self.bsk,
                multi_bit_bsk: self.multi_bit_bsk,
            }
        }
    }
    impl<T: UnsignedInteger> Default for CpuKeysBuilder<T> {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Computing keys in their Cuda flavor.
    #[allow(dead_code)]
    pub struct CudaLocalKeys<T: UnsignedInteger> {
        pub ksk: Option<CudaLweKeyswitchKey<T>>,
        pub pksk: Option<CudaLwePackingKeyswitchKey<T>>,
        pub bsk: Option<CudaLweBootstrapKey>,
        pub multi_bit_bsk: Option<CudaLweMultiBitBootstrapKey<T>>,
    }

    #[allow(dead_code)]
    impl<T: UnsignedInteger> CudaLocalKeys<T> {
        pub fn from_cpu_keys(
            cpu_keys: &CpuKeys<T>,
            ms_noise_reduction: Option<CudaModulusSwitchNoiseReductionConfiguration>,
            stream: &CudaStreams,
        ) -> Self {
            Self {
                ksk: cpu_keys
                    .ksk
                    .as_ref()
                    .map(|ksk| CudaLweKeyswitchKey::from_lwe_keyswitch_key(ksk, stream)),
                pksk: cpu_keys.pksk.as_ref().map(|pksk| {
                    CudaLwePackingKeyswitchKey::from_lwe_packing_keyswitch_key(pksk, stream)
                }),
                bsk: cpu_keys.bsk.as_ref().map(|bsk| {
                    CudaLweBootstrapKey::from_lwe_bootstrap_key(bsk, ms_noise_reduction, stream)
                }),
                multi_bit_bsk: cpu_keys.multi_bit_bsk.as_ref().map(|mb_bsk| {
                    CudaLweMultiBitBootstrapKey::from_lwe_multi_bit_bootstrap_key(mb_bsk, stream)
                }),
            }
        }
    }

    /// Instantiate Cuda computing keys to each available GPU.
    pub fn cuda_local_keys_core<T: UnsignedInteger>(
        cpu_keys: &CpuKeys<T>,
        ms_noise_reduction: Option<CudaModulusSwitchNoiseReductionConfiguration>,
    ) -> Vec<CudaLocalKeys<T>> {
        let gpu_count = get_number_of_gpus() as usize;
        let mut gpu_keys_vec = Vec::with_capacity(gpu_count);
        for i in 0..gpu_count {
            let stream = CudaStreams::new_single_gpu(GpuIndex::new(i as u32));
            gpu_keys_vec.push(CudaLocalKeys::from_cpu_keys(
                cpu_keys,
                ms_noise_reduction.clone(),
                &stream,
            ));
        }
        gpu_keys_vec
    }

    pub struct CudaIndexes<T: Numeric> {
        pub d_input: CudaVec<T>,
        pub d_output: CudaVec<T>,
        pub d_lut: CudaVec<T>,
    }

    impl<T: Numeric> CudaIndexes<T> {
        pub fn new(indexes: &[T], stream: &CudaStreams, stream_index: u32) -> Self {
            let length = indexes.len();
            let mut d_input = CudaVec::<T>::new(length, stream, stream_index);
            let mut d_output = CudaVec::<T>::new(length, stream, stream_index);
            let mut d_lut = CudaVec::<T>::new(length, stream, stream_index);
            let zeros = vec![T::ZERO; length];

            unsafe {
                d_input.copy_from_cpu_async(indexes.as_ref(), stream, stream_index);
                d_output.copy_from_cpu_async(indexes.as_ref(), stream, stream_index);
                d_lut.copy_from_cpu_async(zeros.as_ref(), stream, stream_index);
                stream.synchronize();
            }

            Self {
                d_input,
                d_output,
                d_lut,
            }
        }
    }

    #[cfg(feature = "integer")]
    pub mod cuda_integer_utils {
        use tfhe::core_crypto::gpu::{get_number_of_gpus, CudaStreams};
        use tfhe::integer::gpu::CudaServerKey;
        use tfhe::integer::ClientKey;
        use tfhe::{set_server_key, CompressedServerKey, GpuIndex};

        /// Get number of streams usable for CUDA throughput benchmarks
        fn cuda_num_streams(num_block: usize) -> u64 {
            let num_streams_per_gpu: u32 = match num_block {
                2 => 64,
                4 => 32,
                8 => 16,
                16 => 8,
                32 => 4,
                64 => 2,
                128 => 1,
                _ => 8,
            };
            (num_streams_per_gpu * get_number_of_gpus()) as u64
        }

        /// Get vector of CUDA streams that can be directly used for throughput benchmarks.
        pub fn cuda_local_streams(
            num_block: usize,
            throughput_elements: usize,
        ) -> Vec<CudaStreams> {
            (0..cuda_num_streams(num_block))
                .map(|i| {
                    CudaStreams::new_single_gpu(GpuIndex::new(
                        (i % get_number_of_gpus() as u64) as u32,
                    ))
                })
                .cycle()
                .take(throughput_elements)
                .collect::<Vec<_>>()
        }

        /// Instantiate Cuda server key to each available GPU.
        pub fn cuda_local_keys(cks: &ClientKey) -> Vec<CudaServerKey> {
            let gpu_count = get_number_of_gpus() as usize;
            let mut gpu_sks_vec = Vec::with_capacity(gpu_count);
            for i in 0..gpu_count {
                let stream = CudaStreams::new_single_gpu(GpuIndex::new(i as u32));
                gpu_sks_vec.push(CudaServerKey::new(cks, &stream));
            }
            gpu_sks_vec
        }

        pub fn configure_gpu(client_key: &tfhe::ClientKey) {
            let compressed_sks = CompressedServerKey::new(client_key);
            let sks = compressed_sks.decompress_to_gpu();
            rayon::broadcast(|_| set_server_key(sks.clone()));
            set_server_key(sks);
        }
    }

    #[allow(unused_imports)]
    #[cfg(feature = "integer")]
    pub use cuda_integer_utils::*;
}

#[cfg(feature = "gpu")]
pub use cuda_utils::*;
