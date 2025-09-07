macro_rules! impl_hlapi_showcase {
    ($fhe_type: ty, $user_type: ty) => {
        ::paste::paste! {
        fn hlapi_showcase(
            cks: &ClientKey,
            rng: &mut StdRng,
        ) {
            println!("Start showcase on {} ----------------------------------------", stringify!($fhe_type));
            // Sum -------------------------------------------------------------
            // Generate random inputs value and compute expected result
            let in_a = rng.gen_range(0..$user_type::MAX);
            let in_b = rng.gen_range(0..$user_type::MAX);
            let clear_sum_ab = in_a.wrapping_add(in_b);

            // Encrypt input value
            let fhe_a = $fhe_type::encrypt(in_a, cks);
            let fhe_b = $fhe_type::encrypt(in_b, cks);

            // Triggered operation on HPU through hl_api
            let fhe_sum_ab = fhe_a+fhe_b;

            // Decrypt values
            let dec_sum_ab: $user_type = fhe_sum_ab.decrypt(cks);

            // Display result and check
            println!(" {} +  {} = fhe({}), clear({})", in_a, in_b, dec_sum_ab, clear_sum_ab);
            assert_eq!(dec_sum_ab, clear_sum_ab,
                 "Error with + operation get {}, expect {}",dec_sum_ab, clear_sum_ab);

            // Product ---------------------------------------------------------
            // Generate random inputs value and compute expected result
            let in_a = rng.gen_range(0..$user_type::MAX);
            let in_b = rng.gen_range(0..$user_type::MAX);

            let clear_mul_ab = in_a.wrapping_mul(in_b);

            // Encrypt input value
            let fhe_a = $fhe_type::encrypt(in_a, cks);
            let fhe_b = $fhe_type::encrypt(in_b, cks);

            // Triggered operation on HPU through hl_api
            let fhe_mul_ab = fhe_a * fhe_b;

            // Decrypt values
            let dec_mul_ab: $user_type = fhe_mul_ab.decrypt(cks);

            // Display result and check
            println!(" {} *  {} = fhe({}), clear({})", in_a, in_b, dec_mul_ab, clear_mul_ab);
            assert_eq!(dec_mul_ab, clear_mul_ab,
                 "Error with * operation get {}, expect {}",dec_mul_ab, clear_mul_ab);

            // BW_XOR ----------------------------------------------------------
            // Generate random inputs value and compute expected result
            let in_a = rng.gen_range(0..$user_type::MAX);
            let in_b = rng.gen_range(0..$user_type::MAX);

            let clear_bw_xor_ab = in_a ^ in_b;

            // Encrypt input value
            let fhe_a = $fhe_type::encrypt(in_a, cks);
            let fhe_b = $fhe_type::encrypt(in_b, cks);

            // Triggered operation on HPU through hl_api
            let fhe_bw_xor_ab = fhe_a ^ fhe_b;

            // Decrypt values
            let dec_bw_xor_ab: $user_type = fhe_bw_xor_ab.decrypt(cks);

            // Display result and check
            println!(" {} ^  {} = fhe({}), clear({})", in_a, in_b, dec_bw_xor_ab, clear_bw_xor_ab);

            assert_eq!(dec_bw_xor_ab, clear_bw_xor_ab,
                 "Error with ^ operation get {}, expect {}",dec_bw_xor_ab, clear_bw_xor_ab);

            // CMP_GTE ---------------------------------------------------------
            // Generate random inputs value and compute expected result
            let in_a = rng.gen_range(0..$user_type::MAX);
            let in_b = rng.gen_range(0..$user_type::MAX);

            let clear_cmp_gte_ab = in_a >= in_b;

            // Encrypt input value
            let fhe_a = $fhe_type::encrypt(in_a, cks);
            let fhe_b = $fhe_type::encrypt(in_b, cks);

            // Triggered operation on HPU through hl_api
            let fhe_cmp_gte_ab = fhe_a.ge(fhe_b);

            // Decrypt values
            let dec_cmp_gte_ab: bool = fhe_cmp_gte_ab.decrypt(cks);

            // Display result and check
            println!(" {} >= {} = fhe({}), clear({})", in_a, in_b, dec_cmp_gte_ab, clear_cmp_gte_ab);

            assert_eq!(dec_cmp_gte_ab, clear_cmp_gte_ab,
                 "Error with >= operation get {}, expect {}",dec_cmp_gte_ab, clear_cmp_gte_ab);
        }
        };
    };
}

fn main() {
    use tfhe::core_crypto::commons::generators::DeterministicSeeder;
    use tfhe::core_crypto::prelude::DefaultRandomGenerator;
    use tfhe::prelude::*;
    use tfhe::{set_server_key, ClientKey, CompressedServerKey, Config, FheUint8, *};
    use tfhe_hpu_backend::prelude::*;

    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    pub use clap::Parser;
    /// Define CLI arguments
    #[derive(clap::Parser, Debug, Clone, serde::Serialize)]
    #[command(long_about = "HPU example that shows the use of the HighLevelAPI.")]
    pub struct Args {
        // Fpga configuration ------------------------------------------------------
        /// Toml top-level configuration file
        #[arg(
            long,
            default_value = "${HPU_BACKEND_DIR}/config_store/${HPU_CONFIG}/hpu_config.toml"
        )]
        pub config: ShellString,

        // Exec configuration ----------------------------------------------------
        /// Seed used for some rngs
        #[arg(long)]
        pub seed: Option<u128>,
    }
    let args = Args::parse();
    println!("User Options: {args:?}");

    // Register tracing subscriber that use env-filter
    // Select verbosity with env_var: e.g. `RUST_LOG=Alu=trace`
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .compact()
        // Display source code file paths
        .with_file(false)
        // Display source code line numbers
        .with_line_number(false)
        .without_time()
        // Build & register the subscriber
        .init();

    // Seeder for args randomization ------------------------------------------
    let mut rng: StdRng = if let Some(seed) = args.seed {
        SeedableRng::seed_from_u64((seed & u64::MAX as u128) as u64)
    } else {
        SeedableRng::from_entropy()
    };

    // Instantiate HpuDevice --------------------------------------------------
    let hpu_device = HpuDevice::from_config(&args.config.expand());

    // Generate keys ----------------------------------------------------------
    let config = Config::from_hpu_device(&hpu_device);

    // Force key seeder if seed specified by user
    if let Some(seed) = args.seed {
        let mut seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(Seed(seed));
        let shortint_engine = tfhe::shortint::engine::ShortintEngine::new_from_seeder(&mut seeder);
        tfhe::shortint::engine::ShortintEngine::with_thread_local_mut(|engine| {
            std::mem::replace(engine, shortint_engine)
        });
    }

    let cks = ClientKey::generate(config);
    let csks = CompressedServerKey::new(&cks);

    set_server_key((hpu_device, csks));

    // Show 8bit capabilities --------------------------------------------------
    {
        impl_hlapi_showcase!(FheUint8, u8);
        hlapi_showcase(&cks, &mut rng);
    }

    // Show 16bit capabilities -------------------------------------------------
    {
        impl_hlapi_showcase!(FheUint16, u16);
        hlapi_showcase(&cks, &mut rng);
    }

    // Show 32bit capabilities -------------------------------------------------
    {
        impl_hlapi_showcase!(FheUint32, u32);
        hlapi_showcase(&cks, &mut rng);
    }

    // Show 64bit capabilities -------------------------------------------------
    {
        impl_hlapi_showcase!(FheUint64, u64);
        hlapi_showcase(&cks, &mut rng);
    }
}
