#![allow(clippy::unnecessary_cast)]
//! Define a test-harness that handle setup and configuration of Hpu Backend
//! The test harness take a list of testcase and run them
//! A testcase simply bind a IOp to a closure describing it's behavior
//! WARN: Only one Hpu could be use at a time, thus all test must be run sequentially

//NB: Tests behavior could be altered at runtime with the following env variables:
//     * HPU_SELECTED_NODE<u8>: Instead of using full cluster as target, use only the specified node
//     * HPU_FORCE_RELOAD: Force pdi reload even if the uuid match targeted one
//     * HPU_IO_DUMP<String>: Enable input/output dumping in given path
//     * HPU_KEY_SEED<u128>: Force key seed value for reproducible results
//     * HPU_TEST_SEED<u128>: Force test seed value for reproducible results
//     * HPU_TEST_ITER<usize>: Specify number of iteration for each test (default: 32)
//     * HPU_TEST_TRIVIAL: Use trivial ciphertext instead of real one

#[cfg(feature = "hpu")]
mod hpu_test {
    use std::str::FromStr;

    use rand::rngs::StdRng;
    use rand::{Rng, RngCore, SeedableRng};
    use tfhe::core_crypto::commons::generators::DeterministicSeeder;
    use tfhe::core_crypto::prelude::{DefaultRandomGenerator, UnsignedInteger};
    use tfhe::integer::hpu::ciphertext::HpuRadixCiphertext;

    use tfhe::Seed;
    pub use tfhe_hpu_backend::prelude::*;

    /// Variable to store initialized HpuDevice and associated client key for fast iteration
    static HPU_DEVICE_RNG_CKS: std::sync::OnceLock<(
        std::sync::Mutex<HpuDevice>,
        tfhe::integer::ClientKey,
        u128,
    )> = std::sync::OnceLock::new();

    // // Instantiate a shared rng for cleartext input generation
    // let rng: StdRng = SeedableRng::seed_from_u64((seed & u64::MAX as u128) as u64);

    /// Simple function used to retrieved or generate a seed from environment
    fn get_or_init_seed(name: &str) -> u128 {
        match std::env::var(name) {
            Ok(var) => if let Some(hex) = var.strip_prefix("0x").or_else(|| var.strip_prefix("0X"))
            {
                u128::from_str_radix(hex, 16)
            } else if let Some(bin) = var.strip_prefix("0b").or_else(|| var.strip_prefix("0B")) {
                u128::from_str_radix(bin, 2)
            } else if let Some(oct) = var.strip_prefix("0o").or_else(|| var.strip_prefix("0O")) {
                u128::from_str_radix(oct, 8)
            } else {
                var.parse::<u128>() // default: base 10
            }
            .unwrap_or_else(|_| panic!("{name} env variable {var} couldn't be casted in u128")),
            _ => {
                // Use tread_rng to generate the seed
                let lsb = rand::thread_rng().next_u64() as u128;
                let msb = rand::thread_rng().next_u64() as u128;
                (msb << u64::BITS) | lsb
            }
        }
    }

    /// Simple function to retrieved targeted node from environment
    /// Also extract force_reload request and return it as bool
    fn update_config_node(config: &mut HpuConfig) -> bool {
        match std::env::var("HPU_SELECTED_NODE") {
            Ok(var) => {
                let node = if let Some(hex) =
                    var.strip_prefix("0x").or_else(|| var.strip_prefix("0X"))
                {
                    u8::from_str_radix(hex, 16)
                } else if let Some(bin) = var.strip_prefix("0b").or_else(|| var.strip_prefix("0B"))
                {
                    u8::from_str_radix(bin, 2)
                } else if let Some(oct) = var.strip_prefix("0o").or_else(|| var.strip_prefix("0O"))
                {
                    u8::from_str_radix(oct, 8)
                } else {
                    var.parse::<u8>() // default: base 10
                }
                .unwrap_or_else(|_| {
                    panic!("HPU_SELECTED_NODE env variable {var} couldn't be casted in u8")
                });
                config.fpga.node_id = vec![node];
            }
            _ => {
                // Use all node specify in toml file
            }
        }

        // Extract force_reload from env
        match std::env::var("HPU_FORCE_RELOAD") {
            Ok(_) => true,
            _ => false,
        }
    }

    fn init_hpu_and_associated_material(
    ) -> (std::sync::Mutex<HpuDevice>, tfhe::integer::ClientKey, u128) {
        // Hpu io dump for debug  -------------------------------------------------
        #[cfg(feature = "hpu-debug")]
        if let Ok(dump_path) = std::env::var("HPU_IO_DUMP") {
            set_hpu_io_dump(&dump_path);
        }

        // Instantiate HpuDevice --------------------------------------------------
        let hpu_device = {
            let config_file = ShellString::new(
                "${HPU_BACKEND_DIR}/config_store/${HPU_CONFIG}/hpu_config.toml".to_string(),
            );
            // Read config and update it based on env variables
            let mut hpu_config = HpuConfig::from_toml(config_file.expand().as_str());
            let force_reload = update_config_node(&mut hpu_config);

            HpuDevice::new(hpu_config, force_reload)
                .expect("Impossible to create HpuDevice from current configuration")
        };

        // Check if user force a seed for the key generation
        let key_seed = get_or_init_seed("HPU_KEY_SEED");

        // Force key seeder for easily reproduce failure
        let mut key_seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(Seed(key_seed));
        let shortint_engine =
            tfhe::shortint::engine::ShortintEngine::new_from_seeder(&mut key_seeder);
        tfhe::shortint::engine::ShortintEngine::with_thread_local_mut(|engine| {
            std::mem::replace(engine, shortint_engine)
        });

        // Extract pbs_configuration from Hpu and create Client/Server Key
        let cks = tfhe::integer::ClientKey::new(
            tfhe::shortint::parameters::KeySwitch32PBSParameters::from(hpu_device.params()),
        );
        let sks_compressed =
            tfhe::integer::CompressedServerKey::new_radix_compressed_server_key(&cks);

        // Init Hpu device with server key and firmware
        tfhe::integer::hpu::init_device(&hpu_device, sks_compressed).expect("Invalid key");
        (std::sync::Mutex::new(hpu_device), cks, key_seed)
    }

    fn hpu_check_iop_proto<T, F>(
        iop: hpu_asm::AsmIOpcode,
        proto: hpu_asm::IOpProto,
        behav: F,
        iter: usize,
        device: &mut HpuDevice,
        rng: &mut StdRng,
        cks: &tfhe::integer::ClientKey,
    ) -> bool
    where
        T: UnsignedInteger,
        F: Fn(&[T], &[T]) -> Vec<T>,
    {
        // Check if current configured cluster has enough node
        let nodes = device.config().fpga.node_id.len();
        let proto_max_nodes = proto.used_nodes.max_node() as usize;
        if proto_max_nodes > nodes {
            println!("HpuDevice hasn't enough node to execute {iop:?} [get: {nodes}, req: {proto_max_nodes}].",);
            return false;
        }

        // Check if user ask for test over trivial ciphertext
        let (test_trivial, sks) = match std::env::var("HPU_TEST_TRIVIAL") {
            Ok(var) => {
                let flag_val = usize::from_str(&var).unwrap_or_else(|_| {
                    panic!("HPU_TEST_TRIVIAL env variable {var} couldn't be casted in usize")
                });
                let sks_compressed = tfhe::integer::ServerKey::new_radix_server_key(&cks);
                (flag_val != 0, Some(sks_compressed))
            }
            _ => (false, None),
        };

        let width = T::BITS;
        let max_val: u128 = T::MAX.cast_into();
        let num_block = width / device.params().pbs_params.message_width;
        // NB: To support both mono-hpu IOp and multi-hpu IOp,
        // input are generated only on the first node.
        // If you want to select a specific node for test, use `HPU_SELECTED_NODE` env variable
        //  with the node id you want to target.
        // This will fallback in mono-hpu setup
        let targeted_node = hpu_asm::PhysId(device.config().fpga.node_id[0]);
        (0..iter)
            .map(|_| {
                // Generate inputs ciphertext
                let (srcs_clear, srcs_enc): (Vec<_>, Vec<_>) = proto
                    .src
                    .iter()
                    .enumerate()
                    .map(|(_pos, mode)| {
                        let (bw, block) = match mode {
                            hpu_asm::iop::VarMode::Native => (width, num_block),
                            hpu_asm::iop::VarMode::Half => (width / 2, num_block / 2),
                            hpu_asm::iop::VarMode::Bool => (1, 1),
                        };

                        let clear = rng.gen_range(0_u128..=max_val >> (width - bw));
                        let fhe = if test_trivial {
                            sks.as_ref().unwrap().create_trivial_radix(clear, block)
                        } else {
                            cks.encrypt_radix(clear, block)
                        };
                        let hpu_fhe = HpuRadixCiphertext::from_radix_ciphertext(
                            &fhe,
                            device,
                            Some(targeted_node),
                        );
                        (T::cast_from(clear), hpu_fhe)
                    })
                    .unzip();

                let imms_u128 = (0..proto.imm)
                    .map(|_pos| rng.gen_range(0_u128..max_val))
                    .collect::<Vec<_>>();
                let imms_typed = imms_u128.iter().map(|v| T::cast_from(*v))
                    .collect::<Vec<_>>();

                // execute on Hpu
                let res_hpu =
                    HpuRadixCiphertext::exec(&proto, iop.opcode(), &srcs_enc, &imms_u128, None);
                let res_fhe = res_hpu
                    .iter()
                    .map(|x| x.to_radix_ciphertext())
                    .collect::<Vec<_>>();
                let res = res_fhe
                    .iter()
                    .map(|x| T::cast_from(cks.decrypt_radix::<u128>(x)))
                    .collect::<Vec<T>>();

                let exp_res = behav(&srcs_clear, &imms_typed);
                println!(
                    "[{:>4}] {:>8} <{:>8x?}> <{:>8x?}> => {:<8x?} [exp {:<8x?}] {{Delta: {:x?} }}",
                    T::BITS,
                    iop,
                    srcs_clear,
                    imms_typed,
                    res,
                    exp_res,
                    std::iter::zip(res.iter(), exp_res.iter())
                        .map(|(x, y)| {
                            let x_u128: u128 = x.cast_into();
                            let y_u128: u128 = y.cast_into();
                            T::cast_from(x_u128 ^ y_u128)
                        })
                        .collect::<Vec<_>>()
                );
                std::iter::zip(res.iter(), exp_res.iter())
                    .map(|(x, y)| x == y)
                    .fold(true, |acc, val| acc & val)
            })
            .fold(true, |acc, val| acc & val)
    }

    const DEFAULT_TEST_ITER: usize = 32;

    // Create testbundle
    // => Enable to reuse same Hpu backend for a set of tests
    // NB: Two nested macros are used here to enable cross-product between integer_width * testcase
    macro_rules! hpu_testbundle {
        ($base_name: literal::[$($integer_width:tt),+] => $testcases: tt) => {
            $(
                hpu_testbundle_at_width!($base_name::$integer_width => $testcases);
            )*
        };
    }

    macro_rules! hpu_testbundle_at_width {
    ($base_name: literal::$integer_width:tt=> [$($testcase: literal),+]) => {
    ::paste::paste! {
        #[test]
        pub fn [<hpu_test_ $base_name:lower _u $integer_width>]() {
            // Register tracing subscriber that use env-filter
            // Discard error ( mainly due to already registered subscriber)
            let _ = tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .compact()
                .with_file(false)
                .with_line_number(false)
                .without_time()
                .try_init();
            // Retrieved test iteration from environment ----------------------------
            let hpu_test_iter = match(std::env::var("HPU_TEST_ITER")){
                Ok(var) => usize::from_str(&var).unwrap_or_else(|_| {
                    panic!("HPU_TEST_ITER env variable {var} couldn't be casted in usize")
                }),
                _ => DEFAULT_TEST_ITER
            };

            // Retrieved HpuDevice or init ---------------------------------------------
            let (hpu_mutex, cks, key_seed)= HPU_DEVICE_RNG_CKS.get_or_init(init_hpu_and_associated_material);
            let mut hpu_device = hpu_mutex.lock().expect("Error with HpuDevice Mutex");
            assert!(hpu_device.config().firmware.integer_w.contains(&($integer_width as usize)), "Current Hpu configuration doesn't support {}b integer [has {:?}]", $integer_width, hpu_device.config().firmware.integer_w);

            // Instantiate a Rng for cleartest input generation
            // Create a fresh one for each testbundle to be reproducible even if execution order
            // of testbundle are not stable
            let test_seed = get_or_init_seed("HPU_TEST_SEED");
            // Display used seed value in a reusable manner (i.e. valid bash syntax)
            println!("HPU_KEY_SEED={key_seed} #[i.e. 0x{key_seed:x}]");
            println!("HPU_TEST_SEED={test_seed} #[i.e. 0x{test_seed:x}]");

            let mut rng: StdRng = SeedableRng::seed_from_u64((test_seed & u64::MAX as u128) as u64);

            // Reseed shortint engine for reproducible noise generation.
            let mut noise_seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(Seed(test_seed));
            let shortint_engine =
                tfhe::shortint::engine::ShortintEngine::new_from_seeder(&mut noise_seeder);
            tfhe::shortint::engine::ShortintEngine::with_thread_local_mut(|engine| {
                std::mem::replace(engine, shortint_engine)
            });

            // Run test-case ---------------------------------------------------------
            let mut acc_status = true;
            $(
                {
                let status = [<hpu_ $testcase _u $integer_width>](hpu_test_iter, &mut hpu_device, &mut rng, &cks);
                if !status {
                    println!("Error: in testcase {}", stringify!([<hpu_ $testcase _u $integer_width>]));
                }
                acc_status &= status
                }
            )*

            drop(hpu_device);
            assert!(acc_status, "At least one testcase failed in the testbundle");
       }
    }
    };
}

    // Test based on standard IOp
    // Rely on backend firmware generation with known prototype
    macro_rules! hpu_testcase {
        ($iop: literal => [$($user_type: ty),+] |$ct:ident, $imm: ident| $behav: expr) => {
            ::paste::paste! {
                $(
                #[cfg(feature = "hpu")]
                #[allow(unused)]
                pub fn [<hpu_ $iop:lower _ $user_type>](iter: usize, device: &mut HpuDevice, rng: &mut StdRng, cks: &tfhe::integer::ClientKey) -> bool {
                    let iop = hpu_asm::AsmIOpcode::from_str($iop).expect("Invalid AsmIOpcode ");
                    let proto = if let Some(format) = iop.format() {
                        format.proto.clone()
                    } else {
                        eprintln!("Hpu testcase only work on specified operations. Check test definition");
                        return false;
                    };
                    let behav = |ct:&[$user_type], imm: &[$user_type]| {
                            let $ct = ct;
                            let $imm = imm;
                            ($behav.iter().map(|x| *x as $user_type).collect::<Vec<_>>())
                        };

                    hpu_check_iop_proto::<$user_type, _>(
                        iop,
                        proto,
                        behav,
                        iter,
                        device,
                        rng,
                        cks,
                    )

                }
            )*
            }
        };
    }

    // Test based on custom iop
    // There are specialized hand crafted test for Hpu validation
    // Prototype must be specified by hand
    macro_rules! hpu_custom_testcase {
        ($cust_id: literal, $inproto: literal => [$($user_type: ty),+] |$ct:ident, $imm: ident| $behav: expr) => {
            ::paste::paste! {
                $(
                #[cfg(feature = "hpu")]
                #[allow(unused)]
                pub fn [<hpu_custom $cust_id:lower _ $user_type>](iter: usize, device: &mut HpuDevice, rng: &mut StdRng, cks: &tfhe::integer::ClientKey) -> bool {
                    let iop = hpu_asm::AsmIOpcode::from_opcode(hpu_asm::IOpcode($cust_id));
                    let proto = $inproto.parse::<hpu_asm::IOpProto>().unwrap();
                    let behav = |ct:&[$user_type], imm: &[$user_type]| {
                            let $ct = ct;
                            let $imm = imm;
                            ($behav.iter().map(|x| *x as $user_type).collect::<Vec<_>>())
                        };

                    hpu_check_iop_proto::<$user_type, _>(
                        iop,
                        proto,
                        behav,
                        iter,
                        device,
                        rng,
                        cks,
                    )

                }
            )*
            }
        };
    }

    // Define testcase implementation for all supported IOp
    // Alu IOp with Ct x Imm
    hpu_testcase!("ADDS" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0].wrapping_add(imm[0])]);
    hpu_testcase!("SUBS" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0].wrapping_sub(imm[0])]);
    hpu_testcase!("SSUB" => [u8, u16, u32, u64, u128]
    |ct, imm| [imm[0].wrapping_sub(ct[0])]);
    hpu_testcase!("MULS" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0].wrapping_mul(imm[0])]);
    hpu_testcase!("DIVS" => [u8, u16, u32, u64, u128]
    |ct, imm| if imm[0] == 0 {[0, ct[0]]} else {[ct[0].wrapping_div(imm[0]), ct[0] % imm[0]]});
    hpu_testcase!("MODS" => [u8, u16, u32, u64, u128]
    |ct, imm| if imm[0] == 0 {[ct[0]]} else {[ct[0] % imm[0]]});

    // Version with overflow flag
    hpu_testcase!("OVF_ADDS" => [u8, u16, u32, u64, u128]
        |ct, imm| {
            let (res, flag) = ct[0].overflowing_add(imm[0]);
            [res, flag.into()]
    });
    hpu_testcase!("OVF_SUBS" => [u8, u16, u32, u64, u128]
        |ct, imm| {
            let (res, flag) = ct[0].overflowing_sub(imm[0]);
            [res, flag.into()]
    });
    hpu_testcase!("OVF_SSUB" => [u8, u16, u32, u64, u128]
        |ct, imm| {
            let (res, flag) = imm[0].overflowing_sub(ct[0]);
            [res, flag.into()]
    });
    hpu_testcase!("OVF_MULS" => [u8, u16, u32, u64, u128]
        |ct, imm| {
            let (res, flag) = ct[0].overflowing_mul(imm[0]);
            [res, flag.into()]
    });

    // Shift/Rotation with Scalar IOp
    hpu_testcase!("SHIFTS_R" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0].wrapping_shr(imm[0] as u32)] );
    hpu_testcase!("SHIFTS_L" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0].wrapping_shl(imm[0] as u32)] );
    hpu_testcase!("ROTS_R" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0].rotate_right(imm[0] as u32)] );
    hpu_testcase!("ROTS_L" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0].rotate_left(imm[0] as u32)] );

    // Alu IOp with Ct x Ct
    hpu_testcase!("ADD" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0].wrapping_add(ct[1])]);
    hpu_testcase!("SUB" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0].wrapping_sub(ct[1])]);
    hpu_testcase!("MUL" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0].wrapping_mul(ct[1])]);
    hpu_testcase!("DIV" => [u8, u16, u32, u64, u128]
    |ct, imm| if ct[1] == 0 {[0, ct[0]]} else {[ct[0].wrapping_div(ct[1]), ct[0] % ct[1]]});
    hpu_testcase!("MOD" => [u8, u16, u32, u64, u128]
    |ct, imm| if ct[1] == 0 {[ct[0]]} else {[ct[0] % ct[1]]});

    hpu_testcase!("OVF_ADD" => [u8, u16, u32, u64, u128]
        |ct, imm| {
            let (res, flag) = ct[0].overflowing_add(ct[1]);
            [res, flag.into()]
    });
    hpu_testcase!("OVF_SUB" => [u8, u16, u32, u64, u128]
        |ct, imm| {
            let (res, flag) = ct[0].overflowing_sub(ct[1]);
            [res, flag.into()]
    });
    hpu_testcase!("OVF_MUL" => [u8, u16, u32, u64, u128]
        |ct, imm| {
            let (res, flag) = ct[0].overflowing_mul(ct[1]);
            [res, flag.into()]
    });

    // Shift/Rotation IOp
    hpu_testcase!("SHIFT_R" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0].wrapping_shr(ct[1] as u32)] );
    hpu_testcase!("SHIFT_L" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0].wrapping_shl(ct[1] as u32)] );
    hpu_testcase!("ROT_R" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0].rotate_right(ct[1] as u32)] );
    hpu_testcase!("ROT_L" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0].rotate_left(ct[1] as u32)] );

    // Bitwise IOp
    hpu_testcase!("BW_AND" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0] & ct[1]]);
    hpu_testcase!("BW_OR" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0] | ct[1]]);
    hpu_testcase!("BW_XOR" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0] ^ ct[1]]);

    // Comparison IOp
    hpu_testcase!("CMP_GT" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0] > ct[1]]);
    hpu_testcase!("CMP_GTE" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0] >= ct[1]]);
    hpu_testcase!("CMP_LT" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0] < ct[1]]);
    hpu_testcase!("CMP_LTE" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0] <= ct[1]]);
    hpu_testcase!("CMP_EQ" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0] == ct[1]]);
    hpu_testcase!("CMP_NEQ" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0] != ct[1]]);

    // Ternary IOp
    hpu_testcase!("IF_THEN_ZERO" => [u8, u16, u32, u64, u128]
    |ct, imm| [if ct[1] != 0 {ct[0]} else { 0}]);
    hpu_testcase!("IF_THEN_ELSE" => [u8, u16, u32, u64, u128]
    |ct, imm| [if ct[2] != 0 {ct[0]} else { ct[1]}]);

    // ERC 7984 found xfer
    hpu_testcase!("ERC_7984" => [u8, u16, u32, u64, u128]
        |ct, imm| {
            let from = ct[0];
            let to = ct[1];
            let amount = ct[2];
            // TODO enhance this to prevent overflow
            if from >= amount {
                vec![from - amount, to.wrapping_add(amount)]
                } else {
                    vec![from, to]
                }
    });

    // Bit count IOp
    hpu_testcase!("COUNT0" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0].count_zeros()]);
    hpu_testcase!("COUNT1" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0].count_ones()]);
    hpu_testcase!("ILOG2" => [u8, u16, u32, u64, u128]
    |ct, imm| [if ct[0] == 0 {0} else {ct[0].ilog2()}]);
    hpu_testcase!("LEAD0" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0].leading_zeros()]);
    hpu_testcase!("LEAD1" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0].leading_ones()]);
    hpu_testcase!("TRAIL0" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0].trailing_zeros()]);
    hpu_testcase!("TRAIL1" => [u8, u16, u32, u64, u128]
    |ct, imm| [ct[0].trailing_ones()]);

    // Custom IOp
    hpu_custom_testcase!(32, "[2]<N,N>::<N,N><0>" => [u8]
    |ct, imm| vec![(ct[0] & 0xF) + (ct[1] & 0xF).wrapping_shl(4), (ct[0] & 0xF0).wrapping_shr(4) + (ct[1] & 0xF0)]);
    hpu_custom_testcase!(33, "[2]<N>::<N><0>" => [u8, u32, u64]
    |ct, imm| vec![ct[0]]);
    hpu_custom_testcase!(34, "[2]<N>::<N,N><0>" => [u8]
    |ct, imm| vec![ct[0].wrapping_add(ct[1])]);
    hpu_custom_testcase!(35, "[2]<N>::<N><0>" => [u8]
    |ct, imm| vec![ct[0]]);
    hpu_custom_testcase!(36, "[2]<N>::<N,N><0>" => [u8]
    |ct, imm| vec![ct[0].wrapping_mul(ct[1])]);
    hpu_custom_testcase!(37, "[4]<N,N>::<N,N><0>" => [u8]
    |ct, imm| vec![(ct[0] & 0xF) + (ct[1] & 0xF).wrapping_shl(4), (ct[0] & 0xF0).wrapping_shr(4) + (ct[1] & 0xF0)]);
    hpu_custom_testcase!(40, "[2]<H,H>::<N,N><0>" => [u32]
    |ct, imm| {
        let res = ct[0].wrapping_mul(ct[1]);
        vec![res & 0xFFFF, (res >>16) & 0xFFFF]
    });
    hpu_custom_testcase!(40, "[2]<H,H>::<N,N><0>" => [u64]
    |ct, imm| {
        let res = ct[0].wrapping_mul(ct[1]);
        vec![res & 0xFFFFFFFF, (res >>32) & 0xFFFFFFFF]
    });

    // Define a set of test bundle for various size
    #[cfg(feature = "hpu")]
    hpu_testbundle!("alus"::[8,16,32,64,128] => [
        "adds",
        "subs",
        "ssub",
        "muls",
        "divs",
        "mods"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("ovf_alus"::[8,16,32,64,128] => [
        "ovf_adds",
        "ovf_subs",
        "ovf_ssub",
        "ovf_muls"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("rots"::[8,16,32,64,128] => [
        "rots_r",
        "rots_l"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("shifts"::[8,16,32,64,128] => [
        "shifts_r",
        "shifts_l"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("alu"::[8,16,32,64,128] => [
        "add",
        "sub",
        "mul",
        "div",
        "mod"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("ovf_alu"::[8,16,32,64,128] => [
        "ovf_add",
        "ovf_sub",
        "ovf_mul"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("rot"::[8,16,32,64,128] => [
        "rot_r",
        "rot_l"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("shift"::[8,16,32,64,128] => [
        "shift_r",
        "shift_l"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("bitwise"::[8,16,32,64,128] => [
        "bw_and",
        "bw_or",
        "bw_xor"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("cmp"::[8,16,32,64,128] => [
        "cmp_gt",
        "cmp_gte",
        "cmp_lt",
        "cmp_lte",
        "cmp_eq",
        "cmp_neq"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("ternary"::[8,16,32,64,128] => [
        "if_then_zero",
        "if_then_else"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("algo"::[8,16,32,64,128] => [
        "erc_7984"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("cntbit"::[8,16,32,64,128] => [
        "count0",
        "count1",
        "ilog2",
        "lead0",
        "lead1",
        "trail0",
        "trail1"
    ]);

    // multi-hpu test bundles -----------------------------------------
    #[cfg(feature = "hpu")]
    hpu_testbundle!("multi-hpu"::[8] => [
        "custom32",
        "custom33",
        "custom34",
        "custom35",
        "custom36",
        "custom37"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("multi-hpu"::[32,64] => [
        "custom33",
        "custom40"
    ]);

    /// Simple test dedicated to check entities conversion from/to Cpu
    #[cfg(feature = "hpu")]
    #[test]
    fn hpu_key_loopback() {
        use tfhe::core_crypto::prelude::*;
        use tfhe::*;
        use tfhe_hpu_backend::prelude::*;

        // Retrieved HpuDevice or init ---------------------------------------------
        // Used hpu_device backed in static variable to automatically serialize tests
        let (hpu_params, cks, key_seed) = {
            let (hpu_mutex, cks, key_seed) =
                HPU_DEVICE_RNG_CKS.get_or_init(init_hpu_and_associated_material);
            let hpu_device = hpu_mutex.lock().expect("Error with HpuDevice Mutex");
            (hpu_device.params().clone(), cks, key_seed)
        };
        println!("HPU_KEY_SEED={key_seed} #[i.e. 0x{key_seed:x}]");

        // Generate Keys ---------------------------------------------------------
        let sks_compressed =
            tfhe::integer::CompressedServerKey::new_radix_compressed_server_key(cks)
                .into_raw_parts();

        // Unwrap compressed key ---------------------------------------------------
        let ap_key =  match sks_compressed.compressed_ap_server_key {
                tfhe::shortint::atomic_pattern::compressed::CompressedAtomicPatternServerKey::Standard(_) => {
                    panic!("Hpu not support Standard keys. Required a KeySwitch32 keys")
                    }
                tfhe::shortint::atomic_pattern::compressed::CompressedAtomicPatternServerKey::KeySwitch32(keys) => keys,
        };

        // KSK Loopback conversion and check -------------------------------------
        // Extract and convert ksk
        let cpu_ksk_orig = ap_key
            .key_switching_key()
            .clone()
            .decompress_into_lwe_keyswitch_key();
        let hpu_ksk =
            HpuLweKeyswitchKeyOwned::create_from(cpu_ksk_orig.as_view(), hpu_params.clone());
        let cpu_ksk_lb = LweKeyswitchKeyOwned::<u32>::from(hpu_ksk.as_view());

        // NB: Some hw modifications such as bit shrinki couldn't be reversed
        // cpu_ksk_orig.as_mut().iter_mut().for_each(|coef| {
        //     let ks_p = hpu_params.ks_params;
        //     // Apply Hw rounding
        //     // Extract info bits and rounding if required
        //     let coef_info = *coef >> (u32::BITS - ks_p.width as u32);
        //     let coef_rounding = if (ks_p.width as u32) < u32::BITS {
        //         (*coef >> (u32::BITS - (ks_p.width + 1) as u32)) & 0x1
        //     } else {
        //         0
        //     };
        //     *coef = (coef_info + coef_rounding) << (u32::BITS - ks_p.width as u32);
        // });

        let ksk_mismatch: usize =
            std::iter::zip(cpu_ksk_orig.as_ref().iter(), cpu_ksk_lb.as_ref().iter())
                .enumerate()
                .map(|(i, (x, y))| {
                    if x != y {
                        println!("Ksk mismatch @{i}:: {x:x} != {y:x}");
                        1
                    } else {
                        0
                    }
                })
                .sum();

        // BSK Loopback conversion and check -------------------------------------
        // Extract and convert ksk
        let cpu_bsk_orig = match ap_key.bootstrapping_key() {
            tfhe::shortint::server_key::ShortintCompressedBootstrappingKey::Classic {
                bsk: seeded_bsk,
                ..
            } => seeded_bsk.clone().decompress_into_lwe_bootstrap_key(),
            tfhe::shortint::server_key::ShortintCompressedBootstrappingKey::MultiBit { .. } => {
                panic!("Hpu currently not support multibit. Required a Classic BSK")
            }
        };
        let cpu_bsk_ntt = {
            // Convert the LweBootstrapKey in Ntt domain
            let mut ntt_bsk = NttLweBootstrapKeyOwned::<u64>::new(
                0_u64,
                cpu_bsk_orig.input_lwe_dimension(),
                cpu_bsk_orig.glwe_size(),
                cpu_bsk_orig.polynomial_size(),
                cpu_bsk_orig.decomposition_base_log(),
                cpu_bsk_orig.decomposition_level_count(),
                CiphertextModulus::new(u64::from(&hpu_params.ntt_params.prime_modulus) as u128),
            );

            // Conversion to ntt domain
            par_convert_standard_lwe_bootstrap_key_to_ntt64(
                &cpu_bsk_orig,
                &mut ntt_bsk,
                NttLweBootstrapKeyOption::Raw,
            );
            ntt_bsk
        };
        let hpu_bsk = HpuLweBootstrapKeyOwned::create_from(cpu_bsk_orig.as_view(), hpu_params);

        let cpu_bsk_lb = NttLweBootstrapKeyOwned::from(hpu_bsk.as_view());

        let bsk_mismatch: usize = std::iter::zip(
            cpu_bsk_ntt.as_view().into_container().iter(),
            cpu_bsk_lb.as_view().into_container().iter(),
        )
        .enumerate()
        .map(|(i, (x, y))| {
            if x != y {
                println!("@{i}:: {x:x} != {y:x}");
                1
            } else {
                0
            }
        })
        .sum();

        println!("Ksk loopback with {ksk_mismatch} errors");
        println!("Bsk loopback with {bsk_mismatch} errors");

        assert_eq!(ksk_mismatch + bsk_mismatch, 0);
    }

    // Custom test for MHDMA stress test
    // It generate all the required inputs upfront and iterate over a chain of custom IOp
    macro_rules! hpu_mhdma_test {
        ($($user_type: ty),+) => {
        ::paste::paste! {
        $(
        pub fn [<hpu_mhdma_test_ $user_type>](_iter: usize, device: &mut HpuDevice, rng: &mut StdRng, cks: &tfhe::integer::ClientKey) -> bool {
        use tfhe::integer::hpu::ciphertext::HpuRadixCiphertext;

        // Since all inputs are generated upfront, iteration number is fixed to 256 here.
        // This prevent deadlock on ciphertext allocation
        let iter = 128;
        // Check if current configured cluster has enough node
        let proto = "[2]<H,H>::<N,N><0>".parse::<hpu_asm::IOpProto>().unwrap();
        let nodes = device.config().fpga.node_id.len();
        let proto_max_nodes = proto.used_nodes.max_node() as usize;
        if proto_max_nodes > nodes {
            println!("HpuDevice hasn't enough node to execute mhdma_test [get: {nodes}, req: {proto_max_nodes}].",);
            return false;
        }

        // Check if user ask for test over trivial ciphertext
        let (test_trivial, sks) = match (std::env::var("HPU_TEST_TRIVIAL")) {
            Ok(var) => {
                let flag_val = usize::from_str(&var).unwrap_or_else(|_| {
                    panic!("HPU_TEST_TRIVIAL env variable {var} couldn't be casted in usize")
                });
                let sks_compressed = tfhe::integer::ServerKey::new_radix_server_key(&cks);
                (flag_val != 0, Some(sks_compressed))
            }
            _ => (false, None),
        };

        let width = $user_type::BITS as usize;
        let num_block = width / device.params().pbs_params.message_width;
        // NB: To support both mono-hpu IOp and multi-hpu IOp,
        // input are generated only on the first node.
        // If you want to select a specific node for test, use `HPU_SELECTED_NODE` env variable
        //  with the node id you want to target.
        // This will fallback in mono-hpu setup
        let targeted_node = hpu_asm::PhysId(device.config().fpga.node_id[0]);
        let test_inputs = (0..iter)
            .map(|_| {
                // Generate inputs ciphertext
                let (srcs_clear, srcs_enc): (Vec<_>, Vec<_>) = proto
                    .src
                    .iter()
                    .enumerate()
                    .map(|(_pos, mode)| {
                        let (bw, block) = match mode {
                            hpu_asm::iop::VarMode::Native => (width, num_block),
                            hpu_asm::iop::VarMode::Half => (width / 2, num_block / 2),
                            hpu_asm::iop::VarMode::Bool => (1, 1),
                        };

                        let clear = rng.gen_range(0..u128::MAX >> (u128::BITS - (bw as u32)));
                        let fhe = if test_trivial {
                            sks.as_ref().unwrap().create_trivial_radix(clear, block)
                        } else {
                            cks.encrypt_radix(clear, block)
                        };
                        let hpu_fhe = HpuRadixCiphertext::from_radix_ciphertext(
                            &fhe,
                            device,
                            Some(targeted_node),
                        );
                        (clear, hpu_fhe)
                    })
                    .unzip();

                let imms = (0..proto.imm)
                    .map(|_pos| rng.gen_range(0..u128::MAX) as u128)
                    .collect::<Vec<_>>();
                (srcs_clear, srcs_enc, imms)
            })
            .collect::<Vec<_>>();

        let aggregated_res = test_inputs
        .iter()
        .map(|(srcs_clear, srcs_enc, imms)| {
            let res_hpu = {
                let local_proto = "[2]<N>::<N><0>".parse::<hpu_asm::IOpProto>().unwrap();
                let lsrcs_enc = srcs_enc.split_at(1);
                let hpu_enc_res_1 = HpuRadixCiphertext::exec(&local_proto, hpu_asm::IOpcode(33), &lsrcs_enc.0, imms, Some(hpu_asm::PhysId(device.config().fpga.node_id[0])));
                let hpu_enc_res_2 = HpuRadixCiphertext::exec(&local_proto, hpu_asm::IOpcode(33), &lsrcs_enc.1, imms, Some(hpu_asm::PhysId(device.config().fpga.node_id[1])));
                let combined_inputs = [hpu_enc_res_1[0].clone(),hpu_enc_res_2[0].clone()];
                let hpu_enc_res_3 = HpuRadixCiphertext::exec(&proto, hpu_asm::IOpcode(40), &combined_inputs, imms, Some(hpu_asm::PhysId(device.config().fpga.node_id[1])));
                let local_proto2 = "[2]<H>::<H><0>".parse::<hpu_asm::IOpProto>().unwrap();
                let hpu_enc_res_4 = HpuRadixCiphertext::exec(&local_proto2, hpu_asm::IOpcode(33), &[hpu_enc_res_3[0].clone()], imms, Some(hpu_asm::PhysId(device.config().fpga.node_id[1])));
                let hpu_enc_res_5 = HpuRadixCiphertext::exec(&local_proto2, hpu_asm::IOpcode(33), &[hpu_enc_res_3[1].clone()], imms, Some(hpu_asm::PhysId(device.config().fpga.node_id[0])));
                vec![hpu_enc_res_4[0].clone(), hpu_enc_res_5[0].clone()]
            };
            let res_fhe = res_hpu
                .iter()
                .map(|x| x.to_radix_ciphertext()).collect::<Vec<_>>();
            let res_clear = res_fhe
                .iter()
                .map(|x| cks.decrypt_radix(x))
                .collect::<Vec<u32>>();
            let res : u64 = (res_clear[0] as u64 + ((res_clear[1] as u64) << width / 2));
            let exp_res : u64 = ((srcs_clear[0] * srcs_clear[1]) % (1 << width)).try_into().unwrap();

            println!("[{:>4}] mhdma_test <{:>8x?}> => {:<4x?}-{:<4x?} {:<8x?} [exp {:<8x?}] {{Delta: {:x?} }}",
                $user_type::BITS,
                srcs_clear,
                res_clear[1],
                res_clear[0],
                res,
                exp_res,
                exp_res ^ res);
            (res == exp_res)
        }).fold(true, |acc, val| acc & val);
        aggregated_res
        })*
        }
        };
    }
    hpu_mhdma_test!(u32, u64);

    // NB: Currently remove mhdma_u32 from testbundle.
    // Indeed this new variant led to deadlock and need more investigation
    #[cfg(feature = "hpu")]
    hpu_testbundle!("mhdma"::[32,64] => [
        "mhdma_test"
    ]);
}
