#![allow(clippy::unnecessary_cast)]
//! Define a test-harness that handle setup and configuration of Hpu Backend
//! The test harness take a list of testcase and run them
//! A testcase simply bind a IOp to a closure describing it's behavior
//! WARN: Only one Hpu could be use at a time, thus all test must be run sequentially

#[cfg(feature = "hpu")]
mod hpu_test {
    use std::str::FromStr;

    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use tfhe::core_crypto::commons::generators::DeterministicSeeder;
    use tfhe::core_crypto::prelude::DefaultRandomGenerator;

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
                let lsb = rand::rng().next_u64() as u128;
                let msb = rand::rng().next_u64() as u128;
                (msb << u64::BITS) | lsb
            }
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
            HpuDevice::from_config(&config_file.expand())
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

    const DEFAULT_TEST_ITER: usize = 32;

    macro_rules! hpu_testbundle {
    ($base_name: literal::$integer_width:tt => [$($testcase: literal),+]) => {
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

    macro_rules! hpu_testcase {
    ($iop: literal => [$($user_type: ty),+] |$ct:ident, $imm: ident| $behav: expr) => {
        ::paste::paste! {
            $(
            #[cfg(feature = "hpu")]
            #[allow(unused)]
            pub fn [<hpu_ $iop:lower _ $user_type>](iter: usize, device: &mut HpuDevice, rng: &mut StdRng, cks: &tfhe::integer::ClientKey) -> bool {
                use tfhe::integer::hpu::ciphertext::HpuRadixCiphertext;

                // Check if user ask for test over trivial ciphertext
                let (test_trivial, sks) = match(std::env::var("HPU_TEST_TRIVIAL")){
                Ok(var) => {
                    let flag_val = usize::from_str(&var).unwrap_or_else(|_| {
                    panic!("HPU_TEST_TRIVIAL env variable {var} couldn't be casted in usize")
                    });
                    let sks_compressed =
                    tfhe::integer::ServerKey::new_radix_server_key(&cks);
                    (flag_val != 0, Some(sks_compressed))
                    },
                _ => (false, None)
                    };

                let iop = hpu_asm::AsmIOpcode::from_str($iop).expect("Invalid AsmIOpcode ");
                let proto = if let Some(format) = iop.format() {
                    format.proto.clone()
                } else {
                    eprintln!("Hpu testcase only work on specified operations. Check test definition");
                    return false;
                };

                let width = $user_type::BITS as usize;
                let num_block = width / device.params().pbs_params.message_width;
                (0..iter).map(|_| {
                    // Generate inputs ciphertext
                    let (srcs_clear, srcs_enc): (Vec<_>, Vec<_>) = proto
                        .src
                        .iter()
                        .enumerate()
                        .map(|(pos, mode)| {
                            let (bw, block) = match mode {
                                hpu_asm::iop::VarMode::Native => (width, num_block),
                                hpu_asm::iop::VarMode::Half => (width / 2, num_block / 2),
                                hpu_asm::iop::VarMode::Bool => (1, 1),
                            };

                            let clear = rng.gen_range(0..=$user_type::MAX >> ($user_type::BITS - (bw as u32)));
                            let fhe = if test_trivial {
                                sks.as_ref().unwrap().create_trivial_radix(clear, block)
                            } else {
                                cks.encrypt_radix(clear, block)
                            };
                            let hpu_fhe = HpuRadixCiphertext::from_radix_ciphertext(&fhe, device);
                            (clear, hpu_fhe)
                        })
                        .unzip();

                    let imms = (0..proto.imm)
                        .map(|pos| rng.gen_range(0..$user_type::MAX) as u128)
                        .collect::<Vec<_>>();

                    // execute on Hpu
                    let res_hpu = HpuRadixCiphertext::exec(&proto, iop.opcode(), &srcs_enc, &imms);
                    let res_fhe = res_hpu
                        .iter()
                        .map(|x| x.to_radix_ciphertext()).collect::<Vec<_>>();
                    let res = res_fhe
                        .iter()
                        .map(|x| cks.decrypt_radix(x))
                        .collect::<Vec<$user_type>>();

                    let exp_res = {
                        let $ct = &srcs_clear;
                        let $imm = imms.iter().map(|x| *x as $user_type).collect::<Vec<_>>();
                        ($behav.iter().map(|x| *x as $user_type).collect::<Vec<_>>())
                    };
                    println!("{:>8} <{:>8x?}> <{:>8x?}> => {:<8x?} [exp {:<8x?}] {{Delta: {:x?} }}", iop, srcs_clear, imms, res, exp_res, std::iter::zip(res.iter(), exp_res.iter()).map(|(x,y)| x ^y).collect::<Vec<_>>());
                    std::iter::zip(res.iter(), exp_res.iter()).map(|(x,y)| x== y).fold(true, |acc, val| acc & val)
                }).fold(true, |acc, val| acc & val)
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

    // ERC 20 found xfer
    hpu_testcase!("ERC_20" => [u8, u16, u32, u64, u128]
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

    // Define a set of test bundle for various size
    // 8bit ciphertext -----------------------------------------
    #[cfg(feature = "hpu")]
    hpu_testbundle!("alus"::8 => [
        "adds",
        "subs",
        "ssub",
        "muls",
        "divs",
        "mods"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("ovf_alus"::8 => [
        "ovf_adds",
        "ovf_subs",
        "ovf_ssub",
        "ovf_muls"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("rots"::8 => [
        "rots_r",
        "rots_l"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("shifts"::8 => [
        "shifts_r",
        "shifts_l"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("alu"::8 => [
        "add",
        "sub",
        "mul",
        "div",
        "mod"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("ovf_alu"::8 => [
        "ovf_add",
        "ovf_sub",
        "ovf_mul"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("rot"::8 => [
        "rot_r",
        "rot_l"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("shift"::8 => [
        "shift_r",
        "shift_l"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("bitwise"::8 => [
        "bw_and",
        "bw_or",
        "bw_xor"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("cmp"::8 => [
        "cmp_gt",
        "cmp_gte",
        "cmp_lt",
        "cmp_lte",
        "cmp_eq",
        "cmp_neq"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("ternary"::8 => [
        "if_then_zero",
        "if_then_else"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("algo"::8 => [
        "erc_20"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("cntbit"::8 => [
        "count0",
        "count1",
        "ilog2",
        "lead0",
        "lead1",
        "trail0",
        "trail1"
    ]);

    // 16bit ciphertext -----------------------------------------
    #[cfg(feature = "hpu")]
    hpu_testbundle!("alus"::16 => [
        "adds",
        "subs",
        "ssub",
        "muls",
        "divs",
        "mods"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("ovf_alus"::16 => [
        "ovf_adds",
        "ovf_subs",
        "ovf_ssub",
        "ovf_muls"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("rots"::16 => [
        "rots_r",
        "rots_l"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("shifts"::16 => [
        "shifts_r",
        "shifts_l"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("alu"::16 => [
        "add",
        "sub",
        "mul",
        "div",
        "mod"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("ovf_alu"::16 => [
        "ovf_add",
        "ovf_sub",
        "ovf_mul"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("rot"::16 => [
        "rot_r",
        "rot_l"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("shift"::16 => [
        "shift_r",
        "shift_l"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("bitwise"::16 => [
        "bw_and",
        "bw_or",
        "bw_xor"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("cmp"::16 => [
        "cmp_gt",
        "cmp_gte",
        "cmp_lt",
        "cmp_lte",
        "cmp_eq",
        "cmp_neq"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("ternary"::16 => [
        "if_then_zero",
        "if_then_else"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("algo"::16 => [
        "erc_20"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("cntbit"::16 => [
        "count0",
        "count1",
        "ilog2",
        "lead0",
        "lead1",
        "trail0",
        "trail1"
    ]);

    // 32bit ciphertext -----------------------------------------
    #[cfg(feature = "hpu")]
    hpu_testbundle!("alus"::32 => [
        "adds",
        "subs",
        "ssub",
        "muls",
        "divs",
        "mods"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("ovf_alus"::32 => [
        "ovf_adds",
        "ovf_subs",
        "ovf_ssub",
        "ovf_muls"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("rots"::32 => [
        "rots_r",
        "rots_l"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("shifts"::32 => [
        "shifts_r",
        "shifts_l"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("alu"::32 => [
        "add",
        "sub",
        "mul",
        "div",
        "mod"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("ovf_alu"::32 => [
        "ovf_add",
        "ovf_sub",
        "ovf_mul"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("rot"::32 => [
        "rot_r",
        "rot_l"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("shift"::32 => [
        "shift_r",
        "shift_l"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("bitwise"::32 => [
        "bw_and",
        "bw_or",
        "bw_xor"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("cmp"::32 => [
        "cmp_gt",
        "cmp_gte",
        "cmp_lt",
        "cmp_lte",
        "cmp_eq",
        "cmp_neq"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("ternary"::32 => [
        "if_then_zero",
        "if_then_else"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("algo"::32 => [
        "erc_20"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("cntbit"::32 => [
        "count0",
        "count1",
        "ilog2",
        "lead0",
        "lead1",
        "trail0",
        "trail1"
    ]);

    // 64bit ciphertext -----------------------------------------
    #[cfg(feature = "hpu")]
    hpu_testbundle!("alus"::64 => [
        "adds",
        "subs",
        "ssub",
        "muls",
        "divs",
        "mods"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("ovf_alus"::64 => [
        "ovf_adds",
        "ovf_subs",
        "ovf_ssub",
        "ovf_muls"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("rots"::64 => [
        "rots_r",
        "rots_l"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("shifts"::64 => [
        "shifts_r",
        "shifts_l"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("alu"::64 => [
        "add",
        "sub",
        "mul",
        "div",
        "mod"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("ovf_alu"::64 => [
        "ovf_add",
        "ovf_sub",
        "ovf_mul"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("rot"::64 => [
        "rot_r",
        "rot_l"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("shift"::64 => [
        "shift_r",
        "shift_l"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("bitwise"::64 => [
        "bw_and",
        "bw_or",
        "bw_xor"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("cmp"::64 => [
        "cmp_gt",
        "cmp_gte",
        "cmp_lt",
        "cmp_lte",
        "cmp_eq",
        "cmp_neq"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("ternary"::64 => [
        "if_then_zero",
        "if_then_else"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("algo"::64 => [
        "erc_20"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("cntbit"::64 => [
        "count0",
        "count1",
        "ilog2",
        "lead0",
        "lead1",
        "trail0",
        "trail1"
    ]);

    // 128bit ciphertext -----------------------------------------
    #[cfg(feature = "hpu")]
    hpu_testbundle!("alus"::128 => [
        "adds",
        "subs",
        "ssub",
        "muls",
        "divs",
        "mods"
    ]);

    hpu_testbundle!("ovf_alus"::128 => [
        "ovf_adds",
        "ovf_subs",
        "ovf_ssub",
        "ovf_muls"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("rots"::128 => [
        "rots_r",
        "rots_l"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("shifts"::128 => [
        "shifts_r",
        "shifts_l"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("alu"::128 => [
        "add",
        "sub",
        "mul",
        "div",
        "mod"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("ovf_alu"::128 => [
        "ovf_add",
        "ovf_sub",
        "ovf_mul"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("rot"::128 => [
        "rot_r",
        "rot_l"
    ]);
    #[cfg(feature = "hpu")]
    hpu_testbundle!("shift"::128 => [
        "shift_r",
        "shift_l"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("bitwise"::128 => [
        "bw_and",
        "bw_or",
        "bw_xor"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("cmp"::128 => [
        "cmp_gt",
        "cmp_gte",
        "cmp_lt",
        "cmp_lte",
        "cmp_eq",
        "cmp_neq"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("ternary"::128 => [
        "if_then_zero",
        "if_then_else"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("algo"::128 => [
        "erc_20"
    ]);

    #[cfg(feature = "hpu")]
    hpu_testbundle!("cntbit"::128 => [
        "count0",
        "count1",
        "ilog2",
        "lead0",
        "lead1",
        "trail0",
        "trail1"
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
}
