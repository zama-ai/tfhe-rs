//! Define a test-harness that handle setup and configuration of Hpu Backend
//! The test harness take a list of testcase and run them
//! A testcase simlpy bind a IOp to a closure describing it's behavior
//! WARN: Only one Hpu could be use at a time, thus all test must be run sequentially
pub use serial_test::serial;
use std::str::FromStr;

pub use rand::Rng;
pub use tfhe_hpu_backend::prelude::*;

/// Variable to store initialized HpuDevice and associated client key for fast iteration
static HPU_DEVICE_CKS: std::sync::OnceLock<(
    std::sync::Mutex<HpuDevice>,
    tfhe::integer::ClientKey,
)> = std::sync::OnceLock::new();

// NB: Currently u55c didn't check for workq overflow.
// -> Use default value < queue depth to circumvent this limitation
// NB': This is only for u55c, on V80 user could set HPU_TEST_ITER to whatever value he want
const DEFAULT_TEST_ITER: usize = 32;

#[macro_export]
macro_rules! hpu_testbundle {
    ($base_name: literal::$integer_width:tt => [$($testcase: literal),+]) => {
    ::paste::paste! {
        #[test]
        #[serial]
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
            // Retrieved test iteration from environnement ----------------------------
            let hpu_test_iter = match(std::env::var("HPU_TEST_ITER")){
                Ok(var) => usize::from_str(&var).unwrap_or_else(|_| {
                    panic!("HPU_TEST_ITER env variable {var} couldn't be casted in usize")
                }),
                _ => DEFAULT_TEST_ITER
            };

            // Retrived HpuDevice or init ---------------------------------------------
            let (hpu_mutex, cks)= HPU_DEVICE_CKS.get_or_init(|| {
                // Instanciate HpuDevice --------------------------------------------------
                let hpu_device = {
                    let config_file = ShellString::new(
                        "${HPU_BACKEND_DIR}/config_store/${HPU_CONFIG}/hpu_config.toml".to_string(),
                    );
                    HpuDevice::from_config(&config_file.expand())
                };

                // Extract pbs_configuration from Hpu and create Client/Server Key
                let cks = tfhe::integer::ClientKey::new(tfhe::shortint::ClassicPBSParameters::from(
                    hpu_device.params(),
                ));
                let sks_compressed = tfhe::integer::CompressedServerKey::new_radix_compressed_server_key(&cks);

                // Init Hpu device with server key and firmware
                tfhe::integer::hpu::init_device(&hpu_device, sks_compressed.into());
                (std::sync::Mutex::new(hpu_device), cks)
            });
            let mut hpu_device = hpu_mutex.lock().expect("Error with HpuDevice Mutex");
            assert!(hpu_device.config().firmware.integer_w.contains(&($integer_width as usize)), "Current Hpu configuration doesn't support {}b integer [has {:?}]", $integer_width, hpu_device.config().firmware.integer_w);

            // Run test-case ---------------------------------------------------------
            let mut acc_status = true;
            $(
                {
                let status = [<hpu_ $testcase _u $integer_width>](hpu_test_iter, &mut hpu_device, &cks);
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
            #[allow(unused)]
            pub fn [<hpu_ $iop:lower _ $user_type>](iter: usize, device: &mut HpuDevice, cks: &tfhe::integer::ClientKey) -> bool {
                use tfhe::integer::hpu::ciphertext::HpuRadixCiphertext;

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

                            let clear = rand::thread_rng().gen_range(0..$user_type::MAX >> ($user_type::BITS - (bw as u32)));
                            let fhe = cks.encrypt_radix(clear, block);
                            let hpu_fhe = HpuRadixCiphertext::from_radix_ciphertext(&fhe, device);
                            (clear, hpu_fhe)
                        })
                        .unzip();

                    let imms = (0..proto.imm)
                        .map(|pos| rand::thread_rng().gen_range(0..$user_type::MAX) as u128)
                        .collect::<Vec<_>>();

                    // execute on Hpu
                    let res_hpu = HpuRadixCiphertext::exec(&proto, iop.opcode(), &srcs_enc, &imms);
                    let res_fhe = res_hpu
                        .iter()
                        .map(|x| x.to_radix_ciphertext()).collect::<Vec<_>>();
                    let res_vec = res_fhe
                        .iter()
                        .map(|x| cks.decrypt_radix(x))
                        .collect::<Vec<$user_type>>();
                    let res = res_vec[0];

                    let exp_res = {
                        let $ct = &srcs_clear;
                        let $imm = imms.iter().map(|x| *x as $user_type).collect::<Vec<_>>();
                        ($behav as $user_type)
                    };
                    println!("{:>8} <{:>8x?}> <{:>8x?}> => {:<8x} [exp {:<8x}] {{Delta: 0b {:b} }}", iop, srcs_clear, imms, res, exp_res, res ^ exp_res);

                    res == exp_res
                }).fold(true, |acc, val| acc & val)
            }
        )*
        }
    };
}

// Define testcase implementation for all supported IOp
// Alu IOp with Ct x Imm
hpu_testcase!("ADDS" => [u8, u16, u32, u64, u128]
    |ct, imm| (ct[0].wrapping_add(imm[0])));
hpu_testcase!("SUBS" => [u8, u16, u32, u64, u128]
    |ct, imm| (ct[0].wrapping_sub(imm[0])));
hpu_testcase!("SSUB" => [u8, u16, u32, u64, u128]
    |ct, imm| (imm[0].wrapping_sub(ct[0])));
hpu_testcase!("MULS" => [u8, u16, u32, u64, u128]
    |ct, imm| (ct[0].wrapping_mul(imm[0])));

// Alu IOp with Ct x Ct
hpu_testcase!("ADD" => [u8, u16, u32, u64, u128]
    |ct, imm| (ct[0].wrapping_add(ct[1])));
hpu_testcase!("ADDK" => [u8, u16, u32, u64, u128]
    |ct, imm| (ct[0].wrapping_add(ct[1])));
hpu_testcase!("SUB" => [u8, u16, u32, u64, u128]
    |ct, imm| (ct[0].wrapping_sub(ct[1])));
hpu_testcase!("SUBK" => [u8, u16, u32, u64, u128]
    |ct, imm| (ct[0].wrapping_sub(ct[1])));
hpu_testcase!("MUL" => [u8, u16, u32, u64, u128]
    |ct, imm| (ct[0].wrapping_mul(ct[1])));

// Bitwise IOp
hpu_testcase!("BW_AND" => [u8, u16, u32, u64, u128]
    |ct, imm| (ct[0] & ct[1]));
hpu_testcase!("BW_OR" => [u8, u16, u32, u64, u128]
    |ct, imm| (ct[0] | ct[1]));
hpu_testcase!("BW_XOR" => [u8, u16, u32, u64, u128]
    |ct, imm| (ct[0] ^ ct[1]));

// Comparaison IOp
hpu_testcase!("CMP_GT" => [u8, u16, u32, u64, u128]
    |ct, imm| (ct[0] > ct[1]));
hpu_testcase!("CMP_GTE" => [u8, u16, u32, u64, u128]
    |ct, imm| (ct[0] >= ct[1]));
hpu_testcase!("CMP_LT" => [u8, u16, u32, u64, u128]
    |ct, imm| (ct[0] < ct[1]));
hpu_testcase!("CMP_LTE" => [u8, u16, u32, u64, u128]
    |ct, imm| (ct[0] <= ct[1]));
hpu_testcase!("CMP_EQ" => [u8, u16, u32, u64, u128]
    |ct, imm| (ct[0] == ct[1]));
hpu_testcase!("CMP_NEQ" => [u8, u16, u32, u64, u128]
    |ct, imm| (ct[0] != ct[1]));

// Ternary IOp
hpu_testcase!("IF_THEN_ELSE" => [u8, u16, u32, u64, u128]
    |ct, imm| if ct[2] != 0 {ct[0]} else { ct[1]});

// Define a set of test bundle for various size
// 8bit ciphertext -----------------------------------------
#[cfg(feature = "hpu")]
crate::hpu_testbundle!("alus"::8 => [
    "adds",
    "subs",
    "ssub",
    "muls"
]);

#[cfg(feature = "hpu")]
crate::hpu_testbundle!("alu"::8 => [
    "add",
    "addk",
    "sub",
    "subk",
    "mul"
]);

#[cfg(feature = "hpu")]
crate::hpu_testbundle!("bitwise"::8 => [
    "bw_and",
    "bw_or",
    "bw_xor"
]);

#[cfg(feature = "hpu")]
crate::hpu_testbundle!("cmp"::8 => [
    "cmp_gt",
    "cmp_gte",
    "cmp_lt",
    "cmp_lte",
    "cmp_eq",
    "cmp_neq"
]);

#[cfg(feature = "hpu")]
crate::hpu_testbundle!("ternary"::8 => [
    "if_then_else"
]);

// 16bit ciphertext -----------------------------------------
#[cfg(feature = "hpu")]
crate::hpu_testbundle!("alus"::16 => [
    "adds",
    "subs",
    "ssub",
    "muls"
]);

#[cfg(feature = "hpu")]
crate::hpu_testbundle!("alu"::16 => [
    "add",
    "addk",
    "sub",
    "subk",
    "mul"
]);

#[cfg(feature = "hpu")]
crate::hpu_testbundle!("bitwise"::16 => [
    "bw_and",
    "bw_or",
    "bw_xor"
]);

#[cfg(feature = "hpu")]
crate::hpu_testbundle!("cmp"::16 => [
    "cmp_gt",
    "cmp_gte",
    "cmp_lt",
    "cmp_lte",
    "cmp_eq",
    "cmp_neq"
]);

#[cfg(feature = "hpu")]
crate::hpu_testbundle!("ternary"::16 => [
    "if_then_else"
]);

// 32bit ciphertext -----------------------------------------
#[cfg(feature = "hpu")]
crate::hpu_testbundle!("alus"::32 => [
    "adds",
    "subs",
    "ssub",
    "muls"
]);

#[cfg(feature = "hpu")]
crate::hpu_testbundle!("alu"::32 => [
    "add",
    "addk",
    "sub",
    "subk",
    "mul"
]);

#[cfg(feature = "hpu")]
crate::hpu_testbundle!("bitwise"::32 => [
    "bw_and",
    "bw_or",
    "bw_xor"
]);

#[cfg(feature = "hpu")]
crate::hpu_testbundle!("cmp"::32 => [
    "cmp_gt",
    "cmp_gte",
    "cmp_lt",
    "cmp_lte",
    "cmp_eq",
    "cmp_neq"
]);

#[cfg(feature = "hpu")]
crate::hpu_testbundle!("ternary"::32 => [
    "if_then_else"
]);

// 64bit ciphertext -----------------------------------------
#[cfg(feature = "hpu")]
crate::hpu_testbundle!("alus"::64 => [
    "adds",
    "subs",
    "ssub",
    "muls"
]);

#[cfg(feature = "hpu")]
crate::hpu_testbundle!("alu"::64 => [
    "add",
    "addk",
    "sub",
    "subk",
    "mul"
]);

#[cfg(feature = "hpu")]
crate::hpu_testbundle!("bitwise"::64 => [
    "bw_and",
    "bw_or",
    "bw_xor"
]);

#[cfg(feature = "hpu")]
crate::hpu_testbundle!("cmp"::64 => [
    "cmp_gt",
    "cmp_gte",
    "cmp_lt",
    "cmp_lte",
    "cmp_eq",
    "cmp_neq"
]);

#[cfg(feature = "hpu")]
crate::hpu_testbundle!("ternary"::64 => [
    "if_then_else"
]);

// 128bit ciphertext -----------------------------------------
#[cfg(feature = "hpu")]
crate::hpu_testbundle!("alus"::128 => [
    "adds",
    "subs",
    "ssub",
    "muls"
]);

#[cfg(feature = "hpu")]
crate::hpu_testbundle!("alu"::128 => [
    "add",
    "addk",
    "sub",
    "subk",
    "mul"
]);

#[cfg(feature = "hpu")]
crate::hpu_testbundle!("bitwise"::128 => [
    "bw_and",
    "bw_or",
    "bw_xor"
]);

#[cfg(feature = "hpu")]
crate::hpu_testbundle!("cmp"::128 => [
    "cmp_gt",
    "cmp_gte",
    "cmp_lt",
    "cmp_lte",
    "cmp_eq",
    "cmp_neq"
]);

#[cfg(feature = "hpu")]
crate::hpu_testbundle!("ternary"::128 => [
    "if_then_else"
]);
