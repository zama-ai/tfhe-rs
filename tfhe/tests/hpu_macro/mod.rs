//! Define a test-harness that handle setup and configuration of Hpu Backend
//! The test harness take a list of testcase and run them
//! A testcase simlpy bind a IOp to a closure describing it's behavior

// WARN: Only one Hpu could be use at a time, thus all test must be run sequentially
// #[cfg(feature = "hpu-xfer")]
// mod hpu_test {

pub use serial_test::serial;
use std::str::FromStr;

pub use hpu_asm::strum::IntoEnumIterator;
pub use hpu_asm::{Asm, IOp, IOpName};
pub use tfhe::prelude::*;
pub use tfhe::*;
pub use tfhe_hpu_backend::prelude::*;

pub use rand::Rng;

// NB: Currently backend don't check workq overflow.
// To prevent issue, we prevent overflow with test_case == queue_depth
const TEST_ITER: usize = 32;

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

            // Instanciate HpuDevice --------------------------------------------------
            // NB: Change working dir to top level repository
            // -> Enable to have stable path in configuration file
            std::env::set_current_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()).unwrap();

            let mut hpu_device = {
                let mut config = HpuConfig::read_from("backends/tfhe-hpu-backend/config/hpu_config.toml");
                config.firmware.integer_w = vec![$integer_width];
                HpuDevice::new(config)
            };

            // Extract pbs_configuration from Hpu and generate top-level config
            let pbs_params = tfhe::shortint::PBSParameters::PBS(hpu_device.params().into());
            let config = ConfigBuilder::default()
                .use_custom_parameters(pbs_params)
                .build();

            let (cks, sks) = generate_keys(config);
            let sks_compressed = cks.generate_compressed_server_key();

            // Init cpu side server keys
            set_server_key(sks);

            // Init Hpu device with server key and firmware
            tfhe::integer::hpu::init_device(&hpu_device, sks_compressed.into());

            // Run test-case ---------------------------------------------------------
            let mut acc_status = true;
            $(
                {
                let status = [<hpu_ $testcase _u $integer_width>](&mut hpu_device, &cks);
                if !status {
                    println!("Error: in testcase {}", stringify!([<hpu_ $testcase _u $integer_width>]));
                }
                acc_status &= status
                }
            )*

            assert!(acc_status, "At least one testcase failed in the testbundle");
       }
    }
    };
}

macro_rules! hpu_testcase {
    ($iop: literal => [$(($fhe_type: ty, $user_type: ty)),+] |$a:ident, $b: ident| $behav: expr) => {
        ::paste::paste! {
            $(
            #[allow(unused)]
            pub fn [<hpu_ $iop:lower _ $user_type>](device: &mut HpuDevice, cks: &ClientKey) -> bool {
                let iop = IOpName::from_str($iop).expect("Invalid IOp name");
                let imm_fmt = IOp::from(iop).has_imm();

                (0..TEST_ITER).map(|_| {
                    // Generate clear value
                    let a =
                        rand::thread_rng().gen_range(0..$user_type::MAX);
                    let b =
                        rand::thread_rng().gen_range(0..$user_type::MAX);

                    // Encrypt on cpu side
                    let a_fhe = $fhe_type::encrypt(a, cks);
                    let b_fhe = $fhe_type::encrypt(b, cks);

                    // Copy value in Hpu world
                    let a_hpu = a_fhe.clone_on(device);
                    let b_hpu = b_fhe.clone_on(device);


                    // execute on Hpu
                    let res_hpu = if imm_fmt {
                        a_hpu.iop_imm(iop, b as usize)
                    } else {
                        a_hpu.iop_ct(iop, b_hpu.clone())
                    };
                    let res_fhe = $fhe_type::from(res_hpu);
                    let res: $user_type = res_fhe.decrypt(cks);

                    let exp_res = {
                        let $a = a;
                        let $b = b;
                        ($behav as $user_type)
                    };
                    println!("{:>8x} {:>8} {:<8x} => {:<8x} [exp {:<8x}] {{Delta: 0b {:b} }}", a, iop, b, res, exp_res, res ^ exp_res);

                    res == exp_res
                }).fold(true, |acc, val| acc & val)
            }
        )*
        }
    };
}

// Define testcase implementation for all supported IOp
// Alu IOp with Ct x Imm
hpu_testcase!("ADDS" => [(FheUint8, u8),(FheUint16, u16), (FheUint32, u32), (FheUint64, u64)]
    |a, b| (a.wrapping_add(b)));
hpu_testcase!("SUBS" => [(FheUint8, u8),(FheUint16, u16), (FheUint32, u32), (FheUint64, u64)]
    |a, b| (a.wrapping_sub(b)));
hpu_testcase!("SSUB" => [(FheUint8, u8),(FheUint16, u16), (FheUint32, u32), (FheUint64, u64)]
    |a, b| (b.wrapping_sub(a)));
hpu_testcase!("MULS" => [(FheUint8, u8),(FheUint16, u16), (FheUint32, u32), (FheUint64, u64)]
    |a, b| (a.wrapping_mul(b)));

// Alu IOp with Ct x Ct
hpu_testcase!("ADD" => [(FheUint8, u8),(FheUint16, u16), (FheUint32, u32), (FheUint64, u64)]
    |a, b| (a.wrapping_add(b)));
hpu_testcase!("SUB" => [(FheUint8, u8),(FheUint16, u16), (FheUint32, u32), (FheUint64, u64)]
    |a, b| (a.wrapping_sub(b)));
hpu_testcase!("MUL" => [(FheUint8, u8),(FheUint16, u16), (FheUint32, u32), (FheUint64, u64)]
    |a, b| (a.wrapping_mul(b)));

// Bitwise IOp
hpu_testcase!("BW_AND" => [(FheUint8, u8),(FheUint16, u16), (FheUint32, u32), (FheUint64, u64)]
    |a, b| (a & b));
hpu_testcase!("BW_OR" => [(FheUint8, u8),(FheUint16, u16), (FheUint32, u32), (FheUint64, u64)]
    |a, b| (a | b));
hpu_testcase!("BW_XOR" => [(FheUint8, u8),(FheUint16, u16), (FheUint32, u32), (FheUint64, u64)]
    |a, b| (a ^ b));

// Comparaison IOp
hpu_testcase!("CMP_GT" => [(FheUint8, u8),(FheUint16, u16), (FheUint32, u32), (FheUint64, u64)]
    |a, b| (a > b));
hpu_testcase!("CMP_GTE" => [(FheUint8, u8),(FheUint16, u16), (FheUint32, u32), (FheUint64, u64)]
    |a, b| (a >= b));
hpu_testcase!("CMP_LT" => [(FheUint8, u8),(FheUint16, u16), (FheUint32, u32), (FheUint64, u64)]
    |a, b| (a < b));
hpu_testcase!("CMP_LTE" => [(FheUint8, u8),(FheUint16, u16), (FheUint32, u32), (FheUint64, u64)]
    |a, b| (a <= b));
hpu_testcase!("CMP_EQ" => [(FheUint8, u8),(FheUint16, u16), (FheUint32, u32), (FheUint64, u64)]
    |a, b| (a == b));
hpu_testcase!("CMP_NEQ" => [(FheUint8, u8),(FheUint16, u16), (FheUint32, u32), (FheUint64, u64)]
    |a, b| (a != b));
// }
