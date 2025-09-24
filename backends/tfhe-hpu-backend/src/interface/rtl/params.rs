//!
//! Extract architecture properties from RTL registers
//! Read Rtl parameters from registers.
//! NB: Some registers contains encoded value that must be converted to concrete one (i.e.
//! apps/ntt_moduls)
use parameters::HpuNttPrime;

use super::*;
use crate::entities::*;

// Set of constant defined in RTL and associated rust definition
// -> Cf. fpga/hw/common_lib/common_package/rtl/common_definition_pkg.sv
pub const NTT_CORE_ARCH_OFS: u32 = 5 << 8;
pub const MOD_NTT_NAME_OFS: u32 = 6 << 8;
pub const APPLICATION_NAME_OFS: u32 = 7 << 8;
pub const SIMULATION_CODE: u32 = 1;

impl FromRtl for HpuParameters {
    fn from_rtl(ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) -> Self {
        let pbs_params = HpuPBSParameters::from_rtl(ffi_hw, regmap);
        let ntt_params = HpuNttParameters::from_rtl(ffi_hw, regmap);
        let ks_params = HpuKeyswitchParameters::from_rtl(ffi_hw, regmap);
        let pc_params = HpuPcParameters::from_rtl(ffi_hw, regmap);
        let regf_params = HpuRegfileParameters::from_rtl(ffi_hw, regmap);
        let isc_params = HpuIscParameters::from_rtl(ffi_hw, regmap);
        Self {
            pbs_params,
            ntt_params,
            ks_params,
            pc_params,
            regf_params,
            isc_params,
        }
    }
}

impl FromRtl for HpuKeyswitchParameters {
    fn from_rtl(ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) -> Self {
        let ks_shape = regmap
            .register()
            .get("info::ks_structure")
            .expect("Unknown register, check regmap definition");
        let shape_val = ffi_hw.read_reg(*ks_shape.offset() as u64);
        let shape_fields = ks_shape.as_field(shape_val);

        let ks_info = regmap
            .register()
            .get("info::ks_crypto_param")
            .expect("Unknown register, check regmap definition");
        let info_val = ffi_hw.read_reg(*ks_info.offset() as u64);
        let info_fields = ks_info.as_field(info_val);

        Self {
            width: *info_fields.get("mod_ksk_w").expect("Unknown field") as usize,
            lbx: *shape_fields.get("x").expect("Unknown field") as usize,
            lby: *shape_fields.get("y").expect("Unknown field") as usize,
            lbz: *shape_fields.get("z").expect("Unknown field") as usize,
        }
    }
}
impl FromRtl for HpuNttParameters {
    fn from_rtl(ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) -> Self {
        let core_arch = HpuNttCoreArch::from_rtl(ffi_hw, regmap);

        // Values extracted from NttInternal register
        let ntt_internal = regmap
            .register()
            .get("info::ntt_structure")
            .expect("Unknown register, check regmap definition");
        let internal_val = ffi_hw.read_reg(*ntt_internal.offset() as u64);
        let internal_fields = ntt_internal.as_field(internal_val);

        let radix = *internal_fields.get("radix").expect("Unknown field") as usize;
        let psi = *internal_fields.get("psi").expect("Unknown field") as usize;
        let delta = *internal_fields.get("delta").expect("Unknown field") as usize;

        // Values extracted from NttInternal register
        let ntt_pbs_nb = regmap
            .register()
            .get("info::ntt_pbs")
            .expect("Unknown register, check regmap definition");
        let pbs_nb_val = ffi_hw.read_reg(*ntt_pbs_nb.offset() as u64);
        let pbs_nb_fields = ntt_pbs_nb.as_field(pbs_nb_val);

        let batch_pbs_nb = *pbs_nb_fields.get("batch_pbs_nb").expect("Unknown field") as usize;
        let total_pbs_nb = *pbs_nb_fields.get("total_pbs_nb").expect("Unknown field") as usize;

        // Values extracted from NttModulo register
        // Modulus isn't directly expressed, instead used custom encoding
        let ntt_modulo = regmap
            .register()
            .get("info::ntt_modulo")
            .expect("Unknown register, check regmap definition");
        let ntt_modulo_val = ffi_hw.read_reg(*ntt_modulo.offset() as u64);

        let prime_modulus = {
            // Check register encoding
            let field_code = ntt_modulo_val & (!0xFF_u32);
            assert_eq!(
                field_code, MOD_NTT_NAME_OFS,
                "Invalid register encoding. Check register map definition"
            );
            match (ntt_modulo_val & 0xFF) as u8 {
                enum_id if enum_id == HpuNttPrime::GF64 as u8 => HpuNttPrime::GF64,
                enum_id if enum_id == HpuNttPrime::Solinas3_32_17_13 as u8 => {
                    HpuNttPrime::Solinas3_32_17_13
                }
                enum_id if enum_id == HpuNttPrime::Solinas2_44_14 as u8 => {
                    HpuNttPrime::Solinas2_44_14
                }
                _ => panic!("Unknown NttModName encoding"),
            }
        };

        // Values extracted from Application
        // Not the cleanest way but some required ntt information are only available in the
        // parameters set Thus parse extract HpuPBSParameters inside HpuNttParameters
        let pbs_params = HpuPBSParameters::from_rtl(ffi_hw, regmap);
        let stg_nb = pbs_params.polynomial_size.ilog(radix) as usize;

        Self {
            core_arch,
            min_pbs_nb: None, // TODO: Get this from a register
            batch_pbs_nb,
            total_pbs_nb,
            ct_width: pbs_params.ciphertext_width as u32,
            radix,
            stg_nb,
            prime_modulus,
            psi,
            delta,
        }
    }
}

impl FromRtl for HpuNttCoreArch {
    fn from_rtl(ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) -> Self {
        // Values extracted from NttModulo register
        // Modulus isn't directly expressed, instead used custom encoding
        let ntt_core_arch = regmap
            .register()
            .get("info::ntt_architecture")
            .expect("Unknown register, check regmap definition");
        let ntt_core_arch_val = ffi_hw.read_reg(*ntt_core_arch.offset() as u64);

        // Check register encoding
        let field_code = ntt_core_arch_val & (!0xFF_u32);
        assert_eq!(
            field_code, NTT_CORE_ARCH_OFS,
            "Invalid register encoding. Check register map definition"
        );

        match ntt_core_arch_val & 0xFF {
            // NB: Previous arch aren't supported anymore
            3 => Self::WmmCompactPcg,
            4 => Self::WmmUnfoldPcg,
            5 => {
                // Extract associated radix split

                let radix_cut = regmap
                    .register()
                    .get("info::ntt_rdx_cut")
                    .expect("Unknown register, check regmap definition");
                let radix_cut_val = ffi_hw.read_reg(*radix_cut.offset() as u64);
                let cut_l = (0..(u32::BITS / 4))
                    .map(|ofst| ((radix_cut_val >> (ofst * 4)) & 0xf) as u8)
                    .filter(|x| *x != 0)
                    .collect::<Vec<u8>>();
                Self::GF64(cut_l)
            }
            _ => panic!("Unknown NttCoreArch encoding"),
        }
    }
}

impl FromRtl for HpuPcParameters {
    fn from_rtl(ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) -> Self {
        // Extract number of Pc for each channel
        let hbm_pc = regmap
            .register()
            .get("info::hbm_axi4_nb")
            .expect("Unknown register, check regmap definition");
        let hbm_pc_val = ffi_hw.read_reg(*hbm_pc.offset() as u64);
        let hbm_pc_fields = hbm_pc.as_field(hbm_pc_val);

        let ksk_pc = *hbm_pc_fields.get("ksk_pc").expect("Unknown field") as usize;
        let bsk_pc = *hbm_pc_fields.get("bsk_pc").expect("Unknown field") as usize;
        let pem_pc = *hbm_pc_fields.get("pem_pc").expect("Unknown field") as usize;
        let glwe_pc = *hbm_pc_fields.get("glwe_pc").expect("Unknown field") as usize;

        // Extract bus width for each channel
        let ksk_bytes_w = {
            let ksk_axi4_data_w = regmap
                .register()
                .get("info::hbm_axi4_dataw_ksk")
                .expect("Unknown register, check regmap definition");
            let ksk_axi4_data_w_val = ffi_hw.read_reg(*ksk_axi4_data_w.offset() as u64);
            // Value is in bit in rtl and SW expect bytes
            ksk_axi4_data_w_val.div_ceil(u8::BITS) as usize
        };
        let bsk_bytes_w = {
            let bsk_axi4_data_w = regmap
                .register()
                .get("info::hbm_axi4_dataw_bsk")
                .expect("Unknown register, check regmap definition");
            let bsk_axi4_data_w_val = ffi_hw.read_reg(*bsk_axi4_data_w.offset() as u64);
            // Value is in bit in rtl and SW expect bytes
            bsk_axi4_data_w_val.div_ceil(u8::BITS) as usize
        };
        let pem_bytes_w = {
            let pem_axi4_data_w = regmap
                .register()
                .get("info::hbm_axi4_dataw_pem")
                .expect("Unknown register, check regmap definition");
            let pem_axi4_data_w_val = ffi_hw.read_reg(*pem_axi4_data_w.offset() as u64);
            // Value is in bit in rtl and SW expect bytes
            pem_axi4_data_w_val.div_ceil(u8::BITS) as usize
        };
        let glwe_bytes_w = {
            let glwe_axi4_data_w = regmap
                .register()
                .get("info::hbm_axi4_dataw_glwe")
                .expect("Unknown register, check regmap definition");
            let glwe_axi4_data_w_val = ffi_hw.read_reg(*glwe_axi4_data_w.offset() as u64);
            // Value is in bit in rtl and SW expect bytes
            glwe_axi4_data_w_val.div_ceil(u8::BITS) as usize
        };

        Self {
            ksk_pc,
            bsk_pc,
            pem_pc,
            glwe_pc,
            ksk_bytes_w,
            bsk_bytes_w,
            pem_bytes_w,
            glwe_bytes_w,
        }
    }
}

impl FromRtl for HpuRegfileParameters {
    fn from_rtl(ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) -> Self {
        let regf = regmap
            .register()
            .get("info::regf_structure")
            .expect("Unknown register, check regmap definition");
        let regf_val = ffi_hw.read_reg(*regf.offset() as u64);
        let regf_fields = regf.as_field(regf_val);

        Self {
            reg_nb: *regf_fields.get("reg_nb").expect("Unknown field") as usize,
            coef_nb: *regf_fields.get("coef_nb").expect("Unknown field") as usize,
        }
    }
}

impl FromRtl for HpuIscParameters {
    fn from_rtl(ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) -> Self {
        let isc = regmap
            .register()
            .get("info::isc_structure")
            .expect("Unknown register, check regmap definition");
        let isc_val = ffi_hw.read_reg(*isc.offset() as u64);
        let isc_fields = isc.as_field(isc_val);

        Self {
            min_iop_size: *isc_fields.get("min_iop_size").expect("Unknown field") as usize,
            depth: *isc_fields.get("depth").expect("Unknown field") as usize,
        }
    }
}

// Define parameters set as constants
// Used to easily derived IoMeasure version without duplication
pub const CONCRETE_BOOLEAN: HpuPBSParameters = HpuPBSParameters {
    lwe_dimension: 586,
    glwe_dimension: 2,
    polynomial_size: 512,
    lwe_noise_distribution: HpuNoiseDistributionInput::GaussianStdDev(0.00000000007069849454709433),
    glwe_noise_distribution: HpuNoiseDistributionInput::GaussianStdDev(
        0.0000000000000000000029403601535432533,
    ),
    pbs_base_log: 8,
    pbs_level: 2,
    ks_base_log: 5,
    ks_level: 4,
    message_width: 1,
    carry_width: 0,
    ciphertext_width: 32,
    log2_p_fail: -64.0,
    modulus_switch_type: parameters::HpuModulusSwitchType::Standard,
};

pub const MSG2_CARRY2: HpuPBSParameters = HpuPBSParameters {
    lwe_dimension: 742,
    glwe_dimension: 1,
    polynomial_size: 2048,
    lwe_noise_distribution: HpuNoiseDistributionInput::GaussianStdDev(9.039_924_320_497_611e-6_f64),
    glwe_noise_distribution: HpuNoiseDistributionInput::GaussianStdDev(3.1529314934984704e-16_f64),
    pbs_base_log: 19,
    pbs_level: 1,
    ks_base_log: 3,
    ks_level: 5,
    message_width: 2,
    carry_width: 2,
    ciphertext_width: u64::BITS as usize,
    log2_p_fail: -64.0,
    modulus_switch_type: parameters::HpuModulusSwitchType::Standard,
};

pub const MSG2_CARRY2_64B: HpuPBSParameters = HpuPBSParameters {
    lwe_dimension: 710,
    glwe_dimension: 2,
    polynomial_size: 1024,
    lwe_noise_distribution: HpuNoiseDistributionInput::GaussianStdDev(1.630_783_646_854_603e-5_f64),
    glwe_noise_distribution: HpuNoiseDistributionInput::GaussianStdDev(3.1529314934984704e-16_f64),
    pbs_base_log: 25,
    pbs_level: 1,
    ks_base_log: 2,
    ks_level: 7,
    message_width: 2,
    carry_width: 2,
    ciphertext_width: u64::BITS as usize,
    log2_p_fail: -64.0,
    modulus_switch_type: parameters::HpuModulusSwitchType::Standard,
};

pub const MSG2_CARRY2_44B: HpuPBSParameters = HpuPBSParameters {
    lwe_dimension: 724,
    glwe_dimension: 2,
    polynomial_size: 1024,
    lwe_noise_distribution: HpuNoiseDistributionInput::GaussianStdDev(
        1.259_780_968_897_627_7e-5_f64,
    ),
    glwe_noise_distribution: HpuNoiseDistributionInput::GaussianStdDev(2.2737367544323206e-13_f64),
    pbs_base_log: 20,
    pbs_level: 1,
    ks_base_log: 2,
    ks_level: 7,
    message_width: 2,
    carry_width: 2,
    ciphertext_width: 44,
    log2_p_fail: -64.0,
    modulus_switch_type: parameters::HpuModulusSwitchType::Standard,
};

pub const MSG2_CARRY2_64B_FAKE: HpuPBSParameters = HpuPBSParameters {
    lwe_dimension: 724,
    glwe_dimension: 2,
    polynomial_size: 1024,
    lwe_noise_distribution: HpuNoiseDistributionInput::GaussianStdDev(
        1.259_780_968_897_627_7e-5_f64,
    ),
    glwe_noise_distribution: HpuNoiseDistributionInput::GaussianStdDev(2.2737367544323206e-13_f64),
    pbs_base_log: 20,
    pbs_level: 1,
    ks_base_log: 2,
    ks_level: 7,
    message_width: 2,
    carry_width: 2,
    ciphertext_width: 64,
    log2_p_fail: -64.0,
    modulus_switch_type: parameters::HpuModulusSwitchType::Standard,
};

pub const MSG2_CARRY2_GAUSSIAN: HpuPBSParameters = HpuPBSParameters {
    lwe_dimension: 834,
    glwe_dimension: 1,
    polynomial_size: 2048,
    lwe_noise_distribution: HpuNoiseDistributionInput::GaussianStdDev(
        3.553_990_235_944_282_5e-6_f64,
    ),
    glwe_noise_distribution: HpuNoiseDistributionInput::GaussianStdDev(2.845267479601915e-15_f64),
    pbs_base_log: 23,
    pbs_level: 1,
    ks_base_log: 3,
    ks_level: 5,
    message_width: 2,
    carry_width: 2,
    ciphertext_width: 64,
    log2_p_fail: -64.0,
    modulus_switch_type: parameters::HpuModulusSwitchType::Standard,
};

pub const MSG2_CARRY2_TUNIFORM: HpuPBSParameters = HpuPBSParameters {
    lwe_dimension: 887,
    glwe_dimension: 1,
    polynomial_size: 2048,
    lwe_noise_distribution: HpuNoiseDistributionInput::GaussianStdDev(
        3.553_990_235_944_282_5e-6_f64,
    ),
    glwe_noise_distribution: HpuNoiseDistributionInput::GaussianStdDev(2.845267479601915e-15_f64),
    pbs_base_log: 22,
    pbs_level: 1,
    ks_base_log: 3,
    ks_level: 5,
    message_width: 2,
    carry_width: 2,
    ciphertext_width: 64,
    log2_p_fail: -64.0,
    modulus_switch_type: parameters::HpuModulusSwitchType::Standard,
};

pub const MSG2_CARRY2_PFAIL64_132B_GAUSSIAN_1F72DBA: HpuPBSParameters = HpuPBSParameters {
    lwe_dimension: 804,
    glwe_dimension: 1,
    polynomial_size: 2048,
    lwe_noise_distribution: HpuNoiseDistributionInput::GaussianStdDev(5.963_599_673_924_788e-6_f64),
    glwe_noise_distribution: HpuNoiseDistributionInput::GaussianStdDev(2.8452674713391114e-15_f64),
    pbs_base_log: 23,
    pbs_level: 1,
    ks_base_log: 2,
    ks_level: 8,
    message_width: 2,
    carry_width: 2,
    ciphertext_width: 64,
    log2_p_fail: -64.0,
    modulus_switch_type: parameters::HpuModulusSwitchType::Standard,
};

pub const MSG2_CARRY2_PFAIL64_132B_TUNIFORM_7E47D8C: HpuPBSParameters = HpuPBSParameters {
    lwe_dimension: 839,
    glwe_dimension: 1,
    polynomial_size: 2048,
    lwe_noise_distribution: HpuNoiseDistributionInput::TUniformBound(4),
    glwe_noise_distribution: HpuNoiseDistributionInput::TUniformBound(17),
    pbs_base_log: 23,
    pbs_level: 1,
    ks_base_log: 2,
    ks_level: 7,
    message_width: 2,
    carry_width: 2,
    ciphertext_width: 64,
    log2_p_fail: -64.0,
    modulus_switch_type: parameters::HpuModulusSwitchType::Standard,
};

pub const MSG2_CARRY2_PFAIL128_132B_TUNIFORM_144A47: HpuPBSParameters = HpuPBSParameters {
    lwe_dimension: 879,
    glwe_dimension: 1,
    polynomial_size: 2048,
    lwe_noise_distribution: HpuNoiseDistributionInput::TUniformBound(3),
    glwe_noise_distribution: HpuNoiseDistributionInput::TUniformBound(17),
    pbs_base_log: 23,
    pbs_level: 1,
    ks_base_log: 2,
    ks_level: 8,
    message_width: 2,
    carry_width: 2,
    ciphertext_width: 64,
    log2_p_fail: -128.0,
    modulus_switch_type: parameters::HpuModulusSwitchType::CenteredMeanNoiseReduction,
};

impl FromRtl for HpuPBSParameters {
    fn from_rtl(ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) -> Self {
        let pbs_app = regmap
            .register()
            .get("info::application")
            .expect("Unknown register, check regmap definition");
        let pbs_app_val = ffi_hw.read_reg(*pbs_app.offset() as u64);

        // Check register encoding
        let field_code = pbs_app_val & (!0xFF_u32);
        #[cfg(not(any(feature = "hw-xrt", feature = "hw-v80")))]
        {
            if (field_code == 0) && (pbs_app_val == SIMULATION_CODE) {
                tracing::warn!("Run an simulation backend with custom SIMU parameters set");
                return ffi_hw.get_pbs_parameters();
            }
        }
        #[cfg(any(feature = "hw-xrt", feature = "hw-v80"))]
        {
            assert_eq!(
                field_code, APPLICATION_NAME_OFS,
                "Invalid register encoding. Check register map definition"
            );
        }

        match pbs_app_val & 0xFF {
            0 => CONCRETE_BOOLEAN,
            1 => MSG2_CARRY2,
            2 => {
                let mut params = MSG2_CARRY2;
                params.lwe_dimension = 2;
                params
            }
            3 => MSG2_CARRY2_64B,
            4 => MSG2_CARRY2_44B,
            9 => MSG2_CARRY2_64B_FAKE,
            10 => MSG2_CARRY2_GAUSSIAN,
            11 => MSG2_CARRY2_TUNIFORM,
            12 => MSG2_CARRY2_PFAIL64_132B_GAUSSIAN_1F72DBA,
            13 => MSG2_CARRY2_PFAIL64_132B_TUNIFORM_7E47D8C,
            14 => MSG2_CARRY2_PFAIL128_132B_TUNIFORM_144A47,
            _ => panic!("Unknown TfheAppName encoding"),
        }
    }
}
