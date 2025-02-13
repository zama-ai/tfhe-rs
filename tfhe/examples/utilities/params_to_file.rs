use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use tfhe::boolean::parameters::{BooleanParameters, VEC_BOOLEAN_PARAM};
use tfhe::core_crypto::commons::parameters::{GlweDimension, LweDimension, PolynomialSize};
use tfhe::core_crypto::prelude::{DynamicDistribution, TUniform, UnsignedInteger};
use tfhe::keycache::NamedParam;
use tfhe::shortint::parameters::classic::compact_pk::ALL_PARAMETER_VEC_COMPACT_PK;
use tfhe::shortint::parameters::classic::gaussian::ALL_PARAMETER_VEC_GAUSSIAN;
use tfhe::shortint::parameters::compact_public_key_only::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use tfhe::shortint::parameters::multi_bit::ALL_MULTI_BIT_PARAMETER_VEC;
use tfhe::shortint::parameters::{
    CompactPublicKeyEncryptionParameters, CompressionParameters, ShortintParameterSet,
    COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
};

pub trait ParamDetails<T: UnsignedInteger> {
    fn lwe_dimension(&self) -> LweDimension;
    fn glwe_dimension(&self) -> GlweDimension;
    fn lwe_noise_distribution(&self) -> DynamicDistribution<T>;
    fn glwe_noise_distribution(&self) -> DynamicDistribution<T>;
    fn polynomial_size(&self) -> PolynomialSize;
    fn log_ciphertext_modulus(&self) -> usize;
}

impl ParamDetails<u32> for BooleanParameters {
    fn lwe_dimension(&self) -> LweDimension {
        self.lwe_dimension
    }

    fn glwe_dimension(&self) -> GlweDimension {
        self.glwe_dimension
    }

    fn lwe_noise_distribution(&self) -> DynamicDistribution<u32> {
        self.lwe_noise_distribution
    }
    fn glwe_noise_distribution(&self) -> DynamicDistribution<u32> {
        self.glwe_noise_distribution
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    fn log_ciphertext_modulus(&self) -> usize {
        32
    }
}

impl ParamDetails<u64> for ShortintParameterSet {
    fn lwe_dimension(&self) -> LweDimension {
        self.lwe_dimension()
    }

    fn glwe_dimension(&self) -> GlweDimension {
        self.glwe_dimension()
    }

    fn lwe_noise_distribution(&self) -> DynamicDistribution<u64> {
        self.lwe_noise_distribution()
    }
    fn glwe_noise_distribution(&self) -> DynamicDistribution<u64> {
        self.glwe_noise_distribution()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size()
    }

    fn log_ciphertext_modulus(&self) -> usize {
        assert!(self.ciphertext_modulus().is_native_modulus());
        64
    }
}

impl ParamDetails<u64> for CompactPublicKeyEncryptionParameters {
    fn lwe_dimension(&self) -> LweDimension {
        self.encryption_lwe_dimension
    }

    fn glwe_dimension(&self) -> GlweDimension {
        panic!("glwe_dimension not applicable for compact public-key encryption parameters")
    }

    fn lwe_noise_distribution(&self) -> DynamicDistribution<u64> {
        self.encryption_noise_distribution
    }
    fn glwe_noise_distribution(&self) -> DynamicDistribution<u64> {
        panic!(
            "glwe_noise_distribution not applicable for compact public-key encryption parameters"
        )
    }

    fn polynomial_size(&self) -> PolynomialSize {
        panic!("polynomial_size not applicable for compact public-key encryption parameters")
    }

    fn log_ciphertext_modulus(&self) -> usize {
        assert!(self.ciphertext_modulus.is_native_modulus());
        64
    }
}

impl ParamDetails<u64> for CompressionParameters {
    fn lwe_dimension(&self) -> LweDimension {
        panic!("lwe_dimension not applicable for compression parameters")
    }

    fn glwe_dimension(&self) -> GlweDimension {
        self.packing_ks_glwe_dimension
    }

    fn lwe_noise_distribution(&self) -> DynamicDistribution<u64> {
        panic!("lwe_noise_distribution not applicable for compression parameters")
    }
    fn glwe_noise_distribution(&self) -> DynamicDistribution<u64> {
        self.packing_ks_key_noise_distribution
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.packing_ks_polynomial_size
    }

    fn log_ciphertext_modulus(&self) -> usize {
        64
    }
}

#[derive(Eq, PartialEq, Hash)]
enum ParametersFormat {
    Lwe,
    Glwe,
    LweGlwe,
}

type NoiseDistributionString = String;
type LogCiphertextModulus = usize;

#[derive(Eq, PartialEq, Hash)]
struct ParamGroupKey {
    lwe_dimension: LweDimension,
    log_ciphertext_modulus: LogCiphertextModulus,
    noise_distribution: NoiseDistributionString,
    parameters_format: ParametersFormat,
}

///Function to print in the lattice_estimator format the parameters
/// Format:   LWE.Parameters(n=722, q=2^32, Xs=ND.UniformMod(2),
/// Xe=ND.DiscreteGaussian(56139.60810663548), tag='test_lattice_estimator')
pub fn format_lwe_parameters_to_lattice_estimator<
    U: UnsignedInteger,
    T: ParamDetails<U> + NamedParam,
>(
    param: &T,
    similar_params: Vec<String>,
) -> String {
    let name = param.name();

    match param.lwe_noise_distribution() {
        DynamicDistribution::Gaussian(distrib) => {
            let modular_std_dev =
                param.log_ciphertext_modulus() as f64 + distrib.standard_dev().0.log2();

            format!(
                "{}_LWE = LWE.Parameters(\n n = {},\n q ={},\n Xs=ND.Uniform(0,1), \n Xe=ND.DiscreteGaussian({}),\n tag=('{}_lwe',) \n)\n\n",
                name, param.lwe_dimension().0, (1u128<<param.log_ciphertext_modulus() as u128), 2.0_f64.powf(modular_std_dev), similar_params.join("_lwe', '"))
        }
        DynamicDistribution::TUniform(distrib) => {
            format!(
                "{}_LWE = LWE.Parameters(\n n = {},\n q ={},\n Xs=ND.Uniform(0,1), \n Xe=ND.DiscreteGaussian({}),\n tag=('{}_lwe',) \n)\n\n",
                name, param.lwe_dimension().0, (1u128<<param.log_ciphertext_modulus() as u128), tuniform_equivalent_gaussian_std_dev(&distrib), similar_params.join("_lwe', '"))
        }
    }
}

///Function to print in the lattice_estimator format the parameters
/// Format: LWE.Parameters(n=722, q=2^32, Xs=ND.UniformMod(2),
/// Xe=ND.DiscreteGaussian(56139.60810663548), tag='test_lattice_estimator')
pub fn format_glwe_parameters_to_lattice_estimator<
    U: UnsignedInteger,
    T: ParamDetails<U> + NamedParam,
>(
    param: &T,
    similar_params: Vec<String>,
) -> String {
    let name = param.name();

    match param.glwe_noise_distribution() {
        DynamicDistribution::Gaussian(distrib) => {
            let modular_std_dev =
                param.log_ciphertext_modulus() as f64 + distrib.standard_dev().0.log2();

            format!(
                "{}_GLWE = LWE.Parameters(\n n = {},\n q = {},\n Xs=ND.Uniform(0,1), \n Xe=ND.DiscreteGaussian({}),\n tag=('{}_glwe',) \n)\n\n",
                name, param.glwe_dimension().to_equivalent_lwe_dimension(param.polynomial_size()).0, 1u128<<param.log_ciphertext_modulus() as u128, 2.0_f64.powf(modular_std_dev), similar_params.join("_glwe', '"))
        }
        DynamicDistribution::TUniform(distrib) => {
            format!(
                "{}_GLWE = LWE.Parameters(\n n = {},\n q ={},\n Xs=ND.Uniform(0,1), \n Xe=ND.DiscreteGaussian({}),\n tag=('{}_glwe',) \n)\n\n",
                name, param.glwe_dimension().to_equivalent_lwe_dimension(param.polynomial_size()).0, 1u128<<param.log_ciphertext_modulus() as u128, tuniform_equivalent_gaussian_std_dev(&distrib), similar_params.join("_glwe', '"))
        }
    }
}

fn tuniform_equivalent_gaussian_std_dev<U: UnsignedInteger>(distribution: &TUniform<U>) -> f64 {
    f64::sqrt((2_f64.powf(2.0 * distribution.bound_log2() as f64 + 1_f64) + 1_f64) / 6_f64)
}

fn write_file(file: &mut File, filename: &Path, line: impl Into<String>) {
    let error_message = format!("unable to write file {}", filename.to_str().unwrap());
    file.write_all(line.into().as_bytes())
        .expect(&error_message);
}

fn write_all_params_in_file<U: UnsignedInteger, T: ParamDetails<U> + Copy + NamedParam>(
    filename: &str,
    params: &[T],
    format: ParametersFormat,
) {
    let path = Path::new(filename);
    File::create(path).expect("create results file failed");
    let mut file = OpenOptions::new()
        .append(true)
        .open(path)
        .expect("cannot open parsed results file");

    let mut params_groups: HashMap<ParamGroupKey, Vec<T>> = HashMap::new();

    for params in params.iter() {
        // TODO remetter le if d'avant avec le ||
        //  il va falloir adapter la manière de pousser dans le vecteur (faire un insert() ?)
        let keys = match format {
            ParametersFormat::LweGlwe => vec![
                ParamGroupKey {
                    lwe_dimension: params.lwe_dimension(),
                    log_ciphertext_modulus: params.log_ciphertext_modulus(),
                    noise_distribution: params.lwe_noise_distribution().to_string(),
                    parameters_format: ParametersFormat::Lwe,
                },
                ParamGroupKey {
                    lwe_dimension: params
                        .glwe_dimension()
                        .to_equivalent_lwe_dimension(params.polynomial_size()),
                    log_ciphertext_modulus: params.log_ciphertext_modulus(),
                    noise_distribution: params.glwe_noise_distribution().to_string(),
                    parameters_format: ParametersFormat::Glwe,
                },
            ],
            ParametersFormat::Lwe => vec![ParamGroupKey {
                lwe_dimension: params.lwe_dimension(),
                log_ciphertext_modulus: params.log_ciphertext_modulus(),
                noise_distribution: params.lwe_noise_distribution().to_string(),
                parameters_format: ParametersFormat::Lwe,
            }],
            ParametersFormat::Glwe => vec![ParamGroupKey {
                lwe_dimension: params
                    .glwe_dimension()
                    .to_equivalent_lwe_dimension(params.polynomial_size()),
                log_ciphertext_modulus: params.log_ciphertext_modulus(),
                noise_distribution: params.glwe_noise_distribution().to_string(),
                parameters_format: ParametersFormat::Glwe,
            }],
        };

        for key in keys.into_iter() {
            match params_groups.get_mut(&key) {
                Some(vec) => {
                    vec.push(*params);
                }
                None => {
                    let mut vec = Vec::new();
                    vec.push(*params);
                    params_groups.insert(key, vec);
                }
            };
        }
    }

    let mut param_names_augmented = Vec::new();

    for (key, group) in params_groups.iter() {
        let similar_params = group.iter().map(|p| p.name()).collect::<Vec<String>>();
        let ref_param = group[0];
        let formatted_param = match key.parameters_format {
            ParametersFormat::Lwe => {
                param_names_augmented.push(format!("{}_LWE", ref_param.name()));
                format_lwe_parameters_to_lattice_estimator(&ref_param, similar_params)
            }
            ParametersFormat::Glwe => {
                param_names_augmented.push(format!("{}_GLWE", ref_param.name()));
                format_glwe_parameters_to_lattice_estimator(&ref_param, similar_params)
            }
            ParametersFormat::LweGlwe => panic!("formatted parameters cannot be LweGlwe"),
        };
        write_file(&mut file, path, formatted_param);
    }

    let all_params = format!("all_params = [\n{}\n]\n", param_names_augmented.join(","));
    write_file(&mut file, path, all_params);
}

fn main() {
    let work_dir = std::env::current_dir().unwrap();
    let mut new_work_dir = work_dir;
    new_work_dir.push("ci");
    std::env::set_current_dir(new_work_dir).unwrap();

    write_all_params_in_file(
        "boolean_parameters_lattice_estimator.sage",
        &VEC_BOOLEAN_PARAM,
        ParametersFormat::LweGlwe,
    );

    let all_classic_pbs = [
        ALL_PARAMETER_VEC_GAUSSIAN.to_vec(),
        ALL_PARAMETER_VEC_COMPACT_PK.to_vec(),
        vec![PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64],
    ]
    .concat();
    let classic_pbs = all_classic_pbs
        .iter()
        .map(|p| ShortintParameterSet::from(*p))
        .collect::<Vec<_>>();
    write_all_params_in_file(
        "shortint_classic_parameters_lattice_estimator.sage",
        &classic_pbs,
        ParametersFormat::LweGlwe,
    );

    let multi_bit_pbs = ALL_MULTI_BIT_PARAMETER_VEC
        .iter()
        .map(|p| ShortintParameterSet::from(*p))
        .collect::<Vec<_>>();
    write_all_params_in_file(
        "shortint_multi_bit_parameters_lattice_estimator.sage",
        &multi_bit_pbs,
        ParametersFormat::LweGlwe,
    );

    write_all_params_in_file(
        "shortint_cpke_parameters_lattice_estimator.sage",
        &[V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64],
        ParametersFormat::Lwe,
    );

    write_all_params_in_file(
        "shortint_list_compression_parameters_lattice_estimator.sage",
        &[COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64],
        ParametersFormat::Glwe,
    );

    // TODO perform this gathering later
    // let wopbs = ALL_PARAMETER_VEC_WOPBS
    //     .iter()
    //     .map(|p| ShortintParameterSet::from(*p))
    //     .collect::<Vec<_>>();
    // write_all_params_in_file(
    //     "shortint_wopbs_parameters_lattice_estimator.sage",
    //     &wopbs,
    // );
}
