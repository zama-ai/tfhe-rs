use itertools::Itertools;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use tfhe::boolean::parameters::{BooleanParameters, VEC_BOOLEAN_PARAM};
use tfhe::core_crypto::commons::parameters::{GlweDimension, LweDimension, PolynomialSize};
use tfhe::core_crypto::prelude::{CiphertextModulus, DynamicDistribution, UnsignedInteger};
use tfhe::keycache::NamedParam;
use tfhe::shortint::parameters::current_params::{
    VEC_ALL_CLASSIC_PBS_PARAMETERS, VEC_ALL_COMPACT_PUBLIC_KEY_ENCRYPTION_PARAMETERS,
    VEC_ALL_COMPRESSION_PARAMETERS, VEC_ALL_HPU_PARAMETERS, VEC_ALL_KS32_PARAMETERS,
    VEC_ALL_MULTI_BIT_PBS_PARAMETERS, VEC_ALL_NOISE_SQUASHING_COMPRESSION_PARAMETERS,
    VEC_ALL_NOISE_SQUASHING_MULTI_BIT_PARAMETERS, VEC_ALL_NOISE_SQUASHING_PARAMETERS,
};
use tfhe::shortint::parameters::noise_squashing::NoiseSquashingMultiBitParameters;
use tfhe::shortint::parameters::{
    CompactPublicKeyEncryptionParameters, CompressionParameters,
    NoiseSquashingCompressionParameters, NoiseSquashingParameters,
};
use tfhe::shortint::AtomicPatternParameters;

#[derive(Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum ParamModulus {
    NativeU128,
    Other(u128),
}
impl ParamModulus {
    fn from_ciphertext_modulus<Scalar: UnsignedInteger>(
        ct_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        let scalar_bits = ct_modulus.associated_scalar_bits();
        assert!(scalar_bits <= 128, "ciphertext modulus is too large");

        if ct_modulus.is_native_modulus() {
            if scalar_bits == 128 {
                ParamModulus::NativeU128
            } else {
                ParamModulus::Other(1u128.checked_shl(scalar_bits as u32).unwrap())
            }
        } else {
            ParamModulus::Other(ct_modulus.get_custom_modulus())
        }
    }

    fn as_f64(&self) -> f64 {
        match self {
            Self::NativeU128 => 2.0_f64.powi(128),
            Self::Other(u) => *u as f64,
        }
    }
}

pub trait ParamDetails<T: UnsignedInteger> {
    fn lwe_dimension(&self) -> LweDimension;
    fn glwe_dimension(&self) -> GlweDimension;
    fn lwe_noise_distribution(&self) -> DynamicDistribution<T>;
    fn glwe_noise_distribution(&self) -> DynamicDistribution<T>;
    fn polynomial_size(&self) -> PolynomialSize;
    fn lwe_ciphertext_modulus(&self) -> ParamModulus;
    fn glwe_ciphertext_modulus(&self) -> ParamModulus;
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

    fn lwe_ciphertext_modulus(&self) -> ParamModulus {
        ParamModulus::Other(1u128.checked_shl(u32::BITS).unwrap())
    }

    fn glwe_ciphertext_modulus(&self) -> ParamModulus {
        ParamModulus::Other(1u128.checked_shl(u32::BITS).unwrap())
    }
}

impl ParamDetails<u64> for AtomicPatternParameters {
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

    fn lwe_ciphertext_modulus(&self) -> ParamModulus {
        match self {
            Self::Standard(p) => ParamModulus::from_ciphertext_modulus(p.ciphertext_modulus()),
            Self::KeySwitch32(p) => {
                ParamModulus::from_ciphertext_modulus(p.post_keyswitch_ciphertext_modulus)
            }
        }
    }

    fn glwe_ciphertext_modulus(&self) -> ParamModulus {
        ParamModulus::from_ciphertext_modulus(self.ciphertext_modulus())
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

    fn lwe_ciphertext_modulus(&self) -> ParamModulus {
        ParamModulus::from_ciphertext_modulus(self.ciphertext_modulus)
    }

    fn glwe_ciphertext_modulus(&self) -> ParamModulus {
        panic!(
            "glwe_ciphertext_modulus not applicable for compact public-key encryption parameters"
        )
    }
}

impl ParamDetails<u64> for CompressionParameters {
    fn lwe_dimension(&self) -> LweDimension {
        panic!("lwe_dimension not applicable for compression parameters")
    }

    fn glwe_dimension(&self) -> GlweDimension {
        self.packing_ks_glwe_dimension()
    }

    fn lwe_noise_distribution(&self) -> DynamicDistribution<u64> {
        panic!("lwe_noise_distribution not applicable for compression parameters")
    }
    fn glwe_noise_distribution(&self) -> DynamicDistribution<u64> {
        self.packing_ks_key_noise_distribution()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.packing_ks_polynomial_size()
    }

    fn lwe_ciphertext_modulus(&self) -> ParamModulus {
        panic!("lwe_ciphertext_modulus not applicable for compression parameters")
    }

    fn glwe_ciphertext_modulus(&self) -> ParamModulus {
        ParamModulus::from_ciphertext_modulus(CiphertextModulus::<u64>::new_native())
    }
}

impl ParamDetails<u128> for NoiseSquashingParameters {
    fn lwe_dimension(&self) -> LweDimension {
        panic!("lwe_dimension not applicable for NoiseSquashingParameters")
    }

    fn glwe_dimension(&self) -> GlweDimension {
        self.glwe_dimension()
    }

    fn lwe_noise_distribution(&self) -> DynamicDistribution<u128> {
        panic!("lwe_noise_distribution not applicable for NoiseSquashingParameters")
    }

    fn glwe_noise_distribution(&self) -> DynamicDistribution<u128> {
        self.glwe_noise_distribution()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size()
    }

    fn lwe_ciphertext_modulus(&self) -> ParamModulus {
        panic!("lwe_ciphertext_modulus not applicable for NoiseSquashingParameters")
    }

    fn glwe_ciphertext_modulus(&self) -> ParamModulus {
        ParamModulus::from_ciphertext_modulus(self.ciphertext_modulus())
    }
}

impl ParamDetails<u128> for NoiseSquashingMultiBitParameters {
    fn lwe_dimension(&self) -> LweDimension {
        panic!("lwe_dimension not applicable for NoiseSquashingMultiBitParameters")
    }

    fn glwe_dimension(&self) -> GlweDimension {
        self.glwe_dimension
    }

    fn lwe_noise_distribution(&self) -> DynamicDistribution<u128> {
        panic!("lwe_noise_distribution not applicable for NoiseSquashingMultiBitParameters")
    }

    fn glwe_noise_distribution(&self) -> DynamicDistribution<u128> {
        self.glwe_noise_distribution
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    fn lwe_ciphertext_modulus(&self) -> ParamModulus {
        panic!("lwe_ciphertext_modulus not applicable for NoiseSquashingMultiBitParameters")
    }

    fn glwe_ciphertext_modulus(&self) -> ParamModulus {
        ParamModulus::from_ciphertext_modulus(self.ciphertext_modulus)
    }
}

impl ParamDetails<u128> for NoiseSquashingCompressionParameters {
    fn lwe_dimension(&self) -> LweDimension {
        panic!("lwe_dimension not applicable for NoiseSquashingCompressionParameters")
    }

    fn glwe_dimension(&self) -> GlweDimension {
        self.packing_ks_glwe_dimension
    }

    fn lwe_noise_distribution(&self) -> DynamicDistribution<u128> {
        panic!("lwe_noise_distribution not applicable for NoiseSquashingCompressionParameters")
    }

    fn glwe_noise_distribution(&self) -> DynamicDistribution<u128> {
        self.packing_ks_key_noise_distribution
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.packing_ks_polynomial_size
    }

    fn lwe_ciphertext_modulus(&self) -> ParamModulus {
        panic!("lwe_ciphertext_modulus not applicable for NoiseSquashingCompressionParameters")
    }

    fn glwe_ciphertext_modulus(&self) -> ParamModulus {
        ParamModulus::from_ciphertext_modulus(self.ciphertext_modulus)
    }
}

#[derive(Eq, PartialEq, Hash, Ord, PartialOrd)]
enum ParametersFormat {
    Lwe,
    Glwe,
    LweGlwe,
}

type NoiseDistributionString = String;

#[derive(Eq, PartialEq, Hash, Ord, PartialOrd)]
struct ParamGroupKey {
    lwe_dimension: LweDimension,
    ciphertext_modulus: ParamModulus,
    noise_distribution: NoiseDistributionString,
    // TODO might not need to be hashed since LWE and GLWE share the same security check
    parameters_format: ParametersFormat,
}

fn format_modulus_as_string(modulus: ParamModulus) -> String {
    match modulus {
        ParamModulus::NativeU128 => {
            // What are you gonna do, call the police ?
            "340282366920938463463374607431768211456".to_string()
        }
        ParamModulus::Other(u) => {
            format!("{u}")
        }
    }
}

///Function to print in the lattice_estimator format the parameters
/// Format:   LWE.Parameters(n=722, q=2^32, Xs=ND.UniformMod(2),
/// Xe=ND.DiscreteGaussian(56139.60810663548), tag='test_lattice_estimator')
pub fn format_lwe_parameters_to_lattice_estimator<U: UnsignedInteger, T: ParamDetails<U>>(
    (param, name): (&T, &str),
    similar_params: &[&str],
) -> String {
    match param.lwe_noise_distribution() {
        DynamicDistribution::Gaussian(distrib) => {
            let modular_std_dev =
                (param.lwe_ciphertext_modulus().as_f64() * distrib.standard_dev().0).log2();

            format!(
                "{}_LWE = LWE.Parameters(\n n = {},\n q ={},\n Xs=ND.Uniform(0,1), \n \
                Xe=ND.DiscreteGaussian({}),\n tag=('{}_lwe',) \n)\n\n",
                name,
                param.lwe_dimension().0,
                format_modulus_as_string(param.lwe_ciphertext_modulus()),
                2.0_f64.powf(modular_std_dev),
                similar_params.join("_lwe', '")
            )
        }
        DynamicDistribution::TUniform(distrib) => {
            format!(
                "{}_LWE = LWE.Parameters(\n n = {},\n q ={},\n Xs=ND.Uniform(0,1), \n \
                Xe=ND.TUniform({}),\n tag=('{}_lwe',) \n)\n\n",
                name,
                param.lwe_dimension().0,
                format_modulus_as_string(param.lwe_ciphertext_modulus()),
                distrib.bound_log2(),
                similar_params.join("_lwe', '")
            )
        }
    }
}

///Function to print in the lattice_estimator format the parameters
/// Format: LWE.Parameters(n=722, q=2^32, Xs=ND.UniformMod(2),
/// Xe=ND.DiscreteGaussian(56139.60810663548), tag='test_lattice_estimator')
pub fn format_glwe_parameters_to_lattice_estimator<U: UnsignedInteger, T: ParamDetails<U>>(
    (param, name): (&T, &str),
    similar_params: &[&str],
) -> String {
    match param.glwe_noise_distribution() {
        DynamicDistribution::Gaussian(distrib) => {
            let modular_std_dev =
                (param.glwe_ciphertext_modulus().as_f64() * distrib.standard_dev().0).log2();

            format!(
                "{}_GLWE = LWE.Parameters(\n n = {},\n q = {},\n Xs=ND.Uniform(0,1), \n \
                Xe=ND.DiscreteGaussian({}),\n tag=('{}_glwe',) \n)\n\n",
                name,
                param
                    .glwe_dimension()
                    .to_equivalent_lwe_dimension(param.polynomial_size())
                    .0,
                format_modulus_as_string(param.glwe_ciphertext_modulus()),
                2.0_f64.powf(modular_std_dev),
                similar_params.join("_glwe', '")
            )
        }
        DynamicDistribution::TUniform(distrib) => {
            format!(
                "{}_GLWE = LWE.Parameters(\n n = {},\n q ={},\n Xs=ND.Uniform(0,1), \n \
                Xe=ND.TUniform({}),\n tag=('{}_glwe',) \n)\n\n",
                name,
                param
                    .glwe_dimension()
                    .to_equivalent_lwe_dimension(param.polynomial_size())
                    .0,
                format_modulus_as_string(param.glwe_ciphertext_modulus()),
                distrib.bound_log2(),
                similar_params.join("_glwe', '")
            )
        }
    }
}

fn write_file(file: &mut File, filename: &Path, line: impl Into<String>) {
    let error_message = format!("unable to write file {}", filename.to_str().unwrap());
    file.write_all(line.into().as_bytes())
        .expect(&error_message);
}

fn write_all_params_in_file<U: UnsignedInteger, T: ParamDetails<U> + Copy + NamedParam>(
    filename: &str,
    params: &[(T, Option<&str>)],
    format: ParametersFormat,
) {
    let path = Path::new(filename);
    File::create(path).expect("create results file failed");
    let mut file = OpenOptions::new()
        .append(true)
        .open(path)
        .expect("cannot open parsed results file");

    let mut params_groups: HashMap<ParamGroupKey, Vec<(T, String)>> = HashMap::new();

    for (params, optional_name) in params.iter() {
        let keys = match format {
            ParametersFormat::LweGlwe => vec![
                ParamGroupKey {
                    lwe_dimension: params.lwe_dimension(),
                    ciphertext_modulus: params.lwe_ciphertext_modulus(),
                    noise_distribution: params.lwe_noise_distribution().to_string(),
                    parameters_format: ParametersFormat::Lwe,
                },
                ParamGroupKey {
                    lwe_dimension: params
                        .glwe_dimension()
                        .to_equivalent_lwe_dimension(params.polynomial_size()),
                    ciphertext_modulus: params.glwe_ciphertext_modulus(),
                    noise_distribution: params.glwe_noise_distribution().to_string(),
                    parameters_format: ParametersFormat::Glwe,
                },
            ],
            ParametersFormat::Lwe => vec![ParamGroupKey {
                lwe_dimension: params.lwe_dimension(),
                ciphertext_modulus: params.lwe_ciphertext_modulus(),
                noise_distribution: params.lwe_noise_distribution().to_string(),
                parameters_format: ParametersFormat::Lwe,
            }],
            ParametersFormat::Glwe => vec![ParamGroupKey {
                lwe_dimension: params
                    .glwe_dimension()
                    .to_equivalent_lwe_dimension(params.polynomial_size()),
                ciphertext_modulus: params.glwe_ciphertext_modulus(),
                noise_distribution: params.glwe_noise_distribution().to_string(),
                parameters_format: ParametersFormat::Glwe,
            }],
        };

        for key in keys.into_iter() {
            match params_groups.get_mut(&key) {
                Some(vec) => {
                    vec.push((
                        *params,
                        optional_name.map_or_else(|| params.name(), |name| name.to_string()),
                    ));
                }
                None => {
                    params_groups.insert(
                        key,
                        vec![(
                            *params,
                            optional_name.map_or_else(|| params.name(), |name| name.to_string()),
                        )],
                    );
                }
            };
        }
    }

    let ordered_params_groups = params_groups
        .keys()
        .sorted()
        .map(|k| (k, params_groups.get(k).unwrap()));

    let mut param_names_augmented = Vec::new();

    for (key, group) in ordered_params_groups {
        let similar_params = group.iter().map(|p| p.1.as_str()).collect::<Vec<_>>();
        let (ref_param, ref_param_name) = &group[0];
        let formatted_param = match key.parameters_format {
            ParametersFormat::Lwe => {
                param_names_augmented.push(format!("{ref_param_name}_LWE"));
                format_lwe_parameters_to_lattice_estimator(
                    (ref_param, ref_param_name.as_str()),
                    &similar_params,
                )
            }
            ParametersFormat::Glwe => {
                param_names_augmented.push(format!("{ref_param_name}_GLWE"));
                format_glwe_parameters_to_lattice_estimator(
                    (ref_param, ref_param_name.as_str()),
                    &similar_params,
                )
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

    let boolean_params: Vec<_> = VEC_BOOLEAN_PARAM.into_iter().map(|p| (p, None)).collect();
    write_all_params_in_file(
        "boolean_parameters_lattice_estimator.sage",
        &boolean_params,
        ParametersFormat::LweGlwe,
    );

    let classic_pbs: Vec<_> = VEC_ALL_CLASSIC_PBS_PARAMETERS
        .into_iter()
        .map(|p| (AtomicPatternParameters::from(*p.0), Some(p.1)))
        .collect();
    write_all_params_in_file(
        "shortint_classic_parameters_lattice_estimator.sage",
        &classic_pbs,
        ParametersFormat::LweGlwe,
    );

    let multi_bit_pbs: Vec<_> = VEC_ALL_MULTI_BIT_PBS_PARAMETERS
        .into_iter()
        .map(|p| (AtomicPatternParameters::from(*p.0), Some(p.1)))
        .collect();
    write_all_params_in_file(
        "shortint_multi_bit_parameters_lattice_estimator.sage",
        &multi_bit_pbs,
        ParametersFormat::LweGlwe,
    );

    let cpk_params: Vec<_> = VEC_ALL_COMPACT_PUBLIC_KEY_ENCRYPTION_PARAMETERS
        .into_iter()
        .map(|p| (*p.0, Some(p.1)))
        .collect();
    write_all_params_in_file(
        "shortint_cpke_parameters_lattice_estimator.sage",
        &cpk_params,
        ParametersFormat::Lwe,
    );

    let comp_params: Vec<_> = VEC_ALL_COMPRESSION_PARAMETERS
        .into_iter()
        .map(|p| (*p.0, Some(p.1)))
        .collect();
    write_all_params_in_file(
        "shortint_list_compression_parameters_lattice_estimator.sage",
        &comp_params,
        ParametersFormat::Glwe,
    );

    let noise_squasing_params: Vec<_> = VEC_ALL_NOISE_SQUASHING_PARAMETERS
        .into_iter()
        .map(|p| (*p.0, Some(p.1)))
        .collect();
    write_all_params_in_file(
        "shortint_noise_squashing_parameters_lattice_estimator.sage",
        &noise_squasing_params,
        ParametersFormat::Glwe,
    );

    let noise_squasing_multi_bit_params: Vec<_> = VEC_ALL_NOISE_SQUASHING_MULTI_BIT_PARAMETERS
        .into_iter()
        .map(|p| (*p.0, Some(p.1)))
        .collect();
    write_all_params_in_file(
        "shortint_noise_squashing_multi_bit_parameters_lattice_estimator.sage",
        &noise_squasing_multi_bit_params,
        ParametersFormat::Glwe,
    );

    let noise_squasing_compression_params: Vec<_> = VEC_ALL_NOISE_SQUASHING_COMPRESSION_PARAMETERS
        .into_iter()
        .map(|p| (*p.0, Some(p.1)))
        .collect();
    write_all_params_in_file(
        "shortint_noise_squashing_compression_parameters_lattice_estimator.sage",
        &noise_squasing_compression_params,
        ParametersFormat::Glwe,
    );

    let ks32_params: Vec<_> = VEC_ALL_KS32_PARAMETERS
        .into_iter()
        .map(|p| (AtomicPatternParameters::from(*p.0), Some(p.1)))
        .collect();
    write_all_params_in_file(
        "shortint_ks32_parameters_lattice_estimator.sage",
        &ks32_params,
        ParametersFormat::LweGlwe,
    );

    let hpu_params: Vec<_> = VEC_ALL_HPU_PARAMETERS
        .into_iter()
        .map(|p| (AtomicPatternParameters::from(*p.0), Some(p.1)))
        .collect();
    write_all_params_in_file(
        "shortint_hpu_parameters_lattice_estimator.sage",
        &hpu_params,
        ParametersFormat::LweGlwe,
    );
}
