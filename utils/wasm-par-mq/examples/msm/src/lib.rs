use std::convert::Infallible;
use std::marker::PhantomData;

use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInt, Field, Fp, FpConfig, UniformRand};
use curve_446::Fr;
use curve_446::g1::G1Affine;
use msm::{MsmSyncInput, msm_wnaf_g1_446, msm_wnaf_g1_446_parallel, msm_wnaf_g1_446_parallel_sync};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_par_mq::{execute_async, sync_fn};

mod curve_446;
mod msm;

/// Serialization equivalent of the [`Fp`] struct, where the bigint is split into
/// multiple u64.
#[derive(Serialize, Deserialize, Clone)]
pub struct SerializableFp {
    val: Vec<u64>, // Use a Vec<u64> since serde does not support fixed size arrays with a generic
}

impl<P: FpConfig<N>, const N: usize> From<Fp<P, N>> for SerializableFp {
    fn from(value: Fp<P, N>) -> Self {
        Self {
            val: value.0.0.to_vec(),
        }
    }
}

impl<P: FpConfig<N>, const N: usize> From<SerializableFp> for Fp<P, N> {
    fn from(value: SerializableFp) -> Self {
        Fp(BigInt(value.val.try_into().unwrap()), PhantomData)
    }
}

/// Serialization equivalent to the [`Affine`], which support an optional compression mode
/// where only the `x` coordinate is stored, and the `y` is computed on load.
#[derive(Serialize, Deserialize, Clone)]
pub enum SerializableAffine<F> {
    Infinity,
    Compressed { x: F, take_largest_y: bool },
    Uncompressed { x: F, y: F },
}

impl<F> SerializableAffine<F> {
    #[allow(unused)]
    pub fn uncompressed<BaseField: Into<F> + Field, C: SWCurveConfig<BaseField = BaseField>>(
        value: Affine<C>,
    ) -> Self {
        if value.is_zero() {
            Self::Infinity
        } else {
            Self::Uncompressed {
                x: value.x.into(),
                y: value.y.into(),
            }
        }
    }

    pub fn compressed<BaseField: Into<F> + Field, C: SWCurveConfig<BaseField = BaseField>>(
        value: Affine<C>,
    ) -> Self {
        if value.is_zero() {
            Self::Infinity
        } else {
            let take_largest_y = value.y > -value.y;
            Self::Compressed {
                x: value.x.into(),
                take_largest_y,
            }
        }
    }
}

impl<F, C: SWCurveConfig> From<SerializableAffine<F>> for Affine<C>
where
    F: TryInto<C::BaseField, Error = Infallible>,
{
    fn from(value: SerializableAffine<F>) -> Self {
        match value {
            SerializableAffine::Infinity => Self::zero(),
            SerializableAffine::Compressed { x, take_largest_y } => {
                Self::get_point_from_x_unchecked(x.try_into().unwrap(), take_largest_y).unwrap()
            }

            SerializableAffine::Uncompressed { x, y } => {
                Self::new_unchecked(x.try_into().unwrap(), y.try_into().unwrap())
            }
        }
    }
}

pub(crate) type SerializableG1Affine = SerializableAffine<SerializableFp>;

// Set up panic hook for better error messages
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Initialize the parallel execution pool
#[wasm_bindgen]
pub async fn init_parallel(
    num_workers: u32,
    wasm_url: &str,
    bindgen_url: &str,
) -> Result<(), JsValue> {
    wasm_par_mq::init_pool_async(Some(num_workers), wasm_url, bindgen_url)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn generate_test_data(count: i32) -> JsValue {
    let mut rng = rand::thread_rng();
    web_sys::console::log_1(&format!("count: {count}").into());
    let mut bases = Vec::new();
    bases.resize_with(count as usize, || {
        SerializableG1Affine::uncompressed(G1Affine::rand(&mut rng))
    });

    let mut scalars = Vec::new();
    scalars.resize_with(count as usize, || SerializableFp::from(Fr::rand(&mut rng)));
    let serializer =
        serde_wasm_bindgen::Serializer::new().serialize_large_number_types_as_bigints(true);
    (bases, scalars).serialize(&serializer).unwrap()
}

#[wasm_bindgen]
pub fn run_msm_sequential(data: JsValue) -> Result<String, JsValue> {
    let (bases, scalars): (Vec<SerializableG1Affine>, Vec<SerializableFp>) =
        serde_wasm_bindgen::from_value(data).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let count = bases.len();
    let bases: Vec<_> = bases.into_iter().map(|b| b.into()).collect();
    let scalars: Vec<_> = scalars.into_iter().map(|b| b.into()).collect();
    let _res = msm_wnaf_g1_446(&bases, &scalars).into_affine();
    Ok(format!("MSM completed for {} points", count))
}

#[wasm_bindgen]
pub async fn run_msm_parallel(data: JsValue) -> Result<String, JsValue> {
    let (bases, scalars): (Vec<SerializableG1Affine>, Vec<SerializableFp>) =
        serde_wasm_bindgen::from_value(data).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let count = bases.len();
    let _result = msm_wnaf_g1_446_parallel(bases, scalars).await;

    Ok(format!("Parallel MSM completed for {} points", count))
}

/// Run both sequential and parallel MSM and compare results
#[wasm_bindgen]
pub async fn run_msm_compare(data: JsValue) -> Result<String, JsValue> {
    let (bases, scalars): (Vec<SerializableG1Affine>, Vec<SerializableFp>) =
        serde_wasm_bindgen::from_value(data).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let count = bases.len();

    // Run sequential
    let seq_bases: Vec<G1Affine> = bases.iter().cloned().map(|b| b.into()).collect();
    let seq_scalars: Vec<Fr> = scalars.iter().cloned().map(|s| s.into()).collect();
    let seq_result = msm_wnaf_g1_446(&seq_bases, &seq_scalars).into_affine();

    // Run parallel
    let par_result = msm_wnaf_g1_446_parallel(bases, scalars).await.into_affine();

    // Compare results
    let match_status = if seq_result == par_result {
        "MATCH ✓"
    } else {
        "MISMATCH ✗"
    };

    Ok(format!(
        "MSM comparison for {} points: {}",
        count, match_status
    ))
}

// === Sync Executor Mode Functions ===

/// Initialize the parallel execution pool in sync mode
#[wasm_bindgen]
pub async fn init_parallel_sync(
    num_workers: u32,
    wasm_url: &str,
    bindgen_url: &str,
    coordinator_url: &str,
) -> Result<(), JsValue> {
    wasm_par_mq::register_coordinator(coordinator_url)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    wasm_par_mq::init_pool_sync(Some(num_workers), wasm_url, bindgen_url)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Run MSM using the sync executor (dispatched from main thread)
#[wasm_bindgen]
pub async fn run_msm_sync(data: JsValue) -> Result<String, JsValue> {
    let (bases, scalars): (Vec<SerializableG1Affine>, Vec<SerializableFp>) =
        serde_wasm_bindgen::from_value(data).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let count = bases.len();
    let input = MsmSyncInput { bases, scalars };

    let _result: SerializableG1Affine =
        execute_async(sync_fn!(msm_wnaf_g1_446_parallel_sync), &input)
            .await
            .map_err(|e| JsValue::from_str(&e))?;

    Ok(format!("Sync MSM completed for {} points", count))
}
