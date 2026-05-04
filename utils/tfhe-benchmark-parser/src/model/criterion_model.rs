use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct CriterionBenchmark {
    pub full_id: String,
    pub function_id: Option<String>,
    pub throughput: Option<CriterionThroughput>,
}

#[derive(Deserialize, Debug)]
pub struct CriterionThroughput {
    #[serde(rename = "Elements")]
    pub elements: Option<u64>,
}

#[derive(Deserialize, Debug)]
pub struct CriterionEstimates {
    pub mean: Estimate,
    pub std_dev: Estimate,
}

#[derive(Deserialize, Debug)]
pub struct Estimate {
    pub point_estimate: f64,
}
