use benchmark_spec::{Backend, BenchmarkMetric};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PointClass {
    Evaluate,
    KeyGen,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Point {
    pub value: Number,
    pub test: String,
    pub name: String,
    pub class: PointClass,
    #[serde(rename = "type")]
    pub point_type: BenchmarkMetric,
    pub operator: String,
    pub params: Map<String, Value>,
    pub backend: Backend,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Series {
    pub database: Option<String>,
    pub hardware: Option<String>,
    pub project_version: Option<String>,
    pub branch: Option<String>,
    pub insert_date: Option<String>,
    pub commit_date: Option<String>,
    pub points: Vec<Point>,
}
