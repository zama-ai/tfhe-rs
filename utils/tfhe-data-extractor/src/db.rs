//! PostgreSQL access layer (read-only) for the data extractor.
//!
//! Credentials come from a TOML config file (`--config-file`) and/or the
//! environment variables `DATA_EXTRACTOR_DATABASE_{HOST,USER,PASSWORD}`, the
//! latter taking precedence.

use std::path::Path;

use benchmark_spec::BenchmarkMetric;
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions, PgSslMode};
use sqlx::{Postgres, QueryBuilder};

/// Database credentials. Every field is optional so the file and the
/// environment can each provide a subset.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub struct DbConfig {
    pub host: Option<String>,
    pub user: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct ConfigFile {
    database: DbConfig,
}

impl DbConfig {
    /// Loads credentials from the optional TOML file, then overrides any value
    /// present in the environment, which wins.
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let mut cfg = match path {
            Some(p) => {
                let raw = std::fs::read_to_string(p)
                    .map_err(|e| anyhow::anyhow!("cannot read config file {}: {e}", p.display()))?;
                toml::from_str::<ConfigFile>(&raw)?.database
            }
            None => DbConfig::default(),
        };

        if let Ok(v) = std::env::var("DATA_EXTRACTOR_DATABASE_HOST") {
            cfg.host = Some(v);
        }
        if let Ok(v) = std::env::var("DATA_EXTRACTOR_DATABASE_USER") {
            cfg.user = Some(v);
        }
        if let Ok(v) = std::env::var("DATA_EXTRACTOR_DATABASE_PASSWORD") {
            cfg.password = Some(v);
        }

        Ok(cfg)
    }

    fn connect_options(&self, dbname: &str) -> anyhow::Result<PgConnectOptions> {
        let host = self
            .host
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing database host"))?;
        let user = self
            .user
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing database user"))?;
        let password = self
            .password
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing database password"))?;

        Ok(PgConnectOptions::new()
            .host(host)
            .username(user)
            .password(password)
            .database(dbname)
            // RDS enforces TLS; `Require` encrypts without CA verification.
            .ssl_mode(PgSslMode::Require))
    }

    /// Opens a connection pool to the given database.
    pub async fn connect(&self, dbname: &str) -> anyhow::Result<PgPool> {
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect_with(self.connect_options(dbname)?)
            .await?;
        Ok(pool)
    }
}

/// One benchmark result, as stored. `name` holds the whole rendered id, so
/// every structured part of a result has to be parsed back out of it:
///
/// ```text
/// name     = "<bench path>::<param set>::<type>_mean_avx512"
/// bit_size = 64
/// value    = 2310000.0     // nanoseconds, for a latency bench
/// ```
#[derive(Debug, sqlx::FromRow)]
pub struct BenchRow {
    pub name: String,
    pub bit_size: i64,
    pub value: f64,
}

/// Escapes the `LIKE` metacharacters. Bench ids and parameter aliases are full
/// of `_`, which `LIKE` would otherwise read as "any single character", making
/// the pattern match more than was asked for.
///
/// ```text
/// add_parallelized  ->  add\_parallelized
/// ```
pub fn like_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '_' | '%' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// PBS-kind filter, applied as a pattern on the parameter-set alias.
#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum PbsKind {
    Classical,
    #[value(name = "multi_bit")]
    MultiBit,
    /// Special variant used when the user doesn't care about the PBS kind.
    Any,
}

/// Dynamic filters for the benchmark fetch query.
pub struct FetchQuery<'a> {
    pub hardware: &'a str,
    pub backend: &'a str,
    pub branch: &'a str,
    /// SQL `LIKE` patterns for the id; a row matching any of them is kept.
    /// Either one broad layer pattern, or one exact prefix per bench path when
    /// a regression profile drives the selection.
    pub like_patterns: &'a [String],
    /// Drop the `unchecked_` variants by name. Only needed for the broad
    /// pattern: a profile already spells out the operations it wants.
    pub exclude_non_default: bool,
    /// `None` = no metric filter (both latency and throughput).
    pub metric: Option<BenchmarkMetric>,
    pub pbs_kind: PbsKind,
    /// `LIKE` pattern on the parameter set alias, already wrapped in `%`.
    /// Matched as a substring, which matters: aliases carry a version prefix
    /// (`V1_6_PARAM_…`).
    pub param_pattern: Option<&'a str>,
    /// If set, pin to that exact commit; otherwise use the date window.
    pub project_version: Option<&'a str>,
    pub bench_date: Option<&'a str>,
    pub time_span_days: i32,
}

/// Tiny `WHERE` builder over `sqlx::QueryBuilder`.
///
/// [`BASE_QUERY`] ends with `WHERE true`, so every condition is a plain `AND`
/// and no method has to know whether it is the first one. Which one that would
/// be is not knowable anyway: most filters here are optional. It also keeps the
/// query valid when none of them applies.
///
/// ```sql
/// WHERE true AND h.name = $1 AND bk.name = $2 AND test.name LIKE ANY($3)
/// WHERE true                                    -- no filter active
/// ```
///
/// Column names are always hardcoded constants (safe to inline); only values go
/// through `push_bind`.
struct Filters<'a>(QueryBuilder<'a, Postgres>);

impl<'a> Filters<'a> {
    fn new(base: &str) -> Self {
        Filters(QueryBuilder::new(base))
    }

    fn eq<T>(&mut self, col: &str, val: T) -> &mut Self
    where
        T: 'a + sqlx::Encode<'a, Postgres> + sqlx::Type<Postgres> + Send,
    {
        self.0.push(" AND ").push(col).push(" = ").push_bind(val);
        self
    }

    /// `col LIKE ANY($n)`: one round-trip whatever the number of patterns.
    fn like_any(&mut self, col: &str, patterns: &'a [String]) -> &mut Self {
        self.0
            .push(" AND ")
            .push(col)
            .push(" LIKE ANY(")
            .push_bind(patterns)
            .push(")");
        self
    }

    /// Appends a raw `AND <sql>`. Constant SQL only, never user input.
    fn raw(&mut self, sql: &str) -> &mut Self {
        self.0.push(" AND ").push(sql);
        self
    }
}

const BASE_QUERY: &str = "\
    SELECT DISTINCT ON (test.name) \
        test.name AS name, p.bit_size AS bit_size, m.value AS value \
    FROM benchmark.metrics AS m \
    LEFT JOIN benchmark.hardware        AS h  ON m.hardware_id        = h.id \
    LEFT JOIN benchmark.backend         AS bk ON m.backend_id         = bk.id \
    LEFT JOIN benchmark.branch          AS b  ON m.branch_id          = b.id \
    LEFT JOIN benchmark.test            AS test ON m.test_id          = test.id \
    LEFT JOIN benchmark.parameters      AS p  ON m.parameters_id      = p.id \
    LEFT JOIN benchmark.project_version AS pv ON m.project_version_id = pv.id \
    WHERE true";

/// Latest value per `test.name` matching the filters.
pub async fn fetch_bench_rows(pool: &PgPool, q: &FetchQuery<'_>) -> anyhow::Result<Vec<BenchRow>> {
    let mut f = Filters::new(BASE_QUERY);
    f.eq("h.name", q.hardware)
        .eq("bk.name", q.backend)
        .eq("b.name", q.branch)
        .like_any("test.name", q.like_patterns);

    if let Some(version) = q.project_version {
        f.eq("pv.name", version);
    }

    if let Some(pattern) = q.param_pattern {
        f.0.push(" AND p.crypto_parameters_alias LIKE ")
            .push_bind(pattern);
    }

    if q.exclude_non_default {
        // Default operations only. `smart_` was dropped from the benches in
        // a20ee6325; kept here for the historical rows.
        f.raw("test.name NOT SIMILAR TO '%(smart|unchecked)_%'");
    }

    match q.metric {
        Some(BenchmarkMetric::Latency) => {
            f.raw("test.name NOT LIKE '%::throughput::%'");
        }
        Some(BenchmarkMetric::Throughput) => {
            f.raw("test.name LIKE '%::throughput::%'");
        }
        _ => {}
    }

    match q.pbs_kind {
        PbsKind::Classical => {
            f.raw("p.crypto_parameters_alias NOT SIMILAR TO '%_MULTI_BIT_%'");
        }
        PbsKind::MultiBit => {
            f.raw("p.crypto_parameters_alias SIMILAR TO '%_MULTI_BIT_%'");
        }
        PbsKind::Any => {}
    }

    // Date window only when no exact commit was pinned. Anchored on the
    // requested date, which also closes the window, or on `now()`, in which case
    // there is nothing to close: no row can be inserted in the future.
    if q.project_version.is_none() {
        match q.bench_date {
            Some(date) => {
                f.0.push(" AND m.insert_time <= ")
                    .push_bind(date)
                    .push("::timestamp AND m.insert_time >= ")
                    .push_bind(date)
                    .push("::timestamp - make_interval(days => ")
                    .push_bind(q.time_span_days)
                    .push(")");
            }
            None => {
                f.0.push(" AND m.insert_time >= now() - make_interval(days => ")
                    .push_bind(q.time_span_days)
                    .push(")");
            }
        }
    }

    f.0.push(" ORDER BY test.name, m.insert_time DESC");

    let rows = f.0.build_query_as::<BenchRow>().fetch_all(pool).await?;
    Ok(rows)
}
