//! Regression profiles (`ci/regression.toml`): the list of benchmarks a report
//! is made of, per backend.
//!
//! Operations are listed under benchmark targets (the `[[bench]]` names of
//! `tfhe-benchmark/Cargo.toml`), not under spec layers. Each target maps onto
//! spec path prefixes, and an entry appended to a prefix must parse as a full
//! [`BenchCrate`] path.

use std::collections::HashMap;
use std::path::Path;

use benchmark_spec::{Backend, BenchCrate};
use serde::Deserialize;

use crate::db::like_escape;

/// One `[<backend>.<profile>]` section. `env` and `slab` drive benchmark
/// execution, not extraction, and are deliberately not deserialized.
#[derive(Debug, Deserialize)]
pub struct Profile {
    /// `target.<name> = [<entry>, …]`, where an entry is a spec path fragment
    /// and not just an operation name:
    ///
    /// ```toml
    /// target.shortint = ["bitand"]
    /// target.hlapi-dex = ["swap_request::whitepaper"]
    /// ```
    #[serde(default)]
    pub target: HashMap<String, Vec<String>>,
    /// Parameter set name to restrict the report to, applied as a SQL filter.
    pub parameters_filter: Option<String>,
}

/// Every profile in the file, indexed by backend section, then by profile name.
///
/// ```toml
/// [cpu.default]
/// target.shortint = ["bitand"]
/// ```
///
/// becomes
///
/// ```text
/// {"cpu": {"default": Profile { target: {"shortint": ["bitand"]} }}}
/// ```
#[derive(Debug, Deserialize)]
#[serde(transparent)]
pub struct Profiles(HashMap<String, HashMap<String, Profile>>);

impl Profiles {
    /// Reads and parses the profiles file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read profiles file {}: {e}", path.display()))?;
        Ok(toml::from_str(&raw)?)
    }

    /// Looks up `[<backend>.<name>]`.
    pub fn get(&self, backend: Backend, name: &str) -> anyhow::Result<&Profile> {
        let section = profile_section(backend);
        self.0
            .get(section)
            .and_then(|profiles| profiles.get(name))
            .ok_or_else(|| anyhow::anyhow!("no profile [{section}.{name}] in profiles file"))
    }
}

/// Sections are named after the hardware family, not the spec backend: the
/// Cuda backend lives under `[gpu.*]`.
fn profile_section(backend: Backend) -> &'static str {
    match backend {
        Backend::Cpu => "cpu",
        Backend::Cuda => "gpu",
        Backend::Hpu => "hpu",
    }
}

/// Spec path prefixes a profile target expands to.
///
/// ```text
/// target.integer = ["add_parallelized"]
///   -> tfhe::integer::ops::unsigned::add_parallelized
///   -> tfhe::integer::ops::signed::add_parallelized
/// ```
///
/// `integer` is the only target yielding two prefixes; conversely
/// `core_crypto-ks` and `core_crypto-pbs` share one.
fn target_prefixes(target: &str) -> Option<&'static [&'static str]> {
    Some(match target {
        "integer" => &["tfhe::integer::ops::unsigned", "tfhe::integer::ops::signed"],
        "shortint" => &["tfhe::shortint::ops"],
        "hlapi-dex" => &["tfhe::hlapi::dex"],
        "hlapi-erc7984" => &["tfhe::hlapi::erc7984"],
        "core_crypto-ks" | "core_crypto-pbs" => &["tfhe::core_crypto"],
        _ => return None,
    })
}

/// Outcome of resolving a profile against the spec.
#[derive(Debug, Default)]
pub struct Resolved {
    /// Bench paths the report covers.
    pub paths: Vec<BenchCrate>,
    /// `target.entry` pairs that match no spec path: a not-yet-migrated bench,
    /// or a typo. Reported, never silently dropped.
    pub unresolved: Vec<String>,
}

impl Profile {
    /// Turns every `target.<name> = [ops]` entry into spec bench paths.
    pub fn resolve(&self) -> Resolved {
        let mut out = Resolved::default();

        // HashMap order is arbitrary; sort so warnings are stable.
        let mut targets: Vec<_> = self.target.iter().collect();
        targets.sort_by_key(|(name, _)| *name);

        for (target, entries) in targets {
            let Some(prefixes) = target_prefixes(target) else {
                out.unresolved.push(format!("{target} (unknown target)"));
                continue;
            };

            for entry in entries {
                let matched: Vec<BenchCrate> = prefixes
                    .iter()
                    .filter_map(|prefix| format!("{prefix}::{entry}").parse().ok())
                    .collect();

                if matched.is_empty() {
                    out.unresolved.push(format!("{target}.{entry}"));
                } else {
                    out.paths.extend(matched);
                }
            }
        }

        out
    }
}

impl Resolved {
    /// SQL `LIKE` patterns matching every id under these bench paths.
    ///
    /// `LIKE` matches the whole string, so neither end needs a `%`: both are
    /// anchored, and the single `%` is the hole left for the backend, the
    /// metric, the parameter set and the type.
    ///
    /// ```text
    /// tfhe::integer::ops::unsigned::add_parallelized::%\_mean\_avx512
    /// └──────────── bench path, exact ─────────────┘  ↑└── suffix ──┘
    /// ```
    pub fn like_patterns(&self, suffix: &str) -> Vec<String> {
        self.paths
            .iter()
            .map(|path| {
                format!(
                    "{}::%{}",
                    like_escape(&path.to_string()),
                    like_escape(suffix)
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../ci/regression.toml");

    /// A failure here lists the benches still outside the spec.
    #[test]
    fn regression_profiles_resolve() {
        let profiles = Profiles::load(Path::new(PROFILES)).unwrap();

        for (backend, name) in [(Backend::Cpu, "default"), (Backend::Cuda, "default")] {
            let resolved = profiles.get(backend, name).unwrap().resolve();
            assert!(
                resolved.unresolved.is_empty(),
                "[{}.{name}] does not resolve: {:?}",
                profile_section(backend),
                resolved.unresolved,
            );
            assert!(!resolved.paths.is_empty());
        }
    }

    #[test]
    fn like_patterns_are_escaped_and_anchored() {
        let profiles = Profiles::load(Path::new(PROFILES)).unwrap();
        let resolved = profiles.get(Backend::Cpu, "default").unwrap().resolve();
        let patterns = resolved.like_patterns("_mean_avx512");

        assert!(
            patterns
                .iter()
                .any(|p| p == r"tfhe::integer::ops::unsigned::add\_parallelized::%\_mean\_avx512")
        );
    }
}
