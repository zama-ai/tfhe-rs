//! The registry the crates are released to, read through its sparse index: what cargo itself
//! reads, and all a registry is required to serve.

use std::collections::BTreeMap;
use std::process::Command;

use cargo_metadata::semver::Version;
use serde::Deserialize;

use super::{Failure, Result};

/// The name cargo gives to crates.io, and its index: the registry of a release unless --registry
/// and --index name another one, as the tests of the release tooling do.
pub const CRATES_IO: &str = "crates-io";
const CRATES_IO_INDEX: &str = "https://index.crates.io";
/// crates.io asks its clients to identify themselves.
const USER_AGENT: &str = "tfhe-rs release tooling (https://github.com/zama-ai/tfhe-rs)";

/// Versions of a crate in the registry, each with the checksum of its crate file. A yanked
/// version is listed like any other: it cannot be published again.
pub type Published = BTreeMap<Version, String>;

pub struct Registry {
    /// What cargo calls it, as in `cargo publish --registry`.
    pub name: String,
    /// Where its sparse index is served.
    pub index: String,
    /// What to call it in a message.
    pub label: String,
}

/// A line of the index file of a crate: one of its versions.
#[derive(Deserialize)]
struct IndexEntry {
    vers: String,
    cksum: String,
}

impl Registry {
    pub fn new(name: &str, index: Option<&str>) -> Result<Self> {
        let index = match index {
            Some(index) => index,
            None if name == CRATES_IO => CRATES_IO_INDEX,
            None => {
                return Err(Failure::new(format!(
                    "--index is required to release to {name}"
                )));
            }
        };
        // cargo configuration files write the same URL with a sparse+ prefix.
        let index = index.strip_prefix("sparse+").unwrap_or(index);
        Ok(Self {
            name: name.to_owned(),
            index: index.trim_end_matches('/').to_owned(),
            label: if name == CRATES_IO { "crates.io" } else { name }.to_owned(),
        })
    }

    /// Versions of crate `name` in the registry, none for a crate it does not have.
    fn published_versions(&self, name: &str) -> std::result::Result<Published, String> {
        let url = format!("{}/{}", self.index, index_path(name));
        let Some(index_file) = get(&url)? else {
            return Ok(Published::new());
        };
        let mut versions = Published::new();
        for line in index_file.lines().filter(|line| !line.trim().is_empty()) {
            let entry: IndexEntry =
                serde_json::from_str(line).map_err(|error| format!("{url}: {error}"))?;
            let version = Version::parse(&entry.vers)
                .map_err(|error| format!("{url}: version {}: {error}", entry.vers))?;
            versions.insert(version, entry.cksum);
        }
        Ok(versions)
    }

    /// Published versions of each crate of `names`, or why the registry could not tell.
    pub fn fetch_published(
        &self,
        names: &[String],
    ) -> std::result::Result<BTreeMap<String, Published>, String> {
        // One request per crate, which are worth overlapping.
        std::thread::scope(|scope| {
            let fetches: Vec<_> = names
                .iter()
                .map(|name| scope.spawn(move || self.published_versions(name)))
                .collect();
            names
                .iter()
                .zip(fetches)
                .map(|(name, fetch)| Ok((name.clone(), fetch.join().unwrap()?)))
                .collect()
        })
    }
}

/// Path of the file listing the versions of crate `name` in a registry index.
pub fn index_path(name: &str) -> String {
    let name = name.to_lowercase();
    match name.len() {
        1 | 2 => format!("{}/{name}", name.len()),
        3 => format!("3/{}/{name}", &name[..1]),
        _ => format!("{}/{}/{name}", &name[..2], &name[2..4]),
    }
}

/// What is served at `url`, nothing when the server has nothing there.
///
/// curl is what makes the request: it knows the proxies and the certificates of the machine,
/// and saves this tool a TLS stack of its own.
fn get(url: &str) -> std::result::Result<Option<String>, String> {
    let output = Command::new("curl")
        .args(["--silent", "--show-error", "--location"])
        .args(["--max-time", "30", "--user-agent", USER_AGENT])
        // The status comes after the body, on a line of its own.
        .args(["--write-out", "\n%{http_code}", url])
        .output()
        .map_err(|error| format!("could not run curl: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    let answer = String::from_utf8_lossy(&output.stdout);
    let (body, status) = answer.rsplit_once('\n').unwrap_or(("", &answer));
    match status {
        "200" => Ok(Some(body.to_owned())),
        "404" | "410" => Ok(None),
        _ => Err(format!("{url} answered with status {status}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_paths_follow_the_layout_of_cargo() {
        assert_eq!(index_path("a"), "1/a");
        assert_eq!(index_path("ab"), "2/ab");
        assert_eq!(index_path("abc"), "3/a/abc");
        assert_eq!(index_path("tfhe"), "tf/he/tfhe");
        assert_eq!(index_path("cfg-if"), "cf/g-/cfg-if");
        assert_eq!(index_path("Inflector"), "in/fl/inflector");
    }

    #[test]
    fn an_index_is_named_the_way_cargo_configures_it() {
        let registry = Registry::new("mirror", Some("sparse+http://127.0.0.1:1/index/")).unwrap();
        assert_eq!(registry.index, "http://127.0.0.1:1/index");
        assert_eq!(registry.label, "mirror");
        assert_eq!(Registry::new(CRATES_IO, None).unwrap().label, "crates.io");
        assert!(Registry::new("mirror", None).is_err());
    }
}
