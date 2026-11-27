//! The versions crates.io has of a crate, read from its index with `curl`.

use super::Error;
use cargo_metadata::semver::Version;
use serde::Deserialize;
use std::process::Command;

/// The sparse index holds one static file per crate listing all of its versions, it is what cargo
/// itself resolves dependencies from.
const INDEX_URL: &str = "https://index.crates.io";

/// Identifies this tool to crates.io.
const USER_AGENT: &str = "tfhe-rs release-status (https://github.com/zama-ai/tfhe-rs)";

const CURL_OPTIONS: [&str; 13] = [
    // Has to come first. Ignores ~/.curlrc, which could change what is fetched or printed.
    "--disable",
    "--silent",
    "--show-error",
    // Never talk to the index over anything weaker than HTTPS with TLS 1.3.
    "--proto",
    "=https",
    "--tlsv1.2",
    "--max-time",
    "30",
    "--retry",
    "2",
    "--user-agent",
    USER_AGENT,
    // The HTTP status is needed to tell a crate that was never published from a failure, see
    // STATUS_FORMAT.
    "--write-out",
];

/// Printed by curl after the body: the HTTP status on a line of its own.
const STATUS_FORMAT: &str = "\n%{http_code}";

pub trait CrateRegistry: Sync {
    /// Every version of `name` ever published, yanked ones included since a yanked version can
    /// never be published again. Empty when the crate was never published.
    fn published_versions(&self, name: &str) -> Result<Vec<Version>, Error>;
}

pub struct CratesIo;

impl CrateRegistry for CratesIo {
    fn published_versions(&self, name: &str) -> Result<Vec<Version>, Error> {
        let url = format!("{INDEX_URL}/{}", index_path(name)?);
        let output = Command::new("curl")
            .args(CURL_OPTIONS)
            .arg(STATUS_FORMAT)
            .arg(&url)
            .output()
            .map_err(|error| {
                Error::Registry(format!(
                    "could not run curl, needed to ask crates.io for the published versions: \
                    {error}"
                ))
            })?;
        if !output.status.success() {
            return Err(Error::Registry(format!(
                "could not reach {url}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let response = String::from_utf8(output.stdout)
            .map_err(|_| Error::Registry(format!("{url} did not answer with valid UTF-8")))?;
        parse_response(&url, &response)
    }
}

/// Path of the file of `name` in the index, see
/// <https://doc.rust-lang.org/cargo/reference/registry-index.html#index-files>
fn index_path(name: &str) -> Result<String, Error> {
    let valid = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    if name.is_empty() || !name.chars().all(valid) {
        return Err(Error::Registry(format!(
            "`{name}` is not a crate name crates.io can have"
        )));
    }
    let name = name.to_ascii_lowercase();
    Ok(match name.len() {
        1 => format!("1/{name}"),
        2 => format!("2/{name}"),
        3 => format!("3/{}/{name}", &name[..1]),
        _ => format!("{}/{}/{name}", &name[..2], &name[2..4]),
    })
}

/// Versions listed by what curl printed for `url`: the body, then the HTTP status.
fn parse_response(url: &str, response: &str) -> Result<Vec<Version>, Error> {
    match response.rsplit_once('\n') {
        Some((body, "200")) => parse_index(url, body),
        // The index has no file for a crate that was never published.
        Some((_, "404")) => Ok(Vec::new()),
        Some((_, status)) => Err(Error::Registry(format!(
            "{url} answered with the HTTP status `{status}`"
        ))),
        None => Err(Error::Registry(format!(
            "curl did not report the HTTP status of {url}"
        ))),
    }
}

/// One line of an index file, describing one published version.
#[derive(Deserialize)]
struct IndexEntry {
    vers: String,
}

fn parse_index(url: &str, body: &str) -> Result<Vec<Version>, Error> {
    let versions = body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let entry: IndexEntry = serde_json::from_str(line).map_err(|error| {
                Error::Registry(format!("{url} has an entry that cannot be read: {error}"))
            })?;
            Version::parse(&entry.vers).map_err(|error| {
                Error::Registry(format!(
                    "{url} lists `{}`, which is not a version: {error}",
                    entry.vers
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if versions.is_empty() {
        // A crate in the index has at least one version: an empty answer is not the index.
        return Err(Error::Registry(format!("{url} lists no version")));
    }
    Ok(versions)
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "https://index.crates.io/tf/he/tfhe";

    fn versions(versions: &[&str]) -> Vec<Version> {
        versions
            .iter()
            .map(|v| Version::parse(v).unwrap())
            .collect()
    }

    #[test]
    fn index_path_follows_the_length_of_the_name() {
        assert_eq!(index_path("a").unwrap(), "1/a");
        assert_eq!(index_path("cc").unwrap(), "2/cc");
        assert_eq!(index_path("syn").unwrap(), "3/s/syn");
        assert_eq!(index_path("tfhe").unwrap(), "tf/he/tfhe");
        assert_eq!(index_path("tfhe-zk-pok").unwrap(), "tf/he/tfhe-zk-pok");
        assert_eq!(index_path("wasm_par_mq").unwrap(), "wa/sm/wasm_par_mq");
    }

    #[test]
    fn index_path_is_lowercase() {
        assert_eq!(index_path("Inflector").unwrap(), "in/fl/inflector");
    }

    #[test]
    fn index_path_refuses_what_cannot_be_a_crate_name() {
        for name in ["", "tfhe/../etc", "tfhe?x", "tfhe rs", "tfhé"] {
            let error = index_path(name);
            assert!(
                matches!(error, Err(Error::Registry(_))),
                "{name}: {error:?}"
            );
        }
    }

    #[test]
    fn every_version_of_the_index_is_listed() {
        // Trimmed down entries of a real index file: they come in publication order, and a
        // yanked version is still a version that was published.
        let response = concat!(
            r#"{"name":"tfhe","vers":"0.5.0","deps":[],"cksum":"00","features":{},"yanked":true}"#,
            "\n",
            r#"{"name":"tfhe","vers":"0.4.2","deps":[],"cksum":"11","features":{},"yanked":false}"#,
            "\n",
            r#"{"name":"tfhe","vers":"1.0.0-alpha.1","deps":[],"cksum":"22","yanked":false}"#,
            "\n",
            "\n200"
        );
        assert_eq!(
            parse_response(URL, response).unwrap(),
            versions(&["0.5.0", "0.4.2", "1.0.0-alpha.1"])
        );
    }

    #[test]
    fn a_crate_missing_from_the_index_was_never_published() {
        let response = "<?xml version=\"1.0\"?>\n<Error><Code>NoSuchKey</Code></Error>\n404";
        assert_eq!(parse_response(URL, response).unwrap(), []);
    }

    #[test]
    fn any_other_answer_is_a_failure() {
        for response in ["oops\n500", "\n429", "\n000", "200", "", "{}\n", "\n200"] {
            let error = parse_response(URL, response);
            assert!(
                matches!(error, Err(Error::Registry(_))),
                "{response:?}: {error:?}"
            );
        }
    }

    #[test]
    fn an_index_that_cannot_be_read_is_a_failure() {
        for response in [
            "not json\n200",
            "{\"name\":\"tfhe\"}\n200",
            "{\"vers\":\"not.a.version\"}\n200",
            "{\"vers\":1}\n200",
        ] {
            let error = parse_response(URL, response);
            assert!(
                matches!(error, Err(Error::Registry(_))),
                "{response:?}: {error:?}"
            );
        }
    }
}
