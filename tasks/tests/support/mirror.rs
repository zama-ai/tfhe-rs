//! Local cargo registry standing in for crates.io in the tests of the release tooling.
//!
//! It serves a sparse index, accepts `cargo publish` and keeps what it receives on disk. It can
//! also mirror crates.io, read-only: index entries and crate files are then fetched from there
//! when asked for, and a crate lists the versions of crates.io along with the ones published
//! here. Crates published here can depend on real ones while cargo only ever talks to this
//! registry. Nothing is sent to crates.io.
//!
//! Meant to replace crates.io altogether in a cargo configuration:
//!
//! ```toml
//! [registries.test-mirror]
//! index = "sparse+http://127.0.0.1:<port>/index/"
//!
//! [source.crates-io]
//! replace-with = "test-mirror"
//! ```
//!
//! It only listens on the loopback interface and is in no way a production registry: one token,
//! no users, no yank, one request per connection.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const UPSTREAM_INDEX: &str = "https://index.crates.io";
const UPSTREAM_CRATES: &str = "https://static.crates.io/crates";
/// How cargo names crates.io in the dependencies of a crate sent to another registry.
const CRATES_IO_INDEX: &str = "https://github.com/rust-lang/crates.io-index";
const USER_AGENT: &str = "tfhe-rs release test mirror (https://github.com/zama-ai/tfhe-rs)";

/// Refuse every publication of a crate, see [`Mirror::reject`].
pub const ALWAYS: u32 = u32::MAX;

pub struct Mirror {
    shared: Arc<Shared>,
}

struct Shared {
    root: PathBuf,
    url: String,
    /// The only credential accepted by the publish endpoint.
    token: String,
    /// Mirror crates.io for the crates that were not published here, except for the ones whose
    /// name starts with `local_prefix`: those only ever come from here, whatever crates.io ends
    /// up holding under their name.
    upstream: bool,
    local_prefix: String,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// How many of the next publications of a crate are refused.
    rejections: HashMap<String, u32>,
    /// Crates whose publications are listed with the checksum of another file.
    corrupted: Vec<String>,
    /// How long a publication takes to show in the index, the way the cache in front of a real
    /// index delays it.
    index_delay: Duration,
    /// Crates received, in order, with their version.
    uploads: Vec<(String, String)>,
    /// What crates.io served, by URL, nothing for what it does not have.
    fetched: HashMap<String, Option<Vec<u8>>>,
}

struct Response {
    status: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
}

impl Response {
    fn json(status: &'static str, value: &Value) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: value.to_string().into_bytes(),
        }
    }

    /// The shape cargo expects, it prints `detail` to the user.
    fn error(status: &'static str, detail: impl Into<String>) -> Self {
        let detail: String = detail.into();
        Self::json(status, &json!({ "errors": [{ "detail": detail }] }))
    }
}

/// Path of the index file of crate `name`, as laid out by cargo.
pub fn index_path(name: &str) -> String {
    let name = name.to_lowercase();
    match name.len() {
        1 | 2 => format!("{}/{name}", name.len()),
        3 => format!("3/{}/{name}", &name[..1]),
        _ => format!("{}/{}/{name}", &name[..2], &name[2..4]),
    }
}

pub fn sha256(content: &[u8]) -> String {
    let digest = Sha256::digest(content);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// What crates.io serves at `url`, nothing when it has nothing there.
fn fetch(url: &str) -> Result<Option<Vec<u8>>, String> {
    let output = Command::new("curl")
        .args(["--silent", "--show-error", "--location"])
        .args(["--max-time", "60", "--user-agent", USER_AGENT])
        // The status comes after the body, on a line of its own.
        .args(["--write-out", "\n%{http_code}", url])
        .output()
        .map_err(|error| format!("could not run curl: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    let answer = output.stdout;
    let end = answer.iter().rposition(|byte| *byte == b'\n').unwrap_or(0);
    match &answer[end..] {
        b"\n200" => Ok(Some(answer[..end].to_vec())),
        b"\n404" | b"\n410" => Ok(None),
        status => Err(format!(
            "{url} answered with status {}",
            String::from_utf8_lossy(status).trim()
        )),
    }
}

/// Index line of a crate, from the metadata cargo sends along with it.
fn index_entry(metadata: &Value, checksum: &str) -> Value {
    let dependencies: Vec<Value> = metadata["deps"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|dependency| {
            let renamed = &dependency["explicit_name_in_toml"];
            // This registry is crates.io as far as its users can tell, and a dependency on the
            // registry holding the crate is left unnamed.
            let registry = match dependency["registry"].as_str() {
                Some(CRATES_IO_INDEX) | None => Value::Null,
                Some(registry) => json!(registry),
            };
            json!({
                "name": if renamed.is_null() { &dependency["name"] } else { renamed },
                "req": dependency["version_req"],
                "features": dependency["features"],
                "optional": dependency["optional"],
                "default_features": dependency["default_features"],
                "target": dependency["target"],
                "kind": dependency["kind"],
                "registry": registry,
                "package": if renamed.is_null() { &Value::Null } else { &dependency["name"] },
            })
        })
        .collect();
    json!({
        "name": metadata["name"],
        "vers": metadata["vers"],
        "deps": dependencies,
        "cksum": checksum,
        "features": metadata["features"],
        "yanked": false,
        "links": metadata["links"],
        "rust_version": metadata["rust_version"],
        "v": 2,
    })
}

impl Shared {
    fn index_file(&self, name: &str) -> PathBuf {
        self.root.join("index").join(index_path(name))
    }

    fn crate_file(&self, name: &str, version: &str) -> PathBuf {
        let crates = self.root.join("crates").join(name);
        crates.join(format!("{name}-{version}.crate"))
    }

    /// Whether crate `name` is looked up on crates.io.
    fn mirrors(&self, name: &str) -> bool {
        self.upstream && !name.starts_with(&self.local_prefix)
    }

    /// What crates.io serves at `url`, asked once.
    fn upstream(&self, url: &str) -> Result<Option<Vec<u8>>, String> {
        if let Some(known) = self.state.lock().unwrap().fetched.get(url) {
            return Ok(known.clone());
        }
        let fetched = fetch(url)?;
        let mut state = self.state.lock().unwrap();
        state.fetched.insert(url.to_owned(), fetched.clone());
        Ok(fetched)
    }

    /// Index file of crate `name`: the versions crates.io has, then the ones published here.
    /// Nothing for a crate that is in neither.
    fn index(&self, name: &str) -> Result<Option<String>, String> {
        let mut lines = String::new();
        if self.mirrors(name) {
            let url = format!("{UPSTREAM_INDEX}/{}", index_path(name));
            if let Some(upstream) = self.upstream(&url)? {
                lines += String::from_utf8_lossy(&upstream).trim_end();
                lines += "\n";
            }
        }
        if let Ok(local) = fs::read_to_string(self.index_file(name)) {
            lines += &local;
        }
        Ok((!lines.is_empty()).then_some(lines))
    }

    fn add_to_index(&self, entry: &Value) {
        // One writer at a time.
        let _state = self.state.lock().unwrap();
        let path = self.index_file(entry["name"].as_str().unwrap());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut file = fs::OpenOptions::new().create(true).append(true).open(path);
        writeln!(file.as_mut().unwrap(), "{entry}").unwrap();
    }

    fn get(&self, path: &str) -> Result<Response, String> {
        let not_found = |what: String| Ok(Response::error("404 Not Found", what));
        if path == "/index/config.json" {
            let download = format!("{}/api/v1/crates/{{crate}}/{{version}}/download", self.url);
            let config = json!({ "dl": download, "api": self.url });
            return Ok(Response::json("200 OK", &config));
        }
        if let Some(path) = path.strip_prefix("/index/") {
            let name = path.rsplit('/').next().unwrap_or_default();
            let known = !name.is_empty() && path == index_path(name);
            return match known.then(|| self.index(name)).transpose()?.flatten() {
                Some(index) => Ok(Response {
                    status: "200 OK",
                    content_type: "text/plain",
                    body: index.into_bytes(),
                }),
                None => not_found(format!("no crate at {path}")),
            };
        }
        let download = path.strip_prefix("/api/v1/crates/");
        let download = download.and_then(|path| path.strip_suffix("/download"));
        if let Some((name, version)) = download.and_then(|path| path.split_once('/')) {
            let body = match fs::read(self.crate_file(name, version)) {
                Ok(body) => Some(body),
                Err(_) if self.mirrors(name) => {
                    self.upstream(&format!("{UPSTREAM_CRATES}/{name}/{name}-{version}.crate"))?
                }
                Err(_) => None,
            };
            return match body {
                Some(body) => Ok(Response {
                    status: "200 OK",
                    content_type: "application/gzip",
                    body,
                }),
                None => not_found(format!("no crate {name} {version}")),
            };
        }
        not_found(format!("nothing at {path}"))
    }

    fn publish(
        self: &Arc<Self>,
        authorization: Option<&str>,
        body: &[u8],
    ) -> Result<Response, String> {
        // Layout: metadata length, JSON metadata, crate length, crate; lengths are 32 bit little
        // endian.
        let length = |at: usize| -> Result<usize, String> {
            let bytes = body.get(at..at + 4).ok_or("truncated publication")?;
            Ok(u32::from_le_bytes(bytes.try_into().unwrap()) as usize)
        };
        let metadata_end = 4 + length(0)?;
        let crate_start = metadata_end + 4;
        let crate_end = crate_start + length(metadata_end)?;
        let metadata = body.get(4..metadata_end).ok_or("truncated publication")?;
        let metadata: Value =
            serde_json::from_slice(metadata).map_err(|error| error.to_string())?;
        let crate_file = body
            .get(crate_start..crate_end)
            .ok_or("truncated publication")?;
        let name = metadata["name"].as_str().ok_or("unnamed publication")?;
        let version = metadata["vers"]
            .as_str()
            .ok_or("publication without version")?;

        if authorization != Some(self.token.as_str()) {
            let refusal = "this token cannot publish to the test mirror";
            return Ok(Response::error("403 Forbidden", refusal));
        }
        {
            let mut state = self.state.lock().unwrap();
            if let Some(left) = state.rejections.get_mut(name).filter(|left| **left > 0) {
                if *left != ALWAYS {
                    *left -= 1;
                }
                let refusal = format!("the test mirror was told to reject {name}");
                return Ok(Response::error("500 Internal Server Error", refusal));
            }
        }
        let listed = self.index(name)?.unwrap_or_default();
        let versions = listed
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok());
        let duplicate = versions.into_iter().any(|entry| entry["vers"] == version);
        let destination = self.crate_file(name, version);
        if duplicate || destination.exists() {
            let refusal = format!("crate version `{version}` is already uploaded");
            return Ok(Response::error("400 Bad Request", refusal));
        }

        fs::create_dir_all(destination.parent().unwrap()).map_err(|error| error.to_string())?;
        fs::write(&destination, crate_file).map_err(|error| error.to_string())?;
        let (delay, corrupted) = {
            let mut state = self.state.lock().unwrap();
            state.uploads.push((name.to_owned(), version.to_owned()));
            (
                state.index_delay,
                state.corrupted.iter().any(|corrupted| corrupted == name),
            )
        };
        let listed: &[u8] = if corrupted {
            b"another file"
        } else {
            crate_file
        };
        let entry = index_entry(&metadata, &sha256(listed));
        if delay.is_zero() {
            self.add_to_index(&entry);
        } else {
            let shared = Arc::clone(self);
            std::thread::spawn(move || {
                std::thread::sleep(delay);
                shared.add_to_index(&entry);
            });
        }
        let warnings = json!({ "invalid_categories": [], "invalid_badges": [], "other": [] });
        Ok(Response::json("200 OK", &json!({ "warnings": warnings })))
    }

    /// Answer the request of a connection, which is then closed.
    fn serve(self: &Arc<Self>, mut stream: TcpStream) -> std::io::Result<()> {
        let mut request = BufReader::new(stream.try_clone()?);
        let mut line = String::new();
        request.read_line(&mut line)?;
        let mut words = line.split_whitespace();
        let method = words.next().unwrap_or_default().to_owned();
        let target = words.next().unwrap_or_default().to_owned();
        let path = target.split('?').next().unwrap_or_default();

        let mut headers = HashMap::new();
        loop {
            line.clear();
            request.read_line(&mut line)?;
            let Some((name, value)) = line.trim_end().split_once(':') else {
                break;
            };
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
        // What a client asks before sending a large body.
        if headers
            .get("expect")
            .is_some_and(|expect| expect.eq_ignore_ascii_case("100-continue"))
        {
            stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
        }
        let length = headers
            .get("content-length")
            .and_then(|length| length.parse().ok());
        let mut body = vec![0; length.unwrap_or(0)];
        request.read_exact(&mut body)?;

        let response = match (method.as_str(), path) {
            ("GET", path) => self.get(path),
            ("PUT", "/api/v1/crates/new") => {
                self.publish(headers.get("authorization").map(String::as_str), &body)
            }
            _ => Ok(Response::error(
                "404 Not Found",
                format!("nothing at {path}"),
            )),
        };
        let response = response.unwrap_or_else(|problem| {
            Response::error(
                "502 Bad Gateway",
                format!("the test mirror failed: {problem}"),
            )
        });
        write!(
            stream,
            "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response.status,
            response.content_type,
            response.body.len()
        )?;
        stream.write_all(&response.body)?;
        stream.flush()
    }
}

impl Mirror {
    /// Start a registry keeping what it receives in `root`, on a free loopback port. It serves
    /// until the process ends.
    pub fn start(root: &Path, token: &str, upstream: bool, local_prefix: &str) -> Self {
        fs::create_dir_all(root.join("index")).unwrap();
        fs::create_dir_all(root.join("crates")).unwrap();
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let shared = Arc::new(Shared {
            root: root.to_owned(),
            url: format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port()),
            token: token.to_owned(),
            upstream,
            local_prefix: local_prefix.to_owned(),
            state: Mutex::default(),
        });
        let serving = Arc::clone(&shared);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let shared = Arc::clone(&serving);
                std::thread::spawn(move || {
                    // A client that hangs up is its own problem.
                    let _ = shared.serve(stream);
                });
            }
        });
        Self { shared }
    }

    /// Where cargo is told the index is.
    pub fn index_url(&self) -> String {
        format!("sparse+{}/index/", self.shared.url)
    }

    /// Refuse the next `times` publications of crate `name`, see [`ALWAYS`].
    pub fn reject(&self, name: &str, times: u32) {
        let mut state = self.shared.state.lock().unwrap();
        state.rejections.insert(name.to_owned(), times);
    }

    pub fn accept_everything(&self) {
        self.shared.state.lock().unwrap().rejections.clear();
    }

    /// List the publications of crate `name` with the checksum of another file than the one
    /// received, as a registry serving something else would.
    pub fn corrupt(&self, name: &str) {
        self.shared
            .state
            .lock()
            .unwrap()
            .corrupted
            .push(name.to_owned());
    }

    /// Have the publications take `delay` to show in the index.
    pub fn delay_index(&self, delay: Duration) {
        self.shared.state.lock().unwrap().index_delay = delay;
    }

    /// Crates received so far, in order, with their version.
    pub fn uploads(&self) -> Vec<(String, String)> {
        self.shared.state.lock().unwrap().uploads.clone()
    }

    /// Versions of crate `name` published here, with the checksum the index gives them.
    pub fn published(&self, name: &str) -> BTreeMap<String, String> {
        let index = fs::read_to_string(self.index_file(name)).unwrap_or_default();
        let entries = index
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap());
        entries
            .map(|entry| {
                let field = |name: &str| entry[name].as_str().unwrap().to_owned();
                (field("vers"), field("cksum"))
            })
            .collect()
    }

    /// The crate file received for a version of crate `name`.
    pub fn crate_file(&self, name: &str, version: &str) -> PathBuf {
        self.shared.crate_file(name, version)
    }

    /// The file listing the versions of crate `name` published here.
    pub fn index_file(&self, name: &str) -> PathBuf {
        self.shared.index_file(name)
    }

    /// Whether something about crate `name` was fetched from crates.io.
    pub fn mirrored(&self, name: &str) -> bool {
        let state = self.shared.state.lock().unwrap();
        state
            .fetched
            .iter()
            .any(|(url, fetched)| url.contains(name) && fetched.is_some())
    }
}
