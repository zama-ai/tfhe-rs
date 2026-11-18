//! What the tests of the release tooling work with: a workspace of test crates in a repository of
//! its own, a local registry to release them to, and the release tooling run on both.
//!
//! Nothing can end up on crates.io:
//!   - what gets published is a workspace of test crates generated for the test, that cargo is only
//!     allowed to send to the test registry (`publish = [..]`);
//!   - the registry is [`mirror::Mirror`], listening on a loopback port: it replaces crates.io in
//!     the configuration of a throwaway `CARGO_HOME`;
//!   - the registry tokens of the environment are not handed to cargo.
//!
//! The test crates have what makes the workspace of this repository delicate to release: a
//! proc-macro, a build script that must not see the registry token (the CUDA backends have one),
//! an optional dependency and a crate that is not published.

pub mod mirror;

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, PoisonError};

use mirror::{Mirror, sha256};
use serde_json::Value;

pub const REGISTRY: &str = "test-mirror";
const TOKEN: &str = "test-mirror-token";
/// The variable cargo reads the token of the registry from.
const TOKEN_VARIABLE: &str = "CARGO_REGISTRIES_TEST_MIRROR_TOKEN";

const PREFIX: &str = "release-test-";
pub const DERIVE: &str = "release-test-derive";
pub const VERSIONABLE: &str = "release-test-versionable";
pub const CUDA_COMMON: &str = "release-test-cuda-common";
pub const CUDA_BACKEND: &str = "release-test-cuda-backend";
pub const MAIN: &str = "release-test-main";
/// Not published, as most crates of a workspace.
pub const INTERNAL: &str = "release-test-internal";
/// The crates that are released, in the order of the workspace.
pub const RELEASED: [&str; 5] = [DERIVE, VERSIONABLE, CUDA_COMMON, CUDA_BACKEND, MAIN];

const DERIVE_LIB: &str = "\
use proc_macro::TokenStream;

#[proc_macro_derive(Versionize)]
pub fn versionize(_input: TokenStream) -> TokenStream {
    TokenStream::new()
}
";

const VERSIONABLE_LIB: &str = "\
pub use release_test_derive::Versionize;

#[derive(Versionize)]
pub struct Versioned;
";

/// A build script runs whatever it wants on the machine making the release, and so does the
/// build script of any dependency: the registry token must not be around when crates are built.
const CUDA_COMMON_BUILD: &str = "\
fn main() {
    println!(\"cargo::rerun-if-env-changed=CARGO_REGISTRIES_TEST_MIRROR_TOKEN\");
    if std::env::var_os(\"CARGO_REGISTRIES_TEST_MIRROR_TOKEN\").is_some() {
        panic!(\"the registry token is visible to a build script\");
    }
}
";

const CUDA_COMMON_LIB: &str = "\
pub fn device_count() -> u32 {
    0
}
";

const CUDA_BACKEND_LIB: &str = "\
pub fn device_count() -> u32 {
    release_test_cuda_common::device_count()
}
";

const MAIN_LIB: &str = "\
pub use release_test_versionable::Versioned;

#[cfg(feature = \"gpu\")]
pub fn device_count() -> u32 {
    release_test_cuda_backend::device_count()
}
";

const INTERNAL_LIB: &str = "\
pub use release_test_main::Versioned;
";

/// The tests take turns: each of them removes what its last run left, runs cargo and runs git, in
/// directories next to each other. Done concurrently, this makes processes lose their working
/// directory on some filesystems, the directories a container shares with its host among them.
static TURN: Mutex<()> = Mutex::new(());

/// What a run of the release tooling printed, and how it ended.
pub struct Run {
    pub code: i32,
    pub output: String,
}

impl Run {
    #[track_caller]
    pub fn success(self) -> String {
        assert_eq!(self.code, 0, "the run failed");
        self.output
    }

    /// The run was refused by the release tooling itself.
    #[track_caller]
    pub fn refused(self) -> String {
        assert_eq!(self.code, 1, "the run was not refused");
        self.output
    }

    /// The run failed, with the exit code of cargo when the failure is its own.
    #[track_caller]
    pub fn failure(self) -> String {
        assert_ne!(self.code, 0, "the run was expected to fail");
        self.output
    }
}

/// How the release tooling is run.
#[derive(Clone, Copy, Default)]
pub struct Options {
    /// Give cargo the token of the registry.
    pub token: bool,
    /// Have cargo color what it prints, as a workflow may ask it to.
    pub color: bool,
}

pub const WITH_TOKEN: Options = Options {
    token: true,
    color: false,
};

pub struct World {
    /// Held for as long as the test works.
    _turn: MutexGuard<'static, ()>,
    work: PathBuf,
    /// The repository holding the test crates.
    pub repo: PathBuf,
    pub mirror: Mirror,
    /// Version of each crate.
    versions: BTreeMap<&'static str, String>,
    /// What the crates ask of each of their dependencies: a patch release of a crate does not
    /// change the requirement of its users.
    requirements: BTreeMap<&'static str, String>,
    /// Whether the main crate depends on a crate of crates.io, which the registry then mirrors.
    upstream: bool,
    /// Uploads already returned by [`World::uploads`].
    seen: usize,
}

impl World {
    /// A repository of test crates that were never released, for the test `name`.
    pub fn new(name: &str) -> Self {
        Self::create(name, false)
    }

    /// The same, the main crate depending on a crate of crates.io: this needs network access.
    pub fn with_a_dependency_on_crates_io(name: &str) -> Self {
        Self::create(name, true)
    }

    fn create(name: &str, upstream: bool) -> Self {
        // A test that failed leaves nothing the next ones depend on.
        let turn = TURN.lock().unwrap_or_else(PoisonError::into_inner);
        // Under the target directory: test crates are built there, which a temporary directory
        // mounted noexec, as /tmp may be, does not allow.
        let work = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join("release")
            .join(name);
        let _ = fs::remove_dir_all(&work);
        fs::create_dir_all(&work).unwrap();
        let mirror = Mirror::start(&work.join("registry"), TOKEN, upstream, PREFIX);
        let first_versions = [INTERNAL].into_iter().chain(RELEASED).map(|name| {
            let version = if name == MAIN { "1.0.0" } else { "0.1.0" };
            (name, version.to_owned())
        });
        let versions: BTreeMap<_, _> = first_versions.collect();
        let world = Self {
            _turn: turn,
            repo: work.join("repo"),
            work,
            mirror,
            requirements: versions.clone(),
            versions,
            upstream,
            seen: 0,
        };
        world.setup();
        world
    }

    // Setting up

    fn write(&self, path: &str, content: &str) {
        let path = self.repo.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    fn manifest(&self, name: &str, package: &str, body: &str) -> String {
        let publish = if name == INTERNAL {
            "publish = false".to_owned()
        } else {
            // cargo refuses to send the crate to any other registry.
            format!("publish = [\"{REGISTRY}\"]")
        };
        format!(
            "[package]\n\
            name = \"{name}\"\n\
            version = \"{}\"\n\
            edition = \"2021\"\n\
            license = \"BSD-3-Clause-Clear\"\n\
            description = \"Test crate of the tfhe-rs release tooling\"\n\
            repository = \"https://github.com/zama-ai/tfhe-rs\"\n\
            {publish}\n{package}\n{body}",
            self.versions[name]
        )
    }

    fn dependency(&self, name: &str, optional: bool) -> String {
        let optional = if optional { ", optional = true" } else { "" };
        let requirement = &self.requirements[name];
        format!("{name} = {{ version = \"{requirement}\", path = \"../{name}\"{optional} }}\n")
    }

    fn write_manifests(&self) {
        let dependencies = |lines: &[String]| format!("[dependencies]\n{}", lines.concat());
        let external = if self.upstream {
            "cfg-if = \"1\"\n"
        } else {
            ""
        };
        let manifests = [
            (
                DERIVE,
                self.manifest(DERIVE, "", "[lib]\nproc-macro = true\n"),
            ),
            (
                VERSIONABLE,
                self.manifest(
                    VERSIONABLE,
                    "",
                    &dependencies(&[self.dependency(DERIVE, false)]),
                ),
            ),
            (
                CUDA_COMMON,
                self.manifest(CUDA_COMMON, "links = \"release_test_cuda_common\"\n", ""),
            ),
            (
                CUDA_BACKEND,
                self.manifest(
                    CUDA_BACKEND,
                    "",
                    &dependencies(&[self.dependency(CUDA_COMMON, false)]),
                ),
            ),
            (
                MAIN,
                self.manifest(
                    MAIN,
                    "",
                    &format!(
                        "{}{external}\n[features]\ngpu = [\"dep:{CUDA_BACKEND}\"]\n",
                        dependencies(&[
                            self.dependency(VERSIONABLE, false),
                            self.dependency(CUDA_BACKEND, true),
                        ])
                    ),
                ),
            ),
            (
                INTERNAL,
                self.manifest(INTERNAL, "", &dependencies(&[self.dependency(MAIN, false)])),
            ),
        ];
        for (name, manifest) in manifests {
            self.write(&format!("{name}/Cargo.toml"), &manifest);
        }
    }

    fn setup(&self) {
        let cargo_home = self.work.join("cargo-home");
        fs::create_dir_all(&cargo_home).unwrap();
        // cargo goes to the test registry for everything it would ask crates.io.
        let configuration = format!(
            "[registries.{REGISTRY}]\nindex = \"{}\"\n\n\
            [source.crates-io]\nreplace-with = \"{REGISTRY}\"\n",
            self.mirror.index_url()
        );
        fs::write(cargo_home.join("config.toml"), configuration).unwrap();

        let members: Vec<String> = [INTERNAL]
            .into_iter()
            .chain(RELEASED)
            .map(|name| format!("\"{name}\""))
            .collect();
        self.write(
            "Cargo.toml",
            &format!(
                "[workspace]\nresolver = \"3\"\nmembers = [{}]\n",
                members.join(", ")
            ),
        );
        self.write(".gitignore", "target/\n");
        // Package with the cargo that releases the real crates.
        let toolchain = Path::new(env!("CARGO_MANIFEST_DIR")).join("../rust-toolchain.toml");
        fs::copy(toolchain, self.repo.join("rust-toolchain.toml")).unwrap();
        let external = if self.upstream {
            "\npub use cfg_if::cfg_if;\n"
        } else {
            ""
        };
        let sources = [
            (DERIVE, "src/lib.rs", DERIVE_LIB.to_owned()),
            (VERSIONABLE, "src/lib.rs", VERSIONABLE_LIB.to_owned()),
            (CUDA_COMMON, "build.rs", CUDA_COMMON_BUILD.to_owned()),
            (CUDA_COMMON, "src/lib.rs", CUDA_COMMON_LIB.to_owned()),
            (CUDA_BACKEND, "src/lib.rs", CUDA_BACKEND_LIB.to_owned()),
            (MAIN, "src/lib.rs", format!("{MAIN_LIB}{external}")),
            (INTERNAL, "src/lib.rs", INTERNAL_LIB.to_owned()),
        ];
        for (name, path, content) in sources {
            self.write(&format!("{name}/{path}"), &content);
        }
        self.write_manifests();
        self.run_in(&self.repo, "cargo", &["generate-lockfile"]);
        self.git(&["init", "--quiet", "--initial-branch", "main"]);
        self.commit("test crates");
    }

    /// A command that cannot reach crates.io for good, see the documentation of this module.
    fn command(&self, program: &str, options: Options) -> Command {
        let mut command = Command::new(program);
        for (name, _) in std::env::vars_os() {
            let name = name.to_string_lossy();
            // Neither the registries and tokens cargo is told about through the environment,
            // nor a target directory shared with other builds.
            let registries =
                name.starts_with("CARGO_REGISTRY_") || name.starts_with("CARGO_REGISTRIES_");
            if registries || name == "CARGO_TARGET_DIR" || name == "CARGO_BUILD_TARGET_DIR" {
                command.env_remove(name.as_ref());
            }
        }
        command.env("CARGO_HOME", self.work.join("cargo-home"));
        // The test works inside the directory of a real repository, the one of this crate: git
        // is not to look for a repository above the ones of the test, whatever happens to them.
        command.env("GIT_CEILING_DIRECTORIES", &self.work);
        // The registry is local, whatever proxy the machine goes through.
        let inherited = std::env::var("NO_PROXY").or_else(|_| std::env::var("no_proxy"));
        let local = "127.0.0.1,localhost".to_owned();
        let no_proxy = inherited.map_or(local.clone(), |inherited| format!("{inherited},{local}"));
        command
            .env("NO_PROXY", &no_proxy)
            .env("no_proxy", &no_proxy);
        if options.token {
            command.env(TOKEN_VARIABLE, TOKEN);
        }
        if options.color {
            command.env("CARGO_TERM_COLOR", "always");
        } else {
            command.env_remove("CARGO_TERM_COLOR");
        }
        command
    }

    /// Run a command that is expected to work, return what it printed.
    #[track_caller]
    fn run_in(&self, directory: &Path, program: &str, args: &[&str]) -> String {
        let mut command = self.command(program, Options::default());
        let output = command.args(args).current_dir(directory).output().unwrap();
        let printed = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(
            output.status.success(),
            "{program} {} failed:\n{printed}{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        printed.trim().to_owned()
    }

    #[track_caller]
    pub fn git(&self, args: &[&str]) -> String {
        // Whatever the configuration of the user says about identity and signing.
        let identity = [
            "user.name=release test",
            "user.email=release-test@example.org",
        ];
        let signing = ["commit.gpgsign=false", "tag.gpgsign=false"];
        let configuration = identity
            .iter()
            .chain(&signing)
            .flat_map(|option| ["-c", option]);
        let args: Vec<&str> = configuration.chain(args.iter().copied()).collect();
        self.run_in(&self.repo, "git", &args)
    }

    /// Commit everything, return the commit.
    #[track_caller]
    pub fn commit(&self, message: &str) -> String {
        self.git(&["add", "--all"]);
        self.git(&["commit", "--quiet", "--message", message]);
        self.git(&["rev-parse", "HEAD"])
    }

    /// Add a line to the main crate, as a fix does.
    pub fn change_main_crate(&self) {
        let path = self.repo.join(MAIN).join("src/lib.rs");
        let content = fs::read_to_string(&path).unwrap();
        fs::write(path, content + "\npub const LATE_FIX: bool = true;\n").unwrap();
    }

    /// Commit new versions of crates, along with what the users of the crates of `requirements`
    /// now ask of them. Returns the commit.
    #[track_caller]
    pub fn bump(
        &mut self,
        versions: &[(&'static str, &str)],
        requirements: &[&'static str],
    ) -> String {
        for (name, version) in versions {
            self.versions.insert(name, (*version).to_owned());
        }
        for name in requirements {
            self.requirements.insert(name, self.versions[name].clone());
        }
        self.write_manifests();
        self.run_in(&self.repo, "cargo", &["update", "--workspace"]);
        let bumped: Vec<&str> = versions.iter().map(|(name, _)| *name).collect();
        self.commit(&format!("bump {}", bumped.join(", ")))
    }

    pub fn version(&self, name: &str) -> &str {
        &self.versions[name]
    }

    /// The tag releasing the current version of crate `name`.
    pub fn tag_of(&self, name: &str) -> String {
        format!("{name}-{}", self.versions[name])
    }

    /// Tag the current commit as the release of crate `name`, return the tag.
    #[track_caller]
    pub fn tag(&self, name: &str) -> String {
        let tag = self.tag_of(name);
        self.git(&[
            "tag",
            "--annotate",
            "--message",
            &format!("{name} release"),
            &tag,
        ]);
        tag
    }

    /// A file of the test, outside of its repository.
    pub fn file(&self, name: &str) -> PathBuf {
        self.work.join(name)
    }

    /// Another checkout of the current commit, as a job on another machine has.
    #[track_caller]
    pub fn fresh_checkout(&self) -> PathBuf {
        let checkout = self.work.join("checkout");
        let _ = fs::remove_dir_all(&checkout);
        let (repo, destination) = (self.repo.to_str().unwrap(), checkout.to_str().unwrap());
        self.run_in(&self.work, "git", &["clone", "--quiet", repo, destination]);
        checkout
    }

    // Running the tooling

    fn tool(&self, command: &str, repo: &Path, args: &[&str], options: Options) -> Run {
        let index = self.mirror.index_url();
        let target = [
            "--repo",
            repo.to_str().unwrap(),
            "--registry",
            REGISTRY,
            "--index",
            &index,
        ];
        println!("\n$ {command} {}", args.join(" "));
        // One pipe for both outputs, to read them in the order they were written.
        let (mut reader, writer) = std::io::pipe().unwrap();
        let mut tool = self.command(env!("CARGO_BIN_EXE_tasks"), options);
        tool.arg(command).args(target).args(args);
        tool.stdout(writer.try_clone().unwrap()).stderr(writer);
        let mut running = tool.spawn().unwrap();
        // The command holds the other end of the pipe open.
        drop(tool);
        let mut output = String::new();
        reader.read_to_string(&mut output).unwrap();
        let code = running.wait().unwrap().code().unwrap_or(-1);
        println!(
            "{}",
            output
                .lines()
                .map(|line| format!("    {line}\n"))
                .collect::<String>()
        );
        Run { code, output }
    }

    /// Run `release` with these arguments on the repository.
    pub fn release(&self, args: &[&str]) -> Run {
        self.tool("release", &self.repo, args, Options::default())
    }

    pub fn release_with(&self, options: Options, args: &[&str]) -> Run {
        self.tool("release", &self.repo, args, options)
    }

    /// Run `release` with these arguments on another checkout of the repository.
    pub fn release_in(&self, checkout: &Path, args: &[&str]) -> Run {
        self.tool("release", checkout, args, Options::default())
    }

    pub fn status(&self, args: &[&str]) -> Run {
        self.tool("release-status", &self.repo, args, Options::default())
    }

    /// The plan of a release, the arguments choosing what is released.
    #[track_caller]
    pub fn plan(&self, args: &[&str]) -> Value {
        let args: Vec<&str> = args.iter().copied().chain(["plan", "--json"]).collect();
        let run = self.release(&args);
        // The plan is printed whether or not the release can go ahead, errors come after it.
        let end = run.output.rfind('}').expect("no plan was printed");
        serde_json::from_str(&run.output[..=end]).expect("the plan is not JSON")
    }

    /// Names of the crates of a list of a plan.
    #[track_caller]
    pub fn listed(plan: &Value, list: &str) -> Vec<String> {
        let names = plan[list].as_array().unwrap().iter();
        names
            .map(|name| name.as_str().unwrap().to_owned())
            .collect()
    }

    /// Crates the registry received since the last call, in order, with their version.
    pub fn uploads(&mut self) -> Vec<(String, String)> {
        let uploads = self.mirror.uploads();
        let new = uploads[self.seen..].to_vec();
        self.seen = uploads.len();
        new
    }

    /// Check the SHA256SUMS gathered in the checkout at `repo` lists the crates `expected`, as
    /// the registry holds them.
    #[track_caller]
    pub fn check_checksums(&self, repo: &Path, expected: &[(&str, &str)]) {
        let directory = repo.join("target/release-crates");
        let checksums = fs::read_to_string(directory.join("SHA256SUMS")).unwrap();
        let listed: BTreeMap<&str, &str> = checksums
            .lines()
            .map(|line| line.split_once("  ").unwrap())
            .map(|(checksum, file)| (file, checksum))
            .collect();
        let files: Vec<String> = expected
            .iter()
            .map(|(name, version)| format!("{name}-{version}.crate"))
            .collect();
        let mut sorted: Vec<&str> = files.iter().map(String::as_str).collect();
        sorted.sort();
        assert_eq!(listed.keys().copied().collect::<Vec<_>>(), sorted);
        for ((name, version), file) in expected.iter().zip(&files) {
            let held = sha256(&fs::read(self.mirror.crate_file(name, version)).unwrap());
            assert_eq!(
                listed[file.as_str()],
                held,
                "{file} is not the file the registry holds"
            );
            let gathered = sha256(&fs::read(directory.join(file)).unwrap());
            assert_eq!(gathered, held, "{file} was not gathered");
        }
    }

    /// Tag every crate on the current commit and release them all.
    #[track_caller]
    pub fn release_everything(&mut self) {
        let tags: Vec<String> = RELEASED.iter().map(|name| self.tag(name)).collect();
        let args = [
            "--tag",
            &tags[0],
            "--allow-new-crates",
            "publish",
            "--no-verify",
        ];
        self.release_with(WITH_TOKEN, &args).success();
        assert_eq!(self.uploads().len(), RELEASED.len());
    }
}

/// Value of an output in the file a GitHub step writes its outputs to, the way GitHub reads it.
#[track_caller]
pub fn step_output(outputs: &Path, name: &str) -> String {
    let outputs = fs::read_to_string(outputs).unwrap();
    let mut lines = outputs.lines();
    while let Some(line) = lines.next() {
        if let Some(value) = line.strip_prefix(&format!("{name}=")) {
            return value.to_owned();
        }
        // A value on several lines, up to the delimiter the first one names.
        if let Some(delimiter) = line.strip_prefix(&format!("{name}<<")) {
            let value: Vec<&str> = lines.take_while(|line| *line != delimiter).collect();
            return value.join("\n");
        }
    }
    panic!("no output named {name}");
}

/// `(name, version)` pairs as the registry reports them.
pub fn crates(expected: &[(&str, &str)]) -> Vec<(String, String)> {
    let crates = expected.iter();
    crates
        .map(|(name, version)| ((*name).to_owned(), (*version).to_owned()))
        .collect()
}
