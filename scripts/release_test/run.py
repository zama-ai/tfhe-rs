#!/usr/bin/env python3
"""Run the release tooling against a local registry, on a workspace of test crates.

A rehearsal of what the release workflow asks of scripts/release_publish.py, real
uploads included, set up so that nothing can end up on crates.io:
  - what gets published is a workspace of test crates generated on the spot,
    that cargo is only allowed to send to the test registry (`publish = [..]`);
  - the registry is scripts/release_test/registry_mirror.py, listening on a
    loopback port: it replaces crates.io in the configuration of a throwaway
    CARGO_HOME and mirrors it, read-only, for the dependencies of the test crates;
  - the registry tokens of the environment are not handed to cargo.

The test crates have what makes the workspace of this repository delicate to
release: a proc-macro, a build script that must not see the registry token (the
CUDA backends have one), an optional dependency, a crate that is not published
and a dependency on a crate of crates.io.
"""

import argparse
import hashlib
import json
import math
import os
import shlex
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

from registry_mirror import Mirror

SCRIPTS = Path(__file__).resolve().parent.parent
REPO = SCRIPTS.parent

REGISTRY = "test-mirror"
TOKEN = "test-mirror-token"
# The variable cargo reads the token of the registry from.
TOKEN_VARIABLE = "CARGO_REGISTRIES_TEST_MIRROR_TOKEN"

PREFIX = "release-test-"
DERIVE = PREFIX + "derive"
VERSIONABLE = PREFIX + "versionable"
CUDA_COMMON = PREFIX + "cuda-common"
CUDA_BACKEND = PREFIX + "cuda-backend"
MAIN = PREFIX + "main"
INTERNAL = PREFIX + "internal"
PUBLISHED_CRATES = [DERIVE, VERSIONABLE, CUDA_COMMON, CUDA_BACKEND, MAIN]

# Any exit code but 0, for the failures that are cargo's own.
FAILURE = "failure"

SOURCES = {
    DERIVE: {
        "src/lib.rs": """
            use proc_macro::TokenStream;

            #[proc_macro_derive(Versionize)]
            pub fn versionize(_input: TokenStream) -> TokenStream {
                TokenStream::new()
            }
            """
    },
    VERSIONABLE: {
        "src/lib.rs": """
            pub use release_test_derive::Versionize;

            #[derive(Versionize)]
            pub struct Versioned;
            """
    },
    CUDA_COMMON: {
        # A build script runs whatever it wants on the machine making the release,
        # and so does the build script of any dependency: the registry token must
        # not be around when crates are built.
        "build.rs": f"""
            fn main() {{
                println!("cargo::rerun-if-env-changed={TOKEN_VARIABLE}");
                if std::env::var_os("{TOKEN_VARIABLE}").is_some() {{
                    panic!("the registry token is visible to a build script");
                }}
            }}
            """,
        "src/lib.rs": """
            pub fn device_count() -> u32 {
                0
            }
            """,
    },
    CUDA_BACKEND: {
        "src/lib.rs": """
            pub fn device_count() -> u32 {
                release_test_cuda_common::device_count()
            }
            """
    },
    MAIN: {
        "src/lib.rs": """
            pub use release_test_versionable::Versioned;

            #[cfg(feature = "gpu")]
            pub fn device_count() -> u32 {
                release_test_cuda_backend::device_count()
            }
            """
    },
    INTERNAL: {
        "src/lib.rs": """
            pub use release_test_main::Versioned;
            """
    },
}


class Failure(Exception):
    pass


def check(condition, message):
    if not condition:
        raise Failure(message)


def step(title):
    print(f"\n\n=== {title} ===", flush=True)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def tag_of(crate, version):
    return f"{crate}-{version}"


class TestRun:
    def __init__(self, work, upstream):
        self.work = work
        self.repo = work / "repo"
        self.checkout = work / "checkout"
        self.upstream = upstream
        self.versions = {name: "0.1.0" for name in SOURCES} | {MAIN: "1.0.0"}
        # What the crates ask of their dependencies: a patch release of a crate
        # does not change the requirement of its users.
        self.requirements = dict(self.versions)
        self.mirror = Mirror(
            work / "registry", TOKEN, upstream=upstream, local_prefix=PREFIX
        )
        self.seen = 0

    # Setting up

    def environment(self, token=False, color=False):
        # Neither the registries and tokens cargo is told about through the
        # environment, nor a target directory shared with other builds.
        dropped = ("CARGO_REGISTRY_", "CARGO_REGISTRIES_", "CARGO_TARGET_DIR")
        dropped += ("CARGO_BUILD_TARGET_DIR",)
        env = {
            name: value
            for name, value in os.environ.items()
            if not name.startswith(dropped)
        }
        env["CARGO_HOME"] = str(self.work / "cargo-home")
        # The registry is local, whatever proxy the machine goes through.
        local = "127.0.0.1,localhost"
        inherited = os.environ.get("NO_PROXY") or os.environ.get("no_proxy")
        env["NO_PROXY"] = env["no_proxy"] = ",".join(filter(None, [inherited, local]))
        if token:
            env[TOKEN_VARIABLE] = TOKEN
        if color:
            # What a workflow may set, and what the output of cargo is read through.
            env["CARGO_TERM_COLOR"] = "always"
        return env

    def run(self, *command, cwd=None):
        result = subprocess.run(
            command,
            cwd=cwd or self.repo,
            env=self.environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if result.returncode != 0:
            print(result.stdout)
            raise Failure(f"{shlex.join(command)} failed")
        return result.stdout

    def git(self, *arguments, cwd=None):
        # Whatever the configuration of the user says about identity and signing.
        options = ["user.name=release test", "user.email=release-test@example.org"]
        options += ["commit.gpgsign=false", "tag.gpgsign=false"]
        configuration = [part for option in options for part in ("-c", option)]
        return self.run("git", *configuration, *arguments, cwd=cwd).strip()

    def manifest(self, name, package="", body=""):
        if name == INTERNAL:
            publish = "publish = false"
        else:
            # cargo refuses to send the crate to any other registry.
            publish = f'publish = ["{REGISTRY}"]'
        return (
            "[package]\n"
            f'name = "{name}"\n'
            f'version = "{self.versions[name]}"\n'
            'edition = "2021"\n'
            'license = "BSD-3-Clause-Clear"\n'
            'description = "Test crate of the tfhe-rs release tooling"\n'
            'repository = "https://github.com/zama-ai/tfhe-rs"\n'
            f"{publish}\n{package}\n{body}"
        )

    def dependency(self, name, optional=False):
        optional = ", optional = true" if optional else ""
        requirement = self.requirements[name]
        return (
            f'{name} = {{ version = "{requirement}", path = "../{name}"{optional} }}\n'
        )

    def write_manifests(self):
        external = 'cfg-if = "1"\n' if self.upstream else ""
        manifests = {
            DERIVE: self.manifest(DERIVE, body="[lib]\nproc-macro = true\n"),
            VERSIONABLE: self.manifest(
                VERSIONABLE, body="[dependencies]\n" + self.dependency(DERIVE)
            ),
            CUDA_COMMON: self.manifest(
                CUDA_COMMON, package='links = "release_test_cuda_common"\n'
            ),
            CUDA_BACKEND: self.manifest(
                CUDA_BACKEND, body="[dependencies]\n" + self.dependency(CUDA_COMMON)
            ),
            MAIN: self.manifest(
                MAIN,
                body="[dependencies]\n"
                + self.dependency(VERSIONABLE)
                + self.dependency(CUDA_BACKEND, optional=True)
                + external
                + f'\n[features]\ngpu = ["dep:{CUDA_BACKEND}"]\n',
            ),
            INTERNAL: self.manifest(
                INTERNAL, body="[dependencies]\n" + self.dependency(MAIN)
            ),
        }
        for name, manifest in manifests.items():
            (self.repo / name / "Cargo.toml").write_text(manifest)

    def setup(self):
        cargo_home = self.work / "cargo-home"
        cargo_home.mkdir(parents=True)
        (cargo_home / "config.toml").write_text(
            f"[registries.{REGISTRY}]\n"
            f'index = "{self.mirror.index_url}"\n\n'
            # cargo goes to the test registry for everything it would ask crates.io.
            "[source.crates-io]\n"
            f'replace-with = "{REGISTRY}"\n'
        )
        members = ", ".join(f'"{name}"' for name in SOURCES)
        self.repo.mkdir()
        (self.repo / "Cargo.toml").write_text(
            f'[workspace]\nresolver = "3"\nmembers = [{members}]\n'
        )
        (self.repo / ".gitignore").write_text("target/\n")
        # Package with the cargo that releases the real crates.
        shutil.copy(REPO / "rust-toolchain.toml", self.repo)
        for name, files in SOURCES.items():
            for path, content in files.items():
                file = self.repo / name / path
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text(textwrap.dedent(content).lstrip())
        if self.upstream:
            with (self.repo / MAIN / "src/lib.rs").open("a") as file:
                file.write("\npub use cfg_if::cfg_if;\n")
        self.write_manifests()
        self.run("cargo", "generate-lockfile")
        self.git("init", "--quiet", "--initial-branch", "main")
        self.commit("test crates")

    def commit(self, message):
        self.git("add", "--all")
        self.git("commit", "--quiet", "--message", message)
        return self.git("rev-parse", "HEAD")

    def bump(self, versions, requirements=()):
        """Commit new versions, along with what the users of `requirements` ask for."""
        self.versions |= versions
        self.requirements |= {name: self.versions[name] for name in requirements}
        self.write_manifests()
        self.run("cargo", "update", "--workspace")
        return self.commit("bump " + ", ".join(versions))

    def tag(self, crate):
        """Tag the current commit as the release of `crate`, return the tag."""
        tag = tag_of(crate, self.versions[crate])
        self.git("tag", "--annotate", "--message", f"{crate} release", tag)
        return tag

    def fresh_checkout(self):
        """Another checkout of the current commit, as a job on another machine has."""
        shutil.rmtree(self.checkout, ignore_errors=True)
        self.git("clone", "--quiet", str(self.repo), str(self.checkout), cwd=self.work)
        return self.checkout

    # Running the tooling

    def script(self, name, *arguments, repo=None, token=False, color=False, expect=0):
        command = [
            sys.executable,
            str(SCRIPTS / name),
            "--repo",
            str(repo or self.repo),
        ]
        command += ["--registry", REGISTRY, "--index", self.mirror.index_url]
        print(f"\n$ {name} {shlex.join(arguments)}", flush=True)
        result = subprocess.run(
            [*command, *arguments],
            env=self.environment(token, color),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        print(textwrap.indent(result.stdout, "    "), flush=True)
        if expect == FAILURE:
            check(result.returncode != 0, "this was expected to fail")
        else:
            check(
                result.returncode == expect,
                f"exit code {result.returncode} instead of {expect}",
            )
        return result.stdout

    def release(self, *arguments, **options):
        return self.script("release_publish.py", *arguments, **options)

    def plan(self, *arguments):
        command = [sys.executable, str(SCRIPTS / "release_publish.py")]
        command += ["--repo", str(self.repo), "--registry", REGISTRY]
        command += ["--index", self.mirror.index_url, *arguments, "plan", "--json"]
        result = subprocess.run(
            command, env=self.environment(), stdout=subprocess.PIPE, text=True
        )
        # The plan is printed whether or not the release can go ahead.
        check(result.stdout.startswith("{"), f"no plan from {shlex.join(arguments)}")
        return json.loads(result.stdout)

    def uploads(self):
        """Crates the registry received since the last call, in order."""
        events = self.mirror.events[self.seen :]
        self.seen += len(events)
        return [
            (name, version) for kind, name, version, *_ in events if kind == "published"
        ]

    def check_checksums(self, expected, repo=None):
        """Check SHA256SUMS lists the crates `expected`, as the registry holds them."""
        directory = (repo or self.repo) / "target" / "release-crates"
        lines = (directory / "SHA256SUMS").read_text().splitlines()
        listed = dict(reversed(line.split()) for line in lines)
        files = [f"{name}-{version}.crate" for name, version in expected]
        check(sorted(listed) == sorted(files), f"SHA256SUMS lists {sorted(listed)}")
        for (name, version), file in zip(expected, files):
            held = sha256(self.mirror.crate_file(name, version))
            check(listed[file] == held, f"{file} is not the file the registry holds")
            check(sha256(directory / file) == held, f"{file} was not gathered")

    # The rehearsal

    def rehearse(self, slow):
        new = "--allow-new-crates"
        self.setup()

        step(
            "A rehearsal selects every crate that is not published, and uploads nothing"
        )
        plan = self.plan("--rehearsal", new)
        order = plan["publish"]
        check(sorted(order) == sorted(PUBLISHED_CRATES), f"selected {order}")
        for user, dependency in [
            (VERSIONABLE, DERIVE),
            (CUDA_BACKEND, CUDA_COMMON),
            (MAIN, VERSIONABLE),
            (MAIN, CUDA_BACKEND),
        ]:
            check(
                order.index(dependency) < order.index(user),
                f"{user} comes before {dependency}",
            )
        self.release("--rehearsal", new, "publish", "--dry-run")
        output = self.release("--rehearsal", new, "publish", expect=1)
        check("can only be a dry run" in output, "a rehearsal was about to upload")
        check(self.uploads() == [], "a dry run uploaded crates")

        step("A build script sees the registry token of a run that verifies crates")
        output = self.release(
            "--rehearsal", new, "publish", "--dry-run", token=True, expect=FAILURE
        )
        check("the registry token is visible" in output, "the build script did not run")

        step("Without a release tag on the commit there is nothing to publish")
        check(self.plan(new)["publish"] == [], "untagged crates were selected")
        self.release(new, "publish", "--no-verify", token=True)
        check(self.uploads() == [], "untagged crates were uploaded")

        step("The first version of a crate is not left to trusted publishing")
        self.tag(DERIVE)
        tag = self.tag(VERSIONABLE)
        output = self.release("--tag", tag, "plan", expect=1)
        check("would be the first version" in output, "a new crate went unnoticed")

        step("A release publishes the crates tagged on the commit, and only those")
        selected = self.plan("--tag", tag, new)["publish"]
        check(selected == [DERIVE, VERSIONABLE], f"selected {selected}")
        self.release("--tag", tag, new, "publish", "--dry-run")
        check(self.uploads() == [], "verifying uploaded crates")
        self.release("--tag", tag, new, "publish", "--no-verify", expect=FAILURE)
        check(self.uploads() == [], "crates were uploaded without a token")
        self.release("--tag", tag, new, "publish", "--no-verify", token=True)
        first = [(DERIVE, "0.1.0"), (VERSIONABLE, "0.1.0")]
        check(self.uploads() == first, "the tagged crates were not uploaded in order")
        self.check_checksums(first)

        step("Another checkout reproduces the crates that are in the registry")
        output = self.release("--tag", tag, "reproduce", repo=self.fresh_checkout())
        check("are the ones of test-mirror" in output, "nothing was compared")
        self.check_checksums(first, repo=self.checkout)

        step("A crate is not released without the crates it depends on")
        tag = self.tag(MAIN)
        output = self.release("--tag", tag, new, "plan", expect=1)
        missing = f"depends on {CUDA_BACKEND} 0.1.0, which is neither on"
        check(missing in output, "the missing dependency went unnoticed")
        self.release("--tag", tag, new, "publish", "--no-verify", token=True, expect=1)
        check(self.uploads() == [], "an incomplete release uploaded crates")

        step("A release that failed half way is resumed by running it again")
        self.tag(CUDA_COMMON)
        self.tag(CUDA_BACKEND)
        self.release("--tag", tag, new, "publish", "--dry-run")
        self.mirror.rejections[CUDA_BACKEND] = math.inf
        self.release(
            "--tag", tag, new, "publish", "--no-verify", token=True, expect=FAILURE
        )
        check(self.uploads() == [(CUDA_COMMON, "0.1.0")], "the release did not stop")
        self.mirror.rejections.clear()
        left = self.plan("--tag", tag, new)
        check(left["publish"] == [CUDA_BACKEND, MAIN], f"left with {left['publish']}")
        check(MAIN in left["released"], f"{MAIN} is not seen as being released")
        check(INTERNAL not in left["released"], f"{INTERNAL} is being released")
        self.release("--tag", tag, new, "publish", "--no-verify", token=True)
        second = [(CUDA_BACKEND, "0.1.0"), (MAIN, "1.0.0")]
        check(self.uploads() == second, "the release was not resumed")
        self.check_checksums(second)
        released = self.plan("--tag", tag)
        check(released["publish"] == [], "published crates are selected again")
        check(
            sorted(released["released"]) == sorted(PUBLISHED_CRATES),
            f"released from this commit: {released['released']}",
        )
        self.release("--tag", tag, "reproduce", repo=self.fresh_checkout())
        # The crates of the run that failed and of the first release are part of it.
        everything = [(CUDA_COMMON, "0.1.0"), *first, *second]
        self.check_checksums(everything, repo=self.checkout)

        step("A crate that is not the one in the registry does not reproduce")
        index = next((self.mirror.root / "index").rglob(VERSIONABLE))
        genuine = index.read_text()
        entry = json.loads(genuine)
        index.write_text(json.dumps(entry | {"cksum": "0" * 64}) + "\n")
        output = self.release("--tag", tag, "reproduce", repo=self.checkout, expect=1)
        tampered = f"{VERSIONABLE}-0.1.0.crate does not reproduce"
        check(tampered in output, "a crate that is not the published one passed")
        index.write_text(genuine)

        step("A patch release of one crate publishes that crate alone")
        self.bump({VERSIONABLE: "0.1.1"})
        tag = self.tag(VERSIONABLE)
        self.release("--tag", tag, "publish", "--dry-run")
        sums = self.repo / "target" / "release-crates" / "SHA256SUMS"
        against = ["reproduce", "--against", str(sums)]
        output = self.release("--tag", tag, *against, repo=self.fresh_checkout())
        check("are the ones of" in output, "nothing was compared")
        self.release("--tag", tag, "publish", "--no-verify", token=True)
        check(
            self.uploads() == [(VERSIONABLE, "0.1.1")], "more than the patch went out"
        )

        step("A dependency tagged on another commit is released from that commit")
        changed = [CUDA_COMMON, CUDA_BACKEND]
        versions = {CUDA_COMMON: "0.2.0", CUDA_BACKEND: "0.2.0", MAIN: "1.1.0"}
        earlier = self.bump(versions, requirements=changed)
        common_tag = self.tag(CUDA_COMMON)
        with (self.repo / MAIN / "src/lib.rs").open("a") as file:
            file.write("\npub const LATE_FIX: bool = true;\n")
        self.commit("late fix")
        self.tag(CUDA_BACKEND)
        tag = self.tag(MAIN)
        output = self.release("--tag", tag, "plan", expect=1)
        check("tagged on another commit" in output, "a stray tag went unnoticed")
        output = self.release("--tag", common_tag, "plan", expect=1)
        check("is checked out" in output, "a tag of another commit was accepted")
        output = self.release("--tag", tag_of(VERSIONABLE, "0.1.0"), "plan", expect=1)
        check("is not the release tag" in output, "the tag of an old version passed")
        self.git("checkout", "--quiet", earlier)
        self.release("--tag", common_tag, "publish", "--no-verify", token=True)
        check(
            self.uploads() == [(CUDA_COMMON, "0.2.0")],
            "the dependency was not released on its own from its commit",
        )
        self.git("checkout", "--quiet", "main")

        step("cargo is run again for the crates an upload left behind")
        self.mirror.rejections[MAIN] = 1
        output = self.release(
            "--tag", tag, "publish", "--no-verify", token=True, color=True
        )
        check(f"resuming with {MAIN}" in output, "the upload was not resumed")
        third = [(CUDA_BACKEND, "0.2.0"), (MAIN, "1.1.0")]
        check(self.uploads() == third, "the crates left behind were not uploaded")
        self.check_checksums(third)

        if slow:
            step("An index more than a minute late does not fail the release")
            versions = {CUDA_COMMON: "0.3.0", CUDA_BACKEND: "0.3.0", MAIN: "1.2.0"}
            self.bump(versions, requirements=changed)
            for crate in versions:
                tag = self.tag(crate)
            self.mirror.index_delay = 70
            output = self.release("--tag", tag, "publish", "--no-verify", token=True)
            self.mirror.index_delay = 0
            check("timed out waiting" in output, "cargo did not give up on the index")
            check(len(self.uploads()) == 3, "the release was not completed")

        step("The status report reads the test registry as well")
        output = self.script("release_status.py")
        check("up to date on test-mirror" in output, "something is left to release")

        for crate in PUBLISHED_CRATES:
            held = sorted(self.mirror.published(crate))
            check(self.versions[crate] in held, f"{crate} is missing from the registry")
        check(not self.mirror.published(INTERNAL), f"{INTERNAL} was published")
        if self.upstream:
            mirrored = any("cfg-if" in url for url in self.mirror.upstream_cache)
            check(mirrored, "the dependency on crates.io was not mirrored")


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=REPO / "target" / "release-test",
        help="directory to work in, emptied first: it holds the registry, the test"
        " crates and what cargo builds, so it cannot be mounted noexec the way /tmp"
        " may be. Defaults to target/release-test",
    )
    parser.add_argument(
        "--no-upstream",
        action="store_true",
        help="do not mirror crates.io and leave the dependency on one of its crates"
        " out, to run without network access",
    )
    parser.add_argument(
        "--slow",
        action="store_true",
        help="also rehearse a registry index that is late enough for cargo to give"
        " up on it, which takes a few minutes",
    )
    args = parser.parse_args()

    work = args.work_dir.resolve()
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    test = TestRun(work, not args.no_upstream)
    test.mirror.start()
    print(f"test registry: {test.mirror.index_url}, working in {work}")
    try:
        test.rehearse(args.slow)
    except Failure as failure:
        print(f"\nFAILED: {failure}\nEverything was left in {work}", file=sys.stderr)
        return 1
    finally:
        test.mirror.stop()
    print(f"\nThe release tooling works as expected, see {work} for what it left.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
