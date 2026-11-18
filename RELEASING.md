# Releasing TFHE-rs

A release is one run of the `make_release_tfhe` workflow, from a release tag. It publishes the
crates to crates.io with a single `cargo publish`, attests them, then publishes the JS packages to
npmjs.com.

## What a run publishes

The crates **whose release tag points at the commit of the run and whose version is not on
crates.io yet**. Tagging is how a crate is declared ready: on `main` most crates carry a version
that is not published yet, they are left alone until they are tagged.

Release tags are named `<crate>-<version>`, and `tfhe-rs-<version>` for the `tfhe` crate. The run
can be started from any of the tags of the commit.

That subset is handed to `cargo publish -p <crate> -p <crate> ...`, which publishes it in
dependency order and resolves the crates that are not on crates.io yet from the ones published
along. A run refuses to start when a crate it publishes depends on a version that is neither on
crates.io nor tagged on the same commit.

The JS packages (`tfhe`, `tfhe-compat`, `tfhe-client`, `tfhe-client-compat`, `node-tfhe`) are built
from the `tfhe` crate: they are published when `tfhe` is released from the commit.

## Making a release

1. `make release_status` lists the crates that changed since their last release and need a version
   bump, and the ones that are bumped but not tagged. Bump what has to be, and have it merged.
2. Tag the commit to release for each crate to publish, with the commands `make release_status`
   prints, and push the tags. `make release_plan TAG=<tag>`, run on that commit, shows what a run
   from `<tag>` would publish and what would prevent it.
3. Run `make_release_tfhe` from one of the tags, as a dry-run first. Its summary shows the plan.
   Everything is built and checked, nothing is published.
4. Run it again without `dry_run`.

**A run that fails half way is resumed by running the workflow again** from the same tag: what is
on crates.io or npmjs.com already is skipped, the rest is published and everything released from
the commit is attested.

A dry-run can also be started from a branch. With no tag to tell what to release, it rehearses the
release of every crate that is not on crates.io yet (`make release_plan REHEARSAL=1` locally).

## What the workflow does

| Job | Runs on | What for |
| --- | --- | --- |
| `plan` | GitHub | Decides what to publish, fails before anything else starts if the release cannot go through |
| `verify-crates` | CUDA instance | `cargo publish --dry-run`: packages and builds every crate, CUDA backends included |
| `publish-crates` | CUDA instance | Gets a crates.io token, uploads with `cargo publish --no-verify`, checks crates.io holds the files it packaged |
| `attest-crates` | GitHub | Packages the crates again, checks they are the files crates.io serves, attests them |
| `publish-js` | GitHub | Builds the JS packages that are not on npmjs.com yet, publishes them under the `release-X.Y` tag, then moves `latest` if this is the newest stable version |

No artifact goes from a job to another, which leaves a release fewer ways to fail: the jobs only
exchange outputs, and a job that needs files makes them itself. `publish-crates` and `attest-crates`
package the crates again, which gives the same files, and `publish-js` builds the packages it
publishes, all of them before it publishes the first one.

Building crates runs code that is not ours, the build scripts and proc-macros of their
dependencies. The job building them has no permission to authenticate on a registry, the job
uploading them builds nothing but the release tooling. This is also why the crates.io token, valid
for 30 minutes, is only requested once the crates are verified.

`cargo publish` gives up when the index of crates.io takes more than a minute to list a crate the
next ones depend on. `publish-crates` then waits for the index and runs cargo again for what is
left.

The JS packages are not published from the CUDA instance: npmjs.com only accepts trusted
publishing from GitHub-hosted runners.

## Registry configuration

Both registries are published to with trusted publishing: no token is stored, each registry trusts
a workflow file name of this repository. A dry-run does not authenticate: a wrong setting only
shows when publishing for real, and is fixed by running the release again.

- **crates.io**: each crate needs a trusted publisher for the workflow `make_release_tfhe.yml`
  (crate settings, Trusted Publishing). A crate can have several: the ones of the workflows this one
  replaces are to be kept as long as a release branch uses them.
- **A new crate** cannot be created by trusted publishing: publish its first version with an API
  token, then add its trusted publisher. A run refuses to start when it would publish one.
- **npmjs.com**: each package needs a trusted publisher for `make_release_tfhe.yml` that is allowed
  to `npm publish` and has **Allow npm dist-tag** selected, which moving `latest` requires. A newly
  created trusted publisher expires unless it publishes within 2 days.

GitHub runs the version of the workflow found at the tag. A release branch that does not have this
workflow keeps releasing with the ones it has: `make_release_tfhe` from the Actions page, the
others, which are not on `main` anymore, with `gh workflow run <workflow file> --ref <tag>`.

## Attestations

Crates are attested with [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations),
through [actions/attest](https://github.com/actions/attest). They replace
[slsa-github-generator](https://github.com/slsa-framework/slsa-github-generator), which is no longer
maintained and recommends them.

An attestation is a signed [SLSA build provenance](https://slsa.dev/spec/v1.0/provenance) statement
binding the checksum of a crate file to the repository, commit and workflow that built it. GitHub
stores it (https://github.com/zama-ai/tfhe-rs/attestations) and it is recorded in the public
transparency log of Sigstore, there is nothing to upload.
`gh attestation download <crate file> --repo zama-ai/tfhe-rs` fetches it.

To check a crate downloaded from crates.io:

```sh
curl -LO https://static.crates.io/crates/tfhe/tfhe-<version>.crate
gh attestation verify tfhe-<version>.crate --repo zama-ai/tfhe-rs \
  --signer-workflow zama-ai/tfhe-rs/.github/workflows/make_release_attest.yml
```

The attestation is not made by the job uploading the crates. A crate file only depends on the
commit and on the version of cargo packaging it, so `attest-crates` packages the crates again on a
GitHub-hosted runner and only attests them if they are, byte for byte, the files crates.io serves.
It does so in a reusable workflow, which is what GitHub documents to go from SLSA v1.0 Build Level 2
to Build Level 3. A dry-run checks the same thing against the checksums of the files
`verify-crates` packaged.

JS packages get their provenance from npmjs.com itself, which generates it for packages published
with trusted publishing.

## The release tooling and its tests

The workflow and the `release_*` targets of the Makefile run `cargo xtask release` and
`cargo xtask release-status`, which live in the `tasks` crate. They read the registry through its
index with `curl`.

```sh
make test_release_tooling
```

runs them through releases of test crates to a local registry, real uploads included: a release
of some crates only, a missing dependency, a release failing half way and resumed, a tag on another
commit, a crate that does not match the registry. `SLOW=1` adds an index too slow for cargo, which
takes a few minutes. `OFFLINE=1` leaves out the one test that needs crates.io.

Nothing can end up on crates.io:

- the crates are test crates generated by each test, `release-test-*`, that cargo is only allowed
  to publish to the test registry;
- the registry runs on a local port and replaces crates.io in the configuration of a throwaway
  `CARGO_HOME`. In one test it mirrors crates.io, read-only, for a dependency of the test crates;
- the registry tokens of the environment are not passed to cargo.

The tests are in `tasks/tests/release.rs`. They work in `target/tmp/release`, which is left in
place to be looked at, and `cargo test -p tasks --test release -- --nocapture` shows what each run
of the tooling printed.
