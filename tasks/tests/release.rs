//! The release tooling run against a local registry, on a workspace of test crates: what the
//! release workflow asks of `cargo xtask release`, real uploads included.
//!
//! See the support module for what the test crates are and why none of this can reach crates.io.
//! Run with `make test_release_tooling`.

mod support;

use std::fs;
use std::time::Duration;

use support::mirror::ALWAYS;
use support::{
    CUDA_BACKEND, CUDA_COMMON, DERIVE, INTERNAL, MAIN, Options, RELEASED, VERSIONABLE, WITH_TOKEN,
    World, crates,
};

/// Every test crate is new to the registry, which a release refuses unless told otherwise.
const NEW: &str = "--allow-new-crates";

fn sorted<T: Ord>(mut items: Vec<T>) -> Vec<T> {
    items.sort();
    items
}

#[test]
fn a_rehearsal_selects_every_unpublished_crate_and_uploads_nothing() {
    let mut world = World::new("rehearsal");

    let order = World::listed(&world.plan(&["--rehearsal", NEW]), "publish");
    assert_eq!(sorted(order.clone()), sorted(RELEASED.to_vec()));
    let position = |name: &str| order.iter().position(|listed| listed == name).unwrap();
    for (user, dependency) in [
        (VERSIONABLE, DERIVE),
        (CUDA_BACKEND, CUDA_COMMON),
        (MAIN, VERSIONABLE),
        (MAIN, CUDA_BACKEND),
    ] {
        assert!(
            position(dependency) < position(user),
            "{user} comes before {dependency}"
        );
    }

    let dry_run = world.release(&["--rehearsal", NEW, "publish", "--dry-run"]);
    assert!(dry_run.success().contains("Verifying release-test-main"));
    let upload = world.release_with(WITH_TOKEN, &["--rehearsal", NEW, "publish"]);
    assert!(upload.refused().contains("can only be a dry run"));
    assert!(world.uploads().is_empty(), "a rehearsal uploaded crates");
}

#[test]
fn a_build_script_sees_the_registry_token_of_a_run_that_verifies_crates() {
    let mut world = World::new("token");

    let verify = ["--rehearsal", NEW, "publish", "--dry-run"];
    let output = world.release_with(WITH_TOKEN, &verify).failure();
    assert!(output.contains("the registry token is visible to a build script"));
    assert!(world.uploads().is_empty());
}

#[test]
fn nothing_is_published_without_a_release_tag_on_the_commit() {
    let mut world = World::new("untagged");

    assert!(World::listed(&world.plan(&[NEW]), "publish").is_empty());
    let upload = world.release_with(WITH_TOKEN, &[NEW, "publish", "--no-verify"]);
    assert!(
        upload
            .success()
            .contains("no release tag points at this commit")
    );
    assert!(world.uploads().is_empty(), "untagged crates were uploaded");
}

#[test]
fn the_first_version_of_a_crate_is_not_left_to_trusted_publishing() {
    let mut world = World::new("new-crate");

    let tag = world.tag(DERIVE);
    let plan = world.release(&["--tag", &tag, "plan"]);
    assert!(plan.refused().contains("would be the first version"));
    let upload = world.release_with(WITH_TOKEN, &["--tag", &tag, "publish", "--no-verify"]);
    upload.refused();
    assert!(world.uploads().is_empty(), "a new crate was uploaded");
}

#[test]
fn a_release_publishes_the_crates_tagged_on_the_commit_and_only_those() {
    let mut world = World::new("tagged");

    world.tag(DERIVE);
    let tag = world.tag(VERSIONABLE);
    let plan = world.plan(&["--tag", &tag, NEW]);
    assert_eq!(World::listed(&plan, "publish"), [DERIVE, VERSIONABLE]);

    // Verifying takes no token and uploads nothing.
    let verify = world.release(&["--tag", &tag, NEW, "publish", "--dry-run"]);
    verify.success();
    assert!(world.uploads().is_empty(), "verifying uploaded crates");
    // Uploading takes one.
    let upload = ["--tag", &tag, NEW, "publish", "--no-verify"];
    world.release(&upload).failure();
    assert!(
        world.uploads().is_empty(),
        "crates were uploaded without a token"
    );
    world.release_with(WITH_TOKEN, &upload).success();
    let published = [(DERIVE, "0.1.0"), (VERSIONABLE, "0.1.0")];
    assert_eq!(world.uploads(), crates(&published));
    world.check_checksums(&world.repo, &published);

    // Another checkout packages the very files the registry holds.
    let checkout = world.fresh_checkout();
    let reproduce = world.release_in(&checkout, &["--tag", &tag, "reproduce"]);
    assert!(reproduce.success().contains("are the ones of test-mirror"));
    world.check_checksums(&checkout, &published);
}

#[test]
fn a_crate_is_not_released_without_the_crates_it_depends_on() {
    let mut world = World::new("dependencies");

    world.tag(DERIVE);
    world.tag(VERSIONABLE);
    let tag = world.tag(MAIN);
    let plan = world.release(&["--tag", &tag, NEW, "plan"]).refused();
    let missing = format!("depends on {CUDA_BACKEND} 0.1.0, which is neither on test-mirror");
    assert!(
        plan.contains(&missing),
        "the missing dependency went unnoticed"
    );
    let upload = ["--tag", &tag, NEW, "publish", "--no-verify"];
    world.release_with(WITH_TOKEN, &upload).refused();
    assert!(
        world.uploads().is_empty(),
        "an incomplete release uploaded crates"
    );
}

#[test]
fn a_release_that_failed_half_way_is_resumed_by_running_it_again() {
    let mut world = World::new("resumed");

    // A first release, of two crates.
    world.tag(DERIVE);
    let first_tag = world.tag(VERSIONABLE);
    let first = ["--tag", &first_tag, NEW, "publish", "--no-verify"];
    world.release_with(WITH_TOKEN, &first).success();
    let earlier = [(DERIVE, "0.1.0"), (VERSIONABLE, "0.1.0")];
    assert_eq!(world.uploads(), crates(&earlier));

    // A second one from the same commit, which the registry stops after one crate.
    world.tag(CUDA_COMMON);
    world.tag(CUDA_BACKEND);
    let tag = world.tag(MAIN);
    let upload = ["--tag", &tag, NEW, "publish", "--no-verify"];
    world.mirror.reject(CUDA_BACKEND, ALWAYS);
    world.release_with(WITH_TOKEN, &upload).failure();
    assert_eq!(world.uploads(), crates(&[(CUDA_COMMON, "0.1.0")]));

    world.mirror.accept_everything();
    let left = world.plan(&["--tag", &tag, NEW]);
    assert_eq!(World::listed(&left, "publish"), [CUDA_BACKEND, MAIN]);
    let released = World::listed(&left, "released");
    assert!(released.contains(&MAIN.to_owned()) && !released.contains(&INTERNAL.to_owned()));
    world.release_with(WITH_TOKEN, &upload).success();
    let resumed = [(CUDA_BACKEND, "0.1.0"), (MAIN, "1.0.0")];
    assert_eq!(world.uploads(), crates(&resumed));
    world.check_checksums(&world.repo, &resumed);

    let done = world.plan(&["--tag", &tag]);
    assert!(
        World::listed(&done, "publish").is_empty(),
        "published crates are selected again"
    );
    assert_eq!(
        sorted(World::listed(&done, "released")),
        sorted(RELEASED.to_vec())
    );
    assert!(world.mirror.published(INTERNAL).is_empty());

    // Everything released from the commit is reproduced, whichever run published it.
    let checkout = world.fresh_checkout();
    world
        .release_in(&checkout, &["--tag", &tag, "reproduce"])
        .success();
    let everything = [
        earlier[0],
        earlier[1],
        (CUDA_COMMON, "0.1.0"),
        resumed[0],
        resumed[1],
    ];
    world.check_checksums(&checkout, &everything);
}

#[test]
fn a_registry_holding_another_file_than_the_one_packaged_fails_the_release() {
    let mut world = World::new("corrupted");

    world.tag(DERIVE);
    let tag = world.tag(VERSIONABLE);
    world.mirror.corrupt(VERSIONABLE);
    let upload = ["--tag", &tag, NEW, "publish", "--no-verify"];
    let output = world.release_with(WITH_TOKEN, &upload).refused();
    let other = format!("test-mirror holds another {VERSIONABLE} 0.1.0 than the one packaged");
    assert!(
        output.contains(&other),
        "the registry holds a file that was not packaged here"
    );
    assert!(output.contains(&format!("{DERIVE} 0.1.0 is on test-mirror")));
    assert_eq!(world.uploads().len(), 2);
}

#[test]
fn a_crate_that_is_not_the_one_in_the_registry_does_not_reproduce() {
    let mut world = World::new("tampered");
    world.release_everything();

    let index = world.mirror.index_file(VERSIONABLE);
    let mut entry: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&index).unwrap()).unwrap();
    entry["cksum"] = "0".repeat(64).into();
    fs::write(&index, format!("{entry}\n")).unwrap();

    let checkout = world.fresh_checkout();
    let reproduce = world.release_in(&checkout, &["--tag", &world.tag_of(MAIN), "reproduce"]);
    let output = reproduce.refused();
    let tampered = format!("{VERSIONABLE}-0.1.0.crate does not reproduce");
    assert!(
        output.contains(&tampered),
        "a crate that is not the published one passed"
    );
    assert_eq!(output.matches("does not reproduce").count(), 1);
}

#[test]
fn a_patch_release_of_one_crate_publishes_that_crate_alone() {
    let mut world = World::new("patch");
    world.release_everything();

    world.bump(&[(VERSIONABLE, "0.1.1")], &[]);
    let tag = world.tag(VERSIONABLE);
    world
        .release(&["--tag", &tag, "publish", "--dry-run"])
        .success();

    // What a dry-run of the workflow checks: another machine packages the files that were
    // verified.
    let verified = world.repo.join("target/release-crates/SHA256SUMS");
    let checkout = world.fresh_checkout();
    let against = [
        "--tag",
        &tag,
        "reproduce",
        "--against",
        verified.to_str().unwrap(),
    ];
    assert!(
        world
            .release_in(&checkout, &against)
            .success()
            .contains("are the ones of")
    );
    let checksums = fs::read_to_string(&verified).unwrap();
    let other = world.repo.join("target/other-SHA256SUMS");
    fs::write(&other, format!("{}{}", "0".repeat(64), &checksums[64..])).unwrap();
    let against = [
        "--tag",
        &tag,
        "reproduce",
        "--against",
        other.to_str().unwrap(),
    ];
    assert!(
        world
            .release_in(&checkout, &against)
            .refused()
            .contains("does not reproduce")
    );

    let upload = world.release_with(WITH_TOKEN, &["--tag", &tag, "publish", "--no-verify"]);
    upload.success();
    assert_eq!(world.uploads(), crates(&[(VERSIONABLE, "0.1.1")]));
}

#[test]
fn a_dependency_tagged_on_another_commit_is_released_from_that_commit() {
    let mut world = World::new("elsewhere");
    world.release_everything();

    let versions = [
        (CUDA_COMMON, "0.2.0"),
        (CUDA_BACKEND, "0.2.0"),
        (MAIN, "1.1.0"),
    ];
    let earlier = world.bump(&versions, &[CUDA_COMMON, CUDA_BACKEND]);
    let common_tag = world.tag(CUDA_COMMON);
    world.change_main_crate();
    world.commit("late fix");
    world.tag(CUDA_BACKEND);
    let tag = world.tag(MAIN);

    let plan = world.release(&["--tag", &tag, "plan"]).refused();
    assert!(
        plan.contains("tagged on another commit"),
        "a stray tag went unnoticed"
    );
    let plan = world.release(&["--tag", &common_tag, "plan"]).refused();
    assert!(
        plan.contains("is checked out"),
        "a tag of another commit was accepted"
    );
    let plan = world
        .release(&["--tag", &format!("{MAIN}-1.0.0"), "plan"])
        .refused();
    assert!(
        plan.contains("is not the release tag"),
        "the tag of an old version was accepted"
    );

    world.git(&["checkout", "--quiet", &earlier]);
    let upload = ["--tag", &common_tag, "publish", "--no-verify"];
    world.release_with(WITH_TOKEN, &upload).success();
    assert_eq!(world.uploads(), crates(&[(CUDA_COMMON, "0.2.0")]));

    world.git(&["checkout", "--quiet", "main"]);
    let upload = ["--tag", &tag, "publish", "--no-verify"];
    world.release_with(WITH_TOKEN, &upload).success();
    assert_eq!(
        world.uploads(),
        crates(&[(CUDA_BACKEND, "0.2.0"), (MAIN, "1.1.0")])
    );
}

#[test]
fn cargo_is_run_again_for_the_crates_an_upload_left_behind() {
    let mut world = World::new("left-behind");
    world.release_everything();

    world.bump(&[(CUDA_BACKEND, "0.1.1"), (MAIN, "1.0.1")], &[]);
    world.tag(CUDA_BACKEND);
    let tag = world.tag(MAIN);
    // The registry fails once, and cargo colors what is read to tell what it uploaded.
    world.mirror.reject(MAIN, 1);
    let colored = Options {
        token: true,
        color: true,
    };
    let upload = world.release_with(colored, &["--tag", &tag, "publish", "--no-verify"]);
    let resumed = format!("resuming with {MAIN}");
    assert!(
        upload.success().contains(&resumed),
        "the upload was not resumed"
    );
    let published = [(CUDA_BACKEND, "0.1.1"), (MAIN, "1.0.1")];
    assert_eq!(world.uploads(), crates(&published));
    world.check_checksums(&world.repo, &published);
}

#[test]
fn the_status_report_reads_the_registry_of_the_release() {
    let mut world = World::new("status");

    assert!(
        world
            .status(&[])
            .success()
            .contains("Bumped but not tagged")
    );
    world.release_everything();
    assert!(
        world
            .status(&[])
            .success()
            .contains("up to date on test-mirror")
    );

    world.change_main_crate();
    world.commit("fix");
    let report = world.status(&["--files"]).success();
    assert!(report.contains("Changed without a version bump"));
    assert!(report.contains(&format!("{MAIN}/src/lib.rs")));
    // What the gate of a pull request refuses.
    world.status(&["--pr-gate", "HEAD^"]).refused();
    world.bump(&[(MAIN, "1.0.1")], &[]);
    world.status(&["--pr-gate", "HEAD^^"]).success();
}

/// Needs network access: the registry asks crates.io, see OFFLINE in the Makefile.
#[test]
fn the_registry_mirrors_crates_io_for_the_dependencies_of_the_crates() {
    let mut world = World::with_a_dependency_on_crates_io("mirrored");

    // The main crate is built with cfg-if, which cargo can only get from the test registry.
    let verify = world.release(&["--rehearsal", NEW, "publish", "--dry-run"]);
    assert!(verify.success().contains("cfg-if"));
    assert!(
        world.mirror.mirrored("cfg-if"),
        "cfg-if did not come through the registry"
    );
    world.release_everything();
    assert_eq!(world.version(MAIN), "1.0.0");
    assert!(world.mirror.published(MAIN).contains_key("1.0.0"));
}

#[test]
#[ignore = "takes a few minutes: cargo waits a minute for the index, three times"]
fn an_index_more_than_a_minute_late_does_not_fail_the_release() {
    let mut world = World::new("slow-index");
    world.release_everything();

    let versions = [
        (CUDA_COMMON, "0.2.0"),
        (CUDA_BACKEND, "0.2.0"),
        (MAIN, "1.1.0"),
    ];
    world.bump(&versions, &[CUDA_COMMON, CUDA_BACKEND]);
    world.tag(CUDA_COMMON);
    world.tag(CUDA_BACKEND);
    let tag = world.tag(MAIN);
    world.mirror.delay_index(Duration::from_secs(70));
    let upload = world.release_with(WITH_TOKEN, &["--tag", &tag, "publish", "--no-verify"]);
    let output = upload.success();
    assert!(
        output.contains("timed out waiting"),
        "cargo did not give up on the index"
    );
    assert_eq!(world.uploads().len(), 3, "the release was not completed");
}
