# Contributing to tfhe-rs

There are two ways to contribute to tfhe-rs:

- You can open issues to report bugs, typos and suggest ideas.
- You can become an official contributor, but you need to sign our Contributor License Agreement (CLA) on your first contribution. Our CLA-bot will guide you through the process when you will open a Pull Request on GitHub.

## 1. Setting up the project

First, you need to [fork](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/fork-a-repo) the tfhe-rs repository and follow the installation steps described in the repository [README.md](https://github.com/zama-ai/tfhe-rs/blob/main/README.md)

## 2. Creating a new branch

When creating your branch, make sure to use the following format :

```
git checkout -b {feat|fix|docs|chore…}/short_description
```

For example:

```
git checkout -b feat/new_feature_X
```

## 3. Before committing

### 3.1 Linting

Each commit to tfhe-rs should conform to the standards of the project. In particular, every source code, docker or workflows files should be linted to prevent programmatic and stylistic errors.

- Rust source code linters: `clippy`
- typescript/javascript source code linters: `eslint`, `prettier`

To apply automatic code formating run:

```
make fmt
```

Linting of all Cargo targets can be done with:

```
make clippy_all_targets
```

### 3.2 Testing

Your code must be well documented, provide extensive tests if any feature has been added and must not break other tests.

To execute pre-commit checks, please run the following command:

```
make pcc
```

This command ensure that all the targets in the library are building correctly.
Alternatively, you might want to run a faster version of this command using:
 
```
make fpcc
```
If you're contributing to GPU code, you would want to run also:

```
make pcc_gpu
```

Unit testing suites are heavy and can require a lot of computing power and RAM availability.
Whilst tests are run automatically in continuous integration pipeline, you can run test locally.

All unit tests have a command formatted as:

```
make test_*
```

Run `make help` to display a list of all the commands available.

To quickly test your changes locally:
 * locate where the code has changed
 * add (or modify) a Cargo test filter to the corresponding `make` target in Makefile
 * run the target

For example, if you made changes in `tfhe/src/integer/*`:
 * replace, in `test_integer` target, the filter `-- integer::` by `-- my_new_test`
 * run `make test_integer`

## 4. Committing

Tfhe-rs follows conventional commit specification to have a consistent commit naming scheme and you are expected to follow it as well.

This is a mandatory requirement for Semantic Versioning ([https://semver.org/](https://semver.org/)) used in tfhe-rs release process to define the version number and create automatically meaningful changelog.

Just a reminder that commit messages are checked automatically in the CI and are rejected if they don't follow the rules. To learn more about conventional commits, check [this page](https://www.conventionalcommits.org/en/v1.0.0/).

## 5. Rebasing

You should rebase on top of the repository's `main` branch before you create your pull request. Merge commits are not allowed, so rebasing on `main` before pushing gives you the best chance of to avoid rewriting parts of your PR later if conflicts arise with other PRs being merged.

## 6. Open a pull-request

You can now open a pull-request. For more details on how to do so from a forked repository, please read GitHub's [official documentation](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request-from-a-fork) on the subject.

## 7. Continuous Integration

Several tests suites are executed automatically before being able to merge a pull-request.
The process follows this steps:

**Faire un diagramme mermaid !!!!!!!!!**

1. contributor open a pull-request
2. contributor sign Contributor License Agreement (done only once)
3. reviewer approve and launch the continuous integration pipeline
4. reviewer do a proper review
5. contributor push modifications then get back to step 3.
6. reviewer approve final code changes
7. reviewer approve and launch approval pipeline
8. reviewer merge commit


>Useful details
>* pipeline is triggered by humans
>* review team is located in Paris timezone, pipeline launch will most likely happen during office hours
>* direct changes to CI related files are not allowed for external contributors
>* run `make pcc` to fix any build errors before pushing commits
