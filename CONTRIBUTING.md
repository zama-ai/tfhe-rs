# Contributing to tfhe-rs

This repository uses an **issue-first contribution workflow**.

Pull Requests are disabled on the main repository. All contributions begin with a discussion in an issue so maintainers and contributors can align early on scope, design, compatibility, and maintenance implications before implementation work starts.

## How to Contribute

If you would like to report a bug, propose a feature, or discuss a change, open an issue in the main repository. Please describe the problem clearly and, when possible, include context, motivation, or a proposed direction.

Once the discussion reaches consensus, contributors may implement the change in a personal fork of the repository.

```
git checkout -b ext/feature/my-change
```

After pushing the branch to your fork, create a PR against your forked `main`  branch and share the reference directly in the issue thread instead of opening a Pull Request against the upstream repository.

Example:

```
https://github.com/<your-user>/<repo>/pull/<PR-number>
```

An official maintainer or contributor will review the proposed implementation, request changes if necessary, and integrate the contribution into the main repository.

## Why Pull Requests Are Disabled

This workflow ensures that technical discussions happen before implementation and helps maintain consistency across the project. It also reduces review overhead and avoids contributors spending time on changes that may not align with the roadmap or architecture. Last and not least, it prevents security issues coming from external contributor PR.

## Guidelines

Contributions are easier to review and integrate when they are focused, documented, and discussed early. Small, self-contained changes are generally preferred over large multi-purpose modifications.

For security vulnerabilities, please follow the process described in `SECURITY.md` instead of opening a public issue.

By contributing to this repository, you agree that your contributions will be licensed under the project license.

The contribution guidelines are described in `CONTRIBUTION_GUIDELINES.md`.
