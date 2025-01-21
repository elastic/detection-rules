# Rule Supported Versions and Releases

This document provides detailed information about the different versions that are supported and released for prebuilt detection rules.

## Current Version

The current version of prebuilt detection rules is `v8.17`.

## Previous Versions Released

The following version(s) are released along with the current version.

- `v8.16`
- `v8.15`
- `v8.14`

### Previous Versions Maintained

The following version(s) are maintained along with the current version.

- `v8.13`
- `v8.12`

## End of Life Policy

Our policy is to support and provide public releases for `Current`, `Current-1`, `Current-2`, `Current-3` versions. We maintain and do not release `Current-4` and `Current-5` versions.


# Code Supported Versions and Releases

This outlines the versioning strategy and release process for the [detection-rules](https://github.com/elastic/detection-rules) repository, covering the core code, `kql` and `kibana` libraries, configuration files, and the `hunting` folder. The strategy follows semantic versioning to ensure clear communication of changes to users and compatibility with different Elastic Stack versions.

> [!IMPORTANT]
> This versioning process **excludes** the detection rules themselves. Detection rules are released separately and are not tied to the following process.

---

## Versioning Strategy

### Components Covered by Versioning:
- **Core Detection-Rules Code**: Handles logic for rule management, CLI, etc.
- **Libraries**:
  - **`kql`**: Manages Kibana Query Language parsing and operations.
  - **`kibana`**: Handles integrations and API interactions with Kibana.
- **Configuration Files**: Under the `etc/` folder that impact schema and DAC.
- **Hunting Logic**: The `hunting/` folder, which manages hunting rules.


### Semantic Versioning Approach:
We will use **Semantic Versioning** with the format `MAJOR.MINOR.PATCH`:
- **MAJOR version (`X.0.0`)**: For backward-incompatible changes.
- **MINOR version (`0.Y.0`)**: For backward-compatible new features.
- **PATCH version (`0.0.Z`)**: For backward-compatible bug fixes or small improvements.

> [!NOTE]
> The GitHub labels `patch`, `minor`, or `major` will be used in PRs to indicate the type of change being made.

---

## Versioning Guidelines

### Patch Version (`0.0.Z`):
Increment the patch version when making bug fixes, performance improvements, or small enhancements that do not break backward compatibility. Open a PR to ensure the proper `pyproject.toml` files and any other `version` related files are bumped.

<details><summary>Expand for Examples</summary>
<p>

**Examples**:
- **Kibana Library**:
  - Minor fixes to API calls to ensure correct data retrieval.
  - Updates to the `kibana` lib without adding new features.
- **KQL Library**:
  - Small bug fixes in the query parsing logic.
  - Optimizations that don't alter functionality.
- **Core Detection-Rules Code**:
  - Fixes for CLI bugs or performance tweaks.
  - Minor enhancements to rule management that don’t require users to change workflows.
- **Hunting Folder**:
  - Bug fixes in hunting rules logic.
  - Small performance tweaks for the hunting rule management.
- **Docs Folder**:
  - Updates to documentation.
- **JSON Schemas**:
  - Recurring update to schema definitions that don't break compatibility (not .py schema updates).

</p>
</details>

---

### Minor Version (`0.Y.0`):
Increment the minor version when adding backward-compatible new features, enhancements, or functionality.

<details><summary>Expand for Examples</summary>
<p>

**Examples**:
- **Kibana Library**:
  - Adding a new API endpoint to interact with Elastic Kibana X.Y while maintaining backward compatibility with older versions.
- **KQL Library**:
  - Adding new query parsing functionality that is backward-compatible with previous Elastic Stack versions.
- **Core Detection-Rules Code**:
  - New CLI commands or functionality for managing detection rules.
  - New optional fields in rule schemas that have minimum compatibility requirements. (e.g adding `alert_suppression` with `min_compat=8.14`).
- **Hunting Folder**:
  - Adding new hunting rule management features that are optional and backward-compatible.
  - Enhancements in generating hunting rule markdown or CLI features.

</p>
</details>

> [!NOTE]
> When bumping this version, the patch version should be reset to `0` and the major version should remain the same.

---

### Major Version (`X.0.0`):
Increment the major version when introducing backward-incompatible changes that require users to update workflows, Elastic Stack versions, or rule management strategies.

<details><summary>Expand for Examples</summary>
<p>

**Examples**:
- **Kibana Library**:
  - Replacing or removing an existing API endpoint that forces users to upgrade to Elastic X.Y
- **KQL Library**:
  - Structural changes to query parsing logic that break compatibility with previous Elastic Stack versions.
- **Core Detection-Rules Code**:
  - Breaking changes to rule schema definitions or CLI workflows that require user updates.
  - Forcing users to migrate to a newer Elastic Stack version due to changes in core code or schema compatibility.
- **Hunting Folder**:
  - Major refactors of the hunting logic that break existing workflows.
  - Changes to how hunting rules are defined or managed, requiring users to adjust configurations.

</p>
</details>

> [!NOTE]
> When bumping this version, the minor version and patch version should be reset to `0`.

---

## Tagging Process

Each pyproject.toml update will be tagged using the following format:
- **Tag Format**: `dev-vX.Y.Z` (e.g., `dev-v1.2.0`).
- **Single Tag for Combined Releases**: If there are changes to the core detection-rules code or libraries (`kql`, `kibana`), they will be tagged together as a single release with the core detection-rules versioning.
- **Hunting Folder**: Changes to the hunting logic will be included in the combined release.

> [!CAUTION]
> When a version is bumped in a lib, we need to also bump the core `pyproject.toml` file *(e.g A version bump in `kql` will also require a similar version bump in the core detection-rules versioning)*.
---

## When to Trigger a GitHub Release

A draft release will be triggered on all version updates. For example, in the following cases:
- **New Feature or Bug Fix**: Once a feature or bug fix is merged into `main`, a version bump is made according to the semantic versioning rules.
- **Version Bump**: After the version bump, a GitHub release will be created using **release-drafter** CI workflow to automate draft release generation.

As pull requests are merged, a draft release is kept up-to-date listing the changes, ready to publish quarterly.

> [!IMPORTANT]
> Releases are published on minor and major version bumps at a minimum. Prior to publishing, the release notes should be reviewed and updated with any additional information, or remove any unnecessary details not related to code changes (which may occur due to release-drafter pulling in all commits).
