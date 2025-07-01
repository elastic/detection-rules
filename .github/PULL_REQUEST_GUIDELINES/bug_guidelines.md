## Bug - Guidelines

These guidelines serve as a reminder set of considerations when addressing a bug in the code.

### Documentation and Context

- [ ] Provide detailed documentation (description, screenshots, reproducing the bug, etc.) of the bug if not already documented in an issue.
- [ ] Include additional context or details about the problem.
- [ ] Ensure the fix includes necessary updates to the release documentation and versioning.

### Code Standards and Practices

- [ ] Code follows established design patterns within the repo and avoids duplication.
- [ ] Ensure that the code is modular and reusable where applicable.

### Testing

- [ ] New unit tests have been added to cover the bug fix or edge cases.
- [ ] Existing unit tests have been updated to reflect the changes.
- [ ] Provide evidence of testing and detecting the bug fix (e.g., test logs, screenshots).
- [ ] Validate that any rules affected by the bug are correctly updated.
- [ ] Ensure that performance is not negatively impacted by the changes.
- [ ] Verify that any release artifacts are properly generated and tested.
- [ ] Conducted system testing, including fleet, import, and create APIs (e.g., run `make test-cli`, `make test-remote-cli`, `make test-hunting-cli`)

### Additional Checks

- [ ] Verify that the bug fix works across all relevant environments (e.g., different OS versions).
- [ ] Confirm that the proper version label is applied to the PR `patch`, `minor`, `major`.
