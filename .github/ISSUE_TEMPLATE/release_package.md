---
name: Release package
about: Meta Issue for a package release
title: "[Release] package name or stack version"
labels: release-package
assignees: ''

---


## Required Info
**Stack Version:**
`{majorVersion.minorVersion}`


### Creation
Complete these items when creating this issue

- [ ] Create a label for the rules package version as `X.X` and apply it
- [ ] Create [new milestone](https://github.com/elastic/detection-rules/milestones/new) with version as title
- [ ] Add this to the [detection-rules package tracking](https://github.com/orgs/elastic/projects/342)
- [ ] Add any existing issues and PRs that should be completed by this release
- [ ] Bump and lock versions (`build-packages --update-versions-file`) _before_ all BC testing and final merges to Kibana
- [ ] Pull Request to [Kibana](https://github.com/elastic/kibana)


#### Testing and Validation
- [ ] Create feature branch as `{majorVersion}.{minorVersion}`
- [ ] Tested and verified as custom or prepackaged rules
- [ ] Validate end-to-end
- [ ] Grammar checks
- [ ] UI checks for new rules


#### Post Release
- [ ] Tag and release as github artifact
- [ ] Merge feature branch into `main`. Don't squash commits, use rebase or merge with commits
