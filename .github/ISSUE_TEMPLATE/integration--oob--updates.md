---
name: Integration (OOB) updates
about: Release updates to fleet integration package
title: "[Integration Release] <x.x.x>"
labels: fleet-release
assignees: ''

---

# OOB Fleet integration release

### Release branch
<!-- this will dictate which stacks get the updates (>= up to major)
        the title should reflect this version; ex: releasing from 8.0 is 1.0.x
        the patch version represents the iteration of the release, so the 3rd release for 8.0 is 1.0.3
 -->
* 


## Checklist
<!-- each root level checklist item should have accompanying pr link -->

<!-- always push from latest (main) and merge, before proceeding
        link the completed "kibana updates" issue here
 -->

### Prep
- [ ] complete `updates to kibana` <issue link>
- [ ] tag the locked commit (ex `integration-vx.x.x`) <tag link>

### Release package
- [ ] integrations PR <link>
- [ ] package-storage promotion to `production` PR <link>
- [ ] `Pipeline Release Package Distribution` job <job link>
- [ ] production `epr` <link>

### Updates
- [ ] security-docs PR <link>
- [ ] newsfeed PR <link>
