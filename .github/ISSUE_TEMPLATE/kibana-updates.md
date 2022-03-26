---
name: Kibana updates
about: Template used by Elastic team to push rule updates to Kibana
title: "[Kibana Updates] <source-branch> to kibana:<target-banch>"
labels: kibana-updates
assignees: ''

---

# Kibana updates

- [ ] check if this the final push to the respective Kibana release branch


### Which Kibana branches will this backport to?
<!-- bullet per branch, if none, add 'none' as a bullet. Also link to each backport PR  -->
* 

## Checklist
<!-- each root level checklist item should have accompanying pr link -->

- [ ] lock versions
- [ ] PR rules updates to Kibana


## Additional if this is the final push targeting a respective Kibana release branch
- [ ] create a tag for the branch from the locked versions commit (ex: `v7.15.0`)
- [ ] update security-docs with rule changes
