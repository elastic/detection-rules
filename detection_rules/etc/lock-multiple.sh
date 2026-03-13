#!/bin/bash
set -x
set -e

CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)

BRANCHES=($(echo "$@" | sed "s/,/ /g" | tr ' ' '\n' | sort -V))
LAST_INDEX=$((${#BRANCHES[@]} - 1))

for i in "${!BRANCHES[@]}"
do
    BRANCH=${BRANCHES[$i]}
    echo $BRANCH
    git checkout $BRANCH
    git pull
    python -m detection_rules dev build-release --update-version-lock

    # Reset deprecated_rules.json after all branches except the last to prevent
    # branch-specific deprecations from leaking across checkouts (e.g. D4C rules
    # deprecated on 8.19 but active on 9.3+). The last branch is closest to main
    # and carries the correct deprecation state forward.
    if [ $i -lt $LAST_INDEX ]; then
        git checkout -- detection_rules/etc/deprecated_rules.json
    fi
done

git checkout ${CURRENT_BRANCH}
