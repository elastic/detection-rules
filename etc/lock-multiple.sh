#!/bin/bash
set -x
set -e

CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)

# switch to
for BRANCH in $(echo $@ | sed "s/,/ /g")
do
    echo $BRANCH
    git checkout $BRANCH
    git pull
    python -m detection_rules dev build-release --update-version-lock
done

git checkout ${CURRENT_BRANCH}
