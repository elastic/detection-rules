#!/bin/bash
set -x
set -e

CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)

# switch to
for branch in $(echo $@ | sed "s/,/ /g")
do
    git checkout $branch
    git pull
    python -m detection_rules dev build-release --update-version-lock
    echo $branch
done

git checkout $(CURRENT_BRANCH)