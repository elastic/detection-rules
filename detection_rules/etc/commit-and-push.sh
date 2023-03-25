#!/bin/bash
set -x
set -e

echo "Switch to the target branch and keep the staged changes"
TARGET_BRANCH=$1
COMMIT_SHA=$2
echo "Backporting from commit ${COMMIT_SHA} on branch ${TARGET_BRANCH}"

echo "Checking out target branch"
git checkout ${TARGET_BRANCH}

NEEDS_BACKPORT=$(git diff HEAD --quiet --exit-code && echo n || echo y)

if [ "n" = "$NEEDS_BACKPORT" ]
then
echo "No changes to backport"
exit 0
fi

echo "Create the new commit with the same author"
git commit --reuse-message ${COMMIT_SHA}

echo "Save the commit message"
git log ${COMMIT_SHA} --format=%B -n1 > $COMMIT_MSG_FILE

echo "Append to the commit message"
if [ -s "$UNSTAGED_LIST_FILE" ]
then
echo "Track note for the removed files"

echo "" >> $COMMIT_MSG_FILE
echo "Removed changes from:" >> $COMMIT_MSG_FILE
awk '{print "- " $0}' $UNSTAGED_LIST_FILE >> $COMMIT_MSG_FILE
echo "" >> $COMMIT_MSG_FILE
echo '(selectively cherry picked from commit ${COMMIT_SHA})' >> $COMMIT_MSG_FILE
else
echo "No removed files"

echo "" >> $COMMIT_MSG_FILE
echo '(cherry picked from commit ${COMMIT_SHA})' >> $COMMIT_MSG_FILE
fi

echo "Amend the commit message and push"
git commit --amend -F $COMMIT_MSG_FILE
git push
