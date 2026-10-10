#!/usr/bin/env bash
# Run on master after a merge: bumps the patch version, commits and tags it,
# and pushes both. If the merge changed the version itself (a minor or major
# bump made by hand), that version has no tag yet and is only tagged.
set -euo pipefail

current=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)

if ! git rev-parse -q --verify "refs/tags/v$current" >/dev/null; then
    echo "v$current is not tagged yet, tagging HEAD"
    git tag "v$current"
    git push origin "refs/tags/v$current"
    exit 0
fi
if [ "$(git rev-parse "v$current^{commit}")" = "$(git rev-parse HEAD)" ]; then
    echo "HEAD is already v$current, nothing to do"
    exit 0
fi

IFS=. read -r major minor patch <<<"$current"
export NEW="$major.$minor.$((patch + 1))"
perl -0pi -e 's/^version = "[^"]+"/version = "$ENV{NEW}"/m' Cargo.toml
perl -0pi -e 's/(name = "hush"\nversion = ")[^"]+/$1$ENV{NEW}/' Cargo.lock

git commit -q -m "Bump version to $NEW" Cargo.toml Cargo.lock
git tag "v$NEW"
git push --atomic origin HEAD:master "refs/tags/v$NEW"
echo "bumped $current -> $NEW"
