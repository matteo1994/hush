#!/usr/bin/env bash
# Run on master after a merge: releases it. Bumps the patch version, adds the
# merged commits to CHANGELOG.md, commits and tags that, and pushes both. If
# the merge changed the version itself (a minor or major bump made by hand),
# that version has no tag yet and is released as it is.
set -euo pipefail

current=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)

if ! git rev-parse -q --verify "refs/tags/v$current" >/dev/null; then
    export NEW="$current"
elif [ "$(git rev-parse "v$current^{commit}")" = "$(git rev-parse HEAD)" ]; then
    echo "HEAD is already v$current, nothing to do"
    exit 0
else
    IFS=. read -r major minor patch <<<"$current"
    export NEW="$major.$minor.$((patch + 1))"
    perl -0pi -e 's/^version = "[^"]+"/version = "$ENV{NEW}"/m' Cargo.toml
    perl -0pi -e 's/(name = "hush"\nversion = ")[^"]+/$1$ENV{NEW}/' Cargo.lock
fi

# Everything since the previous release, oldest first, above the older entries.
previous=$(git describe --tags --abbrev=0 --match 'v*')
ENTRY=$(printf '## %s (%s)\n\n%s\n\n' "$NEW" "$(date -u +%F)" \
    "$(git log --reverse --format='- %s' "$previous..HEAD")"; echo x)
export ENTRY="${ENTRY%x}"
perl -0pi -e 's/^(?=## )/$ENV{ENTRY}/m or die "no release heading in CHANGELOG.md\n"' CHANGELOG.md

git commit -q -m "Release $NEW" Cargo.toml Cargo.lock CHANGELOG.md
git tag "v$NEW"
git push --atomic origin HEAD:master "refs/tags/v$NEW"
echo "released $NEW"
