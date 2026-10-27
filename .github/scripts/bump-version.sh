#!/usr/bin/env bash
# Run on master after a merge has passed CI: releases it. Bumps the patch
# version, adds the merged commits to CHANGELOG.md, commits and tags that, and
# pushes both. If the merge changed the version itself (a minor or major bump
# made by hand), that version has no tag yet and is released as it is.
#
# The same script as the sibling project mile's. A merge that doesn't touch the
# program isn't a release, and a run that master has already moved past leaves
# the release to the newer commit's run.
set -euo pipefail

# What ends up in the binary. Docs and CI don't.
program=(src Cargo.toml Cargo.lock build.rs rust-toolchain.toml)

git fetch -q origin master
if [ "$(git rev-parse HEAD)" != "$(git rev-parse origin/master)" ]; then
    echo "master has moved on; the newer commit's run will release this too"
    exit 0
fi

current=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
previous=$(git describe --tags --abbrev=0 --match 'v*')

if git diff --quiet "$previous..HEAD" -- "${program[@]}"; then
    echo "nothing that affects the program changed since $previous, no release"
    exit 0
fi

if ! git rev-parse -q --verify "refs/tags/v$current" >/dev/null; then
    export NEW="$current"
else
    IFS=. read -r major minor patch <<<"$current"
    export NEW="$major.$minor.$((patch + 1))"
    perl -0pi -e 's/^version = "[^"]+"/version = "$ENV{NEW}"/m' Cargo.toml
    # The package's own entry in Cargo.lock, found by the name in Cargo.toml's
    # [package] table ([lib] and [[bin]] have names too). Fail if it isn't
    # there, rather than release a Cargo.lock that --locked builds reject.
    NAME=$(sed -n '/^\[package\]/,/^\[/ s/^name = "\(.*\)"$/\1/p' Cargo.toml)
    export NAME
    perl -0pi -e 's/(name = "\Q$ENV{NAME}\E"\nversion = ")[^"]+/$1$ENV{NEW}/' Cargo.lock
    perl -0ne 'exit !/name = "\Q$ENV{NAME}\E"\nversion = "\Q$ENV{NEW}\E"/' Cargo.lock \
        || { echo "bump-version: no Cargo.lock entry for $NAME" >&2; exit 1; }
fi

# Everything since the previous release, oldest first, above the older entries.
ENTRY=$(printf '## %s (%s)\n\n%s\n\n' "$NEW" "$(date -u +%F)" \
    "$(git log --reverse --format='- %s' "$previous..HEAD")"; echo x)
export ENTRY="${ENTRY%x}"
perl -0pi -e 's/^(?=## )/$ENV{ENTRY}/m or die "no release heading in CHANGELOG.md\n"' CHANGELOG.md

git commit -q -m "Release $NEW" Cargo.toml Cargo.lock CHANGELOG.md
git tag "v$NEW"
git push --atomic origin HEAD:master "refs/tags/v$NEW"
echo "released $NEW"
