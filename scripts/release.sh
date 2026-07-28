#!/bin/sh
# Cut a release: bump the version, commit, tag, push. Pushing the tag is all it
# takes — the tag workflow (.github/workflows/release.yml) publishes the GitHub
# release object from the CHANGELOG, and install.sh (and `netmon update`)
# resolve it as the latest version. No token is needed here; the workflow's own
# token writes the release.
#
# Usage: scripts/release.sh 0.1.0
set -eu

VERSION="${1:?usage: scripts/release.sh X.Y.Z}"
SOURCE="netmon.py"

# Exactly three segments of digits. This must stay in lockstep with
# `_valid_ref` in install.sh and `_release_version` in netmon.py: a version
# accepted here but refused there would cut a tag that silently serves `main`
# to everyone. The pairing is pinned by tests/test_packaging.py.
valid_version() {
    [ "${#1}" -le 32 ] || return 1
    case "$1" in
        *[!0-9.]*) return 1 ;;
        .* | *.)   return 1 ;;
        *..*)      return 1 ;;
        *.*.*.*)   return 1 ;;
        *.*.*)     return 0 ;;
        *)         return 1 ;;
    esac
}

if ! valid_version "$VERSION"; then
    echo "version must look like X.Y.Z (got: $VERSION)" >&2
    exit 1
fi

if [ -n "$(git status --porcelain)" ]; then
    echo "working tree is dirty; commit or stash first." >&2
    exit 1
fi

# Fail before the tag exists, not after. A tag whose CHANGELOG section is
# missing builds a release with no notes — and the workflow dies at the notes
# step, leaving a pushed tag with no release behind it.
if ! ./scripts/changelog-notes.sh "$VERSION" >/dev/null; then
    echo "add a '## [$VERSION]' section to CHANGELOG.md first." >&2
    exit 1
fi

sed -i.bak "s/^__version__ = .*/__version__ = \"$VERSION\"/" "$SOURCE"
rm -f "$SOURCE.bak"

# The very first release tags the version the file already carries — nothing to
# commit then; the tag alone is the release.
if ! git diff --quiet -- "$SOURCE"; then
    git add "$SOURCE"
    git commit -m "Release v$VERSION"
fi
git tag "v$VERSION"
git push
git push origin "v$VERSION"

echo "Pushed v$VERSION. The tag workflow publishes the release; install.sh will"
echo "then resolve it as the latest version."
