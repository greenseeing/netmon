#!/bin/sh
# Print one version's CHANGELOG section, for use as release notes. The tag
# workflow feeds the output to the GitHub release; a human can run it to
# preview what a release will say.
#
# Usage: scripts/changelog-notes.sh v0.2.0 [CHANGELOG.md]
set -eu

VERSION="${1:?usage: scripts/changelog-notes.sh vX.Y.Z [changelog]}"
VERSION="${VERSION#v}"
CHANGELOG="${2:-CHANGELOG.md}"

[ -f "$CHANGELOG" ] || {
    echo "no such changelog: $CHANGELOG" >&2
    exit 1
}

# Everything between this version's heading and whatever ends it: the next
# version heading, or the reference-link block that closes the file. Match a
# link definition by its full `[label]:` shape — a bare leading `[` also starts
# ordinary content (a callout, a footnote), and ending the section there would
# silently truncate the release body.
notes="$(
    awk -v want="## [$VERSION]" '
        index($0, want) == 1        { inside = 1; next }
        !inside                     { next }
        index($0, "## [") == 1      { exit }
        /^\[[^]]*\]:/               { exit }
                                    { lines[n++] = $0 }
        END {
            first = 0
            while (first < n && lines[first] ~ /^[ \t]*$/) first++
            last = n - 1
            while (last >= first && lines[last] ~ /^[ \t]*$/) last--
            for (i = first; i <= last; i++) print lines[i]
        }
    ' "$CHANGELOG"
)"

[ -n "$notes" ] || {
    echo "no CHANGELOG section for $VERSION in $CHANGELOG" >&2
    exit 1
}

printf '%s\n' "$notes"
