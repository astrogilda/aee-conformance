#!/usr/bin/env bash
#
# Point this clone's git hooks at the tracked hooks directory this script
# lives in, then PROVE the hooks run by invoking them.
#
#   bash <this-directory>/install.sh
#
# `core.hooksPath` is local config. No clone inherits it, so every fresh
# clone must run this once; a clone that does not has no hooks at all, which
# is why the same rules are also enforced in CI.
#
# Three properties this script has on purpose, each one a bug that already
# happened here:
#
# 1. It WRITES NO FILES. An earlier installer copied hooks into the resolved
#    hooks directory and destroyed a tracked `pre-push` that was running a
#    visibility guard, ruff and whole-tree strict mypy; it was recovered from
#    the index. This script only sets one config key, so there is nothing it
#    can overwrite.
# 2. It DERIVES the directory from its own location instead of hardcoding
#    one. Repositories keep their tracked hooks in different places
#    (`.githooks`, `tools/git-hooks`), and a hardcoded path is how a shared
#    installer starts lying about one of them.
# 3. It sets a RELATIVE path. An absolute `core.hooksPath` is shared by every
#    linked worktree of a repository, so one worktree ends up running another
#    checkout's hooks -- observed and fixed on this machine. A relative path
#    resolves per working tree and means the same thing in every clone.
#
# It also refuses to make things quietly worse: before switching, it compares
# the hooks git consults today against the ones it would consult afterwards,
# and aborts if any currently-live hook would stop running.

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
hooks_abs="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
hooks_rel="${hooks_abs#"$repo_root"/}"

if [ "$hooks_rel" = "$hooks_abs" ]; then
	echo "install: ABORT -- $hooks_abs is not inside $repo_root." >&2
	exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
	echo "install: ABORT -- python3 not found; the commit-msg hook needs it." >&2
	exit 1
fi

# Ask git where hooks come from today. Never assume `.git/hooks`: four of the
# repositories here redirect elsewhere, and assuming is what destroyed a file.
current_setting="$(git config --get core.hooksPath || true)"
current_abs="$(cd "$repo_root" && cd "$(git rev-parse --git-path hooks)" 2>/dev/null && pwd || true)"

hook_names() {
	# Executable, non-sample entries -- the ones git would actually run.
	# `find -L` follows symlinks on purpose: hooks installed by the previous
	# installer are symlinks into a tracked directory, and plain `-type f`
	# does not match a symlink, so without -L this comparison would report
	# "nothing would be lost" while a live pre-push was about to go dark.
	[ -n "$1" ] && [ -d "$1" ] || return 0
	# The trailing `|| true` is load-bearing under `set -euo pipefail`: when a
	# repository's current hooks directory holds nothing but git's `.sample`
	# files, `grep -v` matches nothing, exits 1, and takes the whole script
	# down before it has said anything. That is the empty-hooks case, which is
	# the most common one in a fresh clone.
	find -L "$1" -maxdepth 1 -type f -perm -u+x -printf '%f\n' 2>/dev/null |
		grep -v -e '\.sample$' -e '^install\.sh$' | sort || true
}

before="$(hook_names "$current_abs")"
after="$(hook_names "$hooks_abs")"
lost="$(comm -23 <(printf '%s\n' "$before") <(printf '%s\n' "$after") | grep -v '^$' || true)"

if [ -n "$lost" ]; then
	echo "install: ABORT -- switching core.hooksPath to '$hooks_rel' would stop these hooks running:" >&2
	printf '  - %s\n' $lost >&2
	echo "install: move them into $hooks_rel and commit them first." >&2
	exit 1
fi

if [ "$current_setting" = "$hooks_rel" ]; then
	echo "install: core.hooksPath is already '$hooks_rel'."
else
	git -C "$repo_root" config core.hooksPath "$hooks_rel"
	echo "install: core.hooksPath '${current_setting:-<unset>}' -> '$hooks_rel'."
fi

echo "install: git will now run these hooks:"
printf '  - %s\n' $after

# Proof, not inference: run the message gate's own fixtures.
echo "install: verifying the commit-msg gate by invoking it..."
"$repo_root/$hooks_rel/commit-msg" --selftest
echo "install: done."
