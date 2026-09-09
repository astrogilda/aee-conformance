#!/usr/bin/env bash
# The four arms of the artifact-binding demonstration, runnable from a fresh
# clone. Each arm prints its command, the verdict and the exit code, so the
# output is the evidence rather than a summary of it.
#
#   ./demo/four-arms.sh                      the four arms, synthetic archive
#   ./demo/four-arms.sh --trial <dir>        additionally profile a real trial
#
# The four arms always run against the deterministic synthetic archive written
# by tools/artifact-binding/fixture.py, so the demonstration reproduces byte for
# byte on any machine with no Docker and no network. `--trial <dir>` adds a
# PROFILE REPORT over a real Harbor trial directory, which is a different
# question: not "do the arms behave" but "does a real trial carry what a
# re-checkable record needs". On Harbor as it stands the honest answer is no,
# and the report prints which roles are missing.
#
# The only dependency beyond CPython is `cryptography`, which this repository
# already declares for its vector generators. With uv:
#
#   uv run --with cryptography ./demo/four-arms.sh
#
# Exit codes, per spec/artifact-binding/v1.md section 7: 0 verified, 2 failed,
# 3 not-established, 1 usage. The script itself exits 0 only when all four arms
# produced the outcome the contract says they must.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS="$ROOT/tools/artifact-binding"
BIND="python3 $TOOLS/aee_bind.py"
WORK="$(mktemp -d)"
REAL_TRIAL=""
STAMP="2026-01-01T00:00:00Z"
FAILURES=0

while [ $# -gt 0 ]; do
  case "$1" in
    --trial) REAL_TRIAL="$2"; shift 2;;
    *) echo "usage: $0 [--trial <harbor-trial-dir>]"; exit 1;;
  esac
done

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

say() { printf '\n=== %s ===\n' "$1"; }

expect() {
  # expect <label> <wanted-exit> <actual-exit>
  if [ "$2" -eq "$3" ]; then
    printf '  ARM RESULT: %s, exit %s, as the contract requires\n' "$1" "$3"
  else
    printf '  ARM RESULT: %s, exit %s, and the contract requires %s\n' "$1" "$3" "$2"
    FAILURES=$((FAILURES + 1))
  fi
}

# A fresh key. The verifier is offline and the key is pinned by the consumer,
# so the demonstration generates its own rather than trusting an ambient one.
$BIND keygen --key "$WORK/key" --pubkey "$WORK/key.pub" || exit 1

# The trial under test. A real Harbor trial directory is copied so the original
# is never touched; otherwise a deterministic synthetic one is generated and
# labelled as such.
mkdir -p "$WORK/trials"
python3 -c "
import sys, pathlib
sys.path.insert(0, '$TOOLS')
import fixture
fixture.build_trial(pathlib.Path('$WORK/trials/intact'))
"
echo "archive under test: SYNTHETIC, written by tools/artifact-binding/fixture.py"
python3 -c "
import sys, pathlib
sys.path.insert(0, '$TOOLS')
import fixture
fixture.build_verifier(pathlib.Path('$WORK/verifier'))
fixture.build_verifier(pathlib.Path('$WORK/verifier-changed'), changed=True)
"

$BIND build "$WORK/trials/intact" --verifier "$WORK/verifier" \
  --verifier-id "demo/tests@v1" --key "$WORK/key" --recorded-at "$STAMP" || exit 1

for arm in tampered incomplete; do
  cp -r "$WORK/trials/intact" "$WORK/trials/$arm"
done

say "ARM 1: intact archive reproduces"
$BIND verify "$WORK/trials/intact" --pubkey "$WORK/key.pub"
expect "verify" 0 $?
$BIND regrade "$WORK/trials/intact" --verifier "$WORK/verifier" \
  --verifier-id "demo/tests@v1" --key "$WORK/key" --out "$WORK/regrade-same" \
  --recorded-at "$STAMP"
expect "regrade with the same verifier" 0 $?
$BIND verify "$WORK/regrade-same" --pubkey "$WORK/key.pub"
expect "verify the regrade record" 0 $?

say "ARM 2: one byte changed in a covered artifact, before any grading"
printf 'HARBOR-BINDING-DEMO-TAMPERED\n' \
  > "$WORK/trials/tampered/artifacts/logs/artifacts/answer.txt"
$BIND verify "$WORK/trials/tampered" --pubkey "$WORK/key.pub"
expect "verify names the artifact and refuses" 2 $?
$BIND regrade "$WORK/trials/tampered" --verifier "$WORK/verifier" \
  --verifier-id "demo/tests@v1" --key "$WORK/key" --out "$WORK/regrade-tampered" \
  --recorded-at "$STAMP"
expect "regrade refuses before grading" 2 $?
if [ -d "$WORK/regrade-tampered/verifier" ]; then
  echo "  DEFECT: the verifier ran on a tampered archive"
  FAILURES=$((FAILURES + 1))
else
  echo "  no grading output was produced, so nothing was graded"
fi

say "ARM 3: a required-role artifact is missing"
rm -f "$WORK/trials/incomplete/verifier/reward.txt"
$BIND verify "$WORK/trials/incomplete" --pubkey "$WORK/key.pub"
expect "verify returns not-established" 3 $?

say "ARM 4: the same archive, a changed verifier, both outcomes preserved"
$BIND regrade "$WORK/trials/intact" --verifier "$WORK/verifier-changed" \
  --verifier-id "demo/tests@v2-stricter" --key "$WORK/key" \
  --out "$WORK/regrade-changed" --recorded-at "$STAMP"
expect "regrade with a changed verifier" 0 $?
$BIND verify "$WORK/regrade-changed" --pubkey "$WORK/key.pub"
expect "both records validate" 0 $?
$BIND lineage "$WORK/trials/intact/binding/manifest.json" \
  "$WORK/regrade-changed/binding/manifest.json"
expect "the lineage is checkable" 0 $?

if [ -n "$REAL_TRIAL" ]; then
  say "PROFILE REPORT: a real Harbor trial"
  echo "  source: $REAL_TRIAL"
  cp -r "$REAL_TRIAL" "$WORK/trials/real"
  $BIND build "$WORK/trials/real" --verifier "$WORK/verifier" \
    --verifier-id "demo/tests@v1" --key "$WORK/key" --recorded-at "$STAMP" > /dev/null
  $BIND verify "$WORK/trials/real" --pubkey "$WORK/key.pub"
  echo "  exit $?"
  echo "  A not-established verdict here is the FINDING, not a demonstration"
  echo "  failure: it names the roles a real trial does not carry today."
fi

printf '\n=== SUMMARY ===\n'
if [ "$FAILURES" -eq 0 ]; then
  echo "all four arms produced the outcome the contract requires"
  exit 0
fi
echo "$FAILURES check(s) did not produce the contract outcome"
exit 1
