#!/usr/bin/env bash
# Sign release/CORPUS-DIGESTS.txt with the corpus signing key.
#
# Signing happens HERE, on the maintainer's machine, at tag time. It does not
# happen in CI, and the key is not a repository secret. A key in an Actions
# secret is readable by every workflow that ever runs in the repository and by
# anyone who can land a workflow change; a key in the maintainer's keyring is
# reachable only by someone already on that machine. CI's job is the other
# half: refuse a tag whose artifacts do not verify.
#
# Nothing here writes key material into the tree. The private half is read from
# the keyring into a file in a private temporary directory, used, and removed on
# every exit path including a failure.
#
# The signature is NOT uploaded to a transparency log (--tlog-upload=false).
# That is deliberate and it is the thesis rather than a convenience: a
# conformance consumer has to be able to verify with no network and no
# dependency on a log staying reachable. The RFC 3161 token and the
# OpenTimestamps proof supply the time evidence a log would otherwise carry,
# and they are verifiable from the bytes on disk.
#
#   scripts/release-sign.sh                 # sign; refuse if the digest file is stale
#   scripts/release-sign.sh --with-timestamps   # also stamp (RFC 3161 + OpenTimestamps)
#
# Exit 0 only when the signature verifies against release/cosign.pub afterwards.
# A signing step that does not verify its own output is a step that reports
# success for a file nobody read.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIGESTS="$REPO/release/CORPUS-DIGESTS.txt"
SIGNATURE="$DIGESTS.sig"
PUBLIC="$REPO/release/cosign.pub"

KEY_SERVICE=cosign
KEY_ACCOUNT=aev-corpus
PASSWORD_ACCOUNT=aev-corpus-password

with_timestamps=0
for arg in "$@"; do
  case "$arg" in
    --with-timestamps) with_timestamps=1 ;;
    *) echo "release-sign: unknown argument $arg" >&2; exit 2 ;;
  esac
done

for tool in cosign secret-tool python3; do
  command -v "$tool" >/dev/null || {
    echo "release-sign: $tool is not on PATH. Refusing to continue: a signing step that cannot run is not a signing step that passed." >&2
    exit 2
  }
done

# The bytes about to be signed must be the bytes the corpora produce. Signing a
# stale list certifies a corpus that is no longer there.
python3 "$REPO/scripts/release-digests.py" --check

workdir="$(mktemp -d)"
cleanup() { rm -rf "$workdir"; }
trap cleanup EXIT
chmod 700 "$workdir"

if ! secret-tool lookup service "$KEY_SERVICE" account "$KEY_ACCOUNT" > "$workdir/key" 2>/dev/null; then
  echo "release-sign: reading the private half from the keyring failed (service $KEY_SERVICE, account $KEY_ACCOUNT)." >&2
  exit 2
fi
if ! [ -s "$workdir/key" ]; then
  echo "release-sign: the keyring returned nothing for service $KEY_SERVICE account $KEY_ACCOUNT. An empty read is not an absent key; unlock the keyring and try again." >&2
  exit 2
fi
if ! COSIGN_PASSWORD="$(secret-tool lookup service "$KEY_SERVICE" account "$PASSWORD_ACCOUNT")" || [ -z "${COSIGN_PASSWORD:-}" ]; then
  echo "release-sign: the key password is not in the keyring (service $KEY_SERVICE, account $PASSWORD_ACCOUNT)." >&2
  exit 2
fi
export COSIGN_PASSWORD

cosign sign-blob \
  --key "$workdir/key" \
  --tlog-upload=false \
  --yes \
  --output-signature "$SIGNATURE" \
  "$DIGESTS"

# Verify what was just written, with the PUBLISHED public half rather than with
# anything derived from the private one. This is the only step that establishes
# that release/cosign.pub is the key a stranger will succeed with.
cosign verify-blob \
  --key "$PUBLIC" \
  --signature "$SIGNATURE" \
  --insecure-ignore-tlog=true \
  "$DIGESTS"

echo "signed: ${SIGNATURE#"$REPO/"}"

if [ "$with_timestamps" = 1 ]; then
  "$REPO/scripts/release-timestamps.sh" stamp
fi
