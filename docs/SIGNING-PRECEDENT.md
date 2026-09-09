# Signed and timestamped conformance corpora: what the field publishes

Each corpus in this repository is signed over its own digest, stamped by an RFC
3161 authority, and anchored by OpenTimestamps. This file exists because the
sentence beside that fact is an ABSENCE claim, and an absence claim is the
easiest kind to get wrong. A query that never ran, a query scoped to the wrong
thing and a genuine nothing all print the same emptiness.

So the claim ships with the command that re-derives it, with the control that
proves the command can see a positive when one exists, and with a table of what
the command actually returned on a stated date. Anyone can re-run the commands
below and disagree with the table.

This section states the claim. The next one gives the command and its control, I
ran both on 2026-09-09, and the section after that is the table they returned.
The last two sections say why this repository signs and stamps at all, and where
I put the raw captures. The verification recipe a
reader runs against a release of this corpus is in the README, under "Verify a
release without trusting us".

## The claim

As of 2026-09-09, no cryptographic-conformance corpus surveyed here publishes a
signature, a detached PGP signature, an RFC 3161 token, or an OpenTimestamps
proof as a release asset. Four of the six publish no GitHub release objects at
all; two publish releases and attach no assets to them.

The claim covers GitHub release assets. That scope is the whole of it. It is not
a claim that these projects are unsigned software: several sign their
distribution artifacts elsewhere, on package indexes and in their own build
systems, and pyca/cryptography ships attested wheels to PyPI, which is a stronger
posture than most of the field manages and is not the posture a citation needs. The survey looked for
one thing: a corpus a third party can fetch by tag and then verify against a key
the maintainers published beside it. That is the operation a conformance
requirement needs when it names a suite. It decides whether a citation resolves
to bytes or to a moving branch.

## Re-derive it

```bash
for repo in google/wycheproof C2SP/CCTV C2SP/x509-limbo pyca/cryptography \
            theupdateframework/tuf-conformance sigstore/sigstore-conformance \
            sigstore/cosign; do
  printf '%s\t' "$repo"
  gh api "repos/$repo/releases?per_page=100" \
    --jq '[.[].assets[].name] | map(select(test("\\.(sig|asc|tsr|ots|sigstore|sigstore\\.json)$"))) | length'
done
```

sigstore/cosign is in the list as the POSITIVE CONTROL and is not part of the
claim. That project attaches 4,171 signature-shaped assets across its 75 releases, so a
run in which cosign also returns zero is a broken query and not a finding. A
reader can tell those two apart without trusting this file.

Four repositories return an empty release list, and an empty list is where an
absence claim usually dies: `[]` and "the call failed" are one character apart in
a pipeline. I therefore read each zero twice, the second time through an endpoint that
answers about something else:

```bash
gh api "repos/$repo/releases?per_page=100" -i | head -1   # must be HTTP 200
gh api "repos/$repo/tags?per_page=100" --jq 'length'      # non-zero proves the read path works
```

A 200 with an empty array from the first, alongside a non-zero count from the
second, is a real negative. Authentication worked, the repository resolved, a
neighbouring endpoint returned content, and the release list is empty because
there are no releases.

## What it returned, 2026-09-09

Every figure below is the output of the commands above. I captured the JSON at
the time of the run. The signature-shaped column counts asset names ending .sig,
.asc, .tsr, .ots, .sigstore or .sigstore.json.

| Repository | What it is | Releases | Release assets | Signature-shaped | Read-path control |
|---|---|---|---|---|---|
| google/wycheproof | cryptographic test vectors | 0 | 0 | 0 | HTTP 200, 2 tags |
| C2SP/CCTV | community cryptography test vectors | 0 | 0 | 0 | HTTP 200, 0 tags, repository resolves |
| C2SP/x509-limbo | X.509 path-validation corpus | 0 | 0 | 0 | HTTP 200, 0 tags, repository resolves |
| pyca/cryptography | the library the vectors above are read by | 0 | 0 | 0 | HTTP 200, at least 100 tags |
| theupdateframework/tuf-conformance | TUF client conformance suite | 8 | 0 | 0 | 8 releases listed |
| sigstore/sigstore-conformance | Sigstore client conformance suite | 29 | 0 | 0 | 29 releases listed |
| sigstore/cosign (control, not part of the claim) | the signing tool itself | 75 | 6929 | 4171 | the query finds them |

The last two rows of the claim are the strongest form of it. tuf-conformance and
sigstore-conformance both publish releases, 8 and 29 of them, and attach no files
at all. So there is no argument that the survey looked in the wrong place, and
none that these projects do not cut releases. They cut releases. The release is a
git tag with notes.

C2SP/CCTV and C2SP/x509-limbo returning zero tags is worth its own sentence. It
is the one row a reader could mistake for a failed read. Both repositories
resolve and both return HTTP 200. Both distribute their corpora by other means:
CCTV as directories on the default branch, x509-limbo as a `limbo.json` built and
served from GitHub Pages. Neither has a versioned, verifiable artifact a citation
can name.

## This repository, before and after

| | Releases | Release assets | Signature-shaped |
|---|---|---|---|
| astrogilda/aee-conformance, 2026-09-09 | 3 | 0 | 0 |

Read that row as the reason this file exists rather than as a boast. On the day
of the survey this repository sat where the corpora it surveys sit. It had a tag
and nothing a stranger could verify. What changed sits in
`release/`, which now holds the digest list, its signature and the two time
proofs, in [`spec/tsa-roots.pem`](../spec/tsa-roots.pem), which pins the
timestamp root, and in
[`scripts/release-gate.py`](../scripts/release-gate.py), which refuses a tag
whose artifacts do not verify or whose digests are not what the vector files on
disk produce. The row above will move when a release is published with those
assets attached, and it will move by re-running the command rather than by
editing the number.

## Why signed, and why timestamped twice

A conformance claim names a corpus. If that corpus can move, the claim means
whatever the corpus says today: which is why every revision here is immutable and
regenerable, why a normative change bumps the revision instead of editing a
published one, and why the vendored specification's digest is itself a corpus
input. A signature closes the remaining gap. It ties the person who
maintains the corpus to exactly these bytes, so a relying party who trusts
nobody can still tell a fetched corpus from a substituted one.

Time is the second question and it has two different answers. The RFC 3161 token
is an assertion by a named authority, verifiable offline against the root pinned
in `spec/tsa-roots.pem`, and worth exactly that authority's honesty. The
OpenTimestamps proof is an anchor into a public chain that nobody here can
rewrite, and it is worth nothing until its Bitcoin attestation lands about a day
later. One is trusted and immediate. The other is trustless and slow. A release
carries both. The weekly job in `.github/workflows/ots-upgrade.yml` finishes the
slow one.

The signature is deliberately never uploaded to a transparency log. A consumer
running a conformance suite has to be able to verify with no network and no
dependency on a log staying reachable, and the two time proofs supply the
evidence a log would otherwise carry.

## The capture

The JSON behind the table was captured at the time of the run, one file per
repository. It lives outside this repository, in the research tree that produced
this file (`research/351-bin-e-campaign-2026-09-09/_raw/A-release-signing/`, with
byte counts and SHA-256 digests in that directory's index). Nothing in this file
depends on those captures surviving. Every figure in the table is re-derivable
from the two command listings above, which is why they are printed in full.
