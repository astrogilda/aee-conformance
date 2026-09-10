---
target: https://github.com/harbor-framework/harbor/pull/3123 ("RFC: Regrade from a saved artifact archive", a PULL REQUEST, opened 2026-09-08T06:35:10Z by ayushnangia, state open)
channel: GitHub comment into the live RFC thread. Not a new issue, not a competing proposal.
deadline: none. The reason to send now is that the RFC asks a direct question, has 3 comments, and all 3 are bots (vercel, github-actions, codecov), so no human has answered it.
audience: ayushnangia, who opened the RFC, and the Harbor maintainers who will decide between its two options
status: DRAFT. Not posted. The operator sends.
identity: private individual. No company, product or repository name from the stealth list appears in this text.
writing_pass: edelman register applied; humanizer run end to end including the jury stage; mechanical gates run. See the report for the per-gate results.
evidence_status:
  - "the RFC is a pull request, opened 2026-09-08T06:35:10Z, open, 3 comments, all 3 bots": verified_fact, gh api capture at research/351-bin-e-campaign-2026-09-09/_raw/harbor-threads/3123.json and 3123-comments.json, sha256 in _raw/INDEX.md
  - "the RFC's closing question, quoted verbatim": verified_fact, same capture
  - "regrade.py:361 is `if replay_path.exists(): continue`": verified_fact, read directly at harbor-framework/harbor 1f84b4c in ~/Documents/git-clones/harbor-framework
  - "the _validate_artifact_coverage docstring, quoted verbatim": verified_fact, regrade.py:308-318 at that commit
  - "read_artifact_manifest raises when the manifest is missing or unreadable": verified_fact, regrade.py:191-212
  - "SourceTrialLock at lock.py:91, TrialLock.source_trial at lock.py:195": verified_fact, grep of the identifier at that commit. The plan's lock.py:89 is stale by 2 lines; cite the identifier
  - "ArtifactManifestEntry has 5 members and no length and no digest": verified_fact, models/trial/artifact_manifest.py:6-12
  - "compute_skill_digest returns sha256:<hex> over a directory walk": verified_fact, skills.py:214-223
  - "_validate_digest enforces sha256:<64 lowercase hex>": verified_fact, lock.py:45-53
  - "acp.py raises on a manifest digest mismatch": verified_fact, acp.py:1004-1007
  - "test_stderr_path has 1 reference in src/ and test_stdout_path has 9, including the writer": verified_fact, grep with a positive control on the same command
  - "a real trial scored 1.0 in 43 seconds and its verifier directory held 2 files": verified_fact, run locally 2026-09-09 on 1f84b4c, oracle agent, separate-mode verifier
  - "the 4 arms reach the outcomes the contract states": verified_fact, demo/four-arms.sh exits 0
  - "about 5 days for the 2 fields plus the comparison": inference, an estimate from the 2026-09-09 evaluation-clone sweep. Not measured, and not written into the comment
push_plan:
  - the operator posts it as a comment on the pull request, from his own account, as a private individual
  - re-read the thread first. It is days old and a maintainer may have answered the question in the interval
  - if ayushnangia or a maintainer engages, the follow-up is one pull request: length and sha256 on ArtifactManifestEntry, populated where the entries are built, and a digest comparison at regrade.py:361, in that order and nothing else
  - the harbor#2343 comment goes out within a day and each links the other, because one artifact backs both
  - follow-up cadence: one nudge after 10 days, then leave it
---

# Draft comment for harbor#3123

The RFC ends on a question: "Would an archive mode be useful, or would checksums on the existing artifacts cover the need?" Checksums cover it, as best I can tell. I read the regrade path to find where such a check would have to go. It is one line.

`_validate_artifact_coverage` in src/harbor/trial/regrade.py already does most of this job, and its docstring is precise about how much: "for entries recorded as collected the bytes must exist at the exact host path the artifact uploader will read during replay, so validation cannot pass while the upload silently skips." Existence at a path. The four-state taxonomy under it is careful in a way that is easy to underrate, with failed meaning collection did not capture the input, skipped meaning "the recorded bytes belong to a different source" after a host-path collision, and empty marked as "an honest empty directory" that replays as one. `read_artifact_manifest` refuses a missing or unparseable manifest outright, "since without it artifact coverage cannot be verified." And lineage is already recorded: `SourceTrialLock` carries the action, the source type, the source trial id and the source trial's own TaskLock, and TrialLock.source_trial hangs it off every trial lock.

So 3 of the 4 things an auditable regrade needs are in the tree today: refusal on an uncollected input, refusal on an unreadable manifest, and recorded lineage from a regrade to its source. The fourth is at regrade.py line 361. The whole of it is `if replay_path.exists(): continue`.

Swap the bytes at that path between the execute and the regrade. Validation passes. The verifier runs.

The new score looks exactly as authoritative as one computed over the original archive. A regrade over a modified archive is currently indistinguishable from a regrade over an intact one.

The check cannot go there yet, and the reason sits one level up in the model. An `ArtifactManifestEntry` in src/harbor/models/trial/artifact_manifest.py has 5 members: source, destination, type, status, service. It carries no length and no digest.

The manifest records that a file was collected and where it was put. It does not record what it was.

Add `length: int` and `sha256: str` to `ArtifactManifestEntry`, and the check becomes possible. Populate them in src/harbor/trial/artifact_handler.py, where the bytes are already on the host at a known path when the entry is built. Then make `regrade.py:361` an existence-and-digest check that raises the same RegradeError shape as the 4 cases above it, so a byte mismatch is reported in the vocabulary that function already speaks.

None of that is new machinery here. `compute_skill_digest` in src/harbor/skills.py already walks a directory, hashes each file with hashlib.sha256(file_path.read_bytes()).hexdigest(), and returns f"sha256:{hasher.hexdigest()}". `_validate_digest` in lock.py already enforces sha256:<64 hex chars> and raises on anything else.

And acp.py already fails closed on exactly this comparison, with the message "ACP source manifest digest does not match manifest_sha256". The change extends a pattern this codebase applies to inputs so that it also covers what a regrade reads.

I built a working version to check that the line is really where it turns. It runs 4 arms. An intact archive verifies and regrades to the same reward.

One changed byte fails before any grading is re-run, naming the file, the declared digest and the computed one, and the regrade stops there and writes no grading output at all. A required artifact that is absent returns a third outcome, not-established, with its own exit code, distinct from both a pass and a failure. And the same archive graded by a changed verifier produces a second record naming the new verifier and the new reward, where both records validate, both name the same archive digest, and either one can be checked against the other.

Arm 2 is the arm Harbor does not have. Arms 1, 3 and 4 are there to show that adding it breaks none of the three you already have.

One thing about arm 2 is worth stating plainly, because it is the argument for doing this now. A fresh score computed over corrupted bytes is worse than no score, because it carries a number and a provenance trail and gets read as a result. The check has to run before grading, not after.

I then ran it against a real trial, not a synthetic directory, and it turned up a separate defect. A single-step task with a separate-mode verifier and the oracle agent scored 1.0 in 43 seconds. The record I built from its directory came back not-established on 2 roles.

One was the trajectory, expected for the oracle agent. The other was the grading standard error. That one has nothing to do with the agent.

TrialPaths.test_stderr_path is defined in src/harbor/models/trial/paths.py and nothing in src/ writes it: `test_stderr_path` has 1 reference in the whole tree, its own definition, while test_stdout_path has 9, including the writer in src/harbor/verifier/verifier.py. A grading run that wrote to standard error and then failed leaves no record of what it said. A regrade has nothing to compare against.

Small, independent of everything above, and worth a separate fix.

The same reading turned up a swallowed exception. `_write_manifest` swallows the exception when the write fails, and the read path swallows it too, so a corrupted manifest quietly becomes an empty entry list, and the merge it feeds then writes a manifest that has lost the earlier passes. A trial whose collection broke is currently indistinguishable from a trial that collected nothing.

A `capture_errors` list on the manifest would close that, and by my reading it costs almost nothing next to the digest work. Separately, the _equality_key tuples on the lock models are semantic input comparison for resume and cache decisions, and I would keep them out of this: a hash preimage wants a deterministic wire encoding, and a Python tuple is not one. Whatever record carries the digests should canonicalize its own bytes.

On the archive-mode side of your question, the one thing an archive buys that checksums do not is a name for the whole set, and by my reading that is a single extra digest, no mode required: hash the sorted per-file entries and, as best I can tell, you have an identifier for the archive that two regrades of it can both cite. Arm 4 is checkable in my version because the two records carry that same identifier. It needs no new packaging.

Beyond the 2 fields I would also offer, separately and only if wanted, a detached signature over the manifest with a deterministic encoding rule, so a party holding the archive, trusting neither whoever produced it nor the storage it sat on, can check it offline: RFC 8785 canonical bytes, a static ed25519 key, no network and no transparency log, which matters for a framework whose users run private evaluations. I would not bundle that with the digest change. The digest change stands on its own and should not wait on a conversation about keys.

The limit of all of it, so the digests are not read as more than they are: this binds a result to the saved artifacts and grading inputs it names, it supports integrity checking and auditable regrading, and it does not, by itself, attest that the original agent execution was genuine or completely observed. Anyone who fabricates a coherent archive and signs it has made an attributable assertion and nothing else. It does get you the narrower thing the RFC is reaching for.

After the fact, someone can tell an intact archive from a modified one. An incomplete record is distinguishable from both. They can re-grade with a different verifier, and the first verifier's result survives beside the second.

If the 2 fields and the comparison are the direction you want, I will open them as one pull request with the 4 arms wired as tests, and leave the signature for its own thread. If you prefer the archive mode, the same digest work is its prerequisite. It is not wasted under either answer to your question.
