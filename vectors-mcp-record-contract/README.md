# Cross-run record contract

The subject under test here is not a protocol message. It is a **run record**:
the artifact a cross-implementation claim rests on when it says two
implementations agree.

The rule is in `../docs/INTEROP-EVIDENCE.md` and `check_run_record.py` is that
rule as code. This corpus is the checker's own conformance suite, so the rule
is measured rather than asserted beside itself. `check_vectors.py` runs the
checker over every member and refuses when an answer differs from the one the
member declares.

## Three answers, kept apart

| answer | question |
|---|---|
| `recheckable` | can a third party obtain the same result from what is published |
| `figureMeansWhatItSays` | does the headline agree with its own counting rule |
| `independence` | independent, self-report, or undeclared |

A record can be fully re-checkable, carry a figure nobody should quote, and be
a declared self-report. One member here is exactly that, and it is the member
that separates a checker reading the record from a checker reading the summary.

Independence is three-valued rather than a pass. A run of somebody else's
vectors by their author is worth publishing and is not independent evidence,
and only an undeclared record is a defect: failing a declared self-report would
push records towards leaving the declaration out, which is the opposite of what
the field is for.

## Every member is synthetic

Each is shaped after a defect observed in published cross-run claims in open
specification threads. None transcribes or attributes a particular claim, and
no party is named anywhere in this directory. The shape is the thing under
test, and a corpus that named parties would be an accusation with a schema.

A reject member differs from an accepting twin in exactly one field, and its
condition says which axis it fails. `check_vectors.py` refuses a reject member
declaring failures on two axes, because a member failing two cannot tell you
which rule caught it.

## Layout

| path | what it is |
|---|---|
| `records/` | one run record per member, named after a digest of its own declaration |
| `MANIFEST.json` | the conditions, the expectations, counts and corpus digest |
| `INDEX.md` | every member in one table |
| `check_run_record.py` | the criterion, as a checker; usable on any record, not only these |
| `gen_vectors.py` | regenerates the corpus byte-identically |
| `check_vectors.py` | self-check, and the criterion run against every member |

## Running it

```
python3 gen_vectors.py                       # regenerate, byte-identically
python3 gen_vectors.py --check               # refuse a tree the generator does not emit
python3 check_vectors.py                     # self-check, including the criterion
python3 check_run_record.py records/*.json   # the criterion on its own
```

`check_run_record.py` takes any run record in the shape `records/` uses, so a
project publishing one can check it before publishing rather than after being
asked about it.

## What this corpus does not do

It says nothing about whether any claim is true. A record failing the rule is
an assertion, which is a statement about what a reader can do with it. A
self-report from a careful engineer is frequently correct and is not evidence,
and holding those two apart is the whole content of the suite.
