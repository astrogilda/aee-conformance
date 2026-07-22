package aee

import (
	"encoding/json"
	"errors"
	"fmt"
)

// StatementType is the only accepted in-toto statement _type (spec:125).
const StatementType = "https://in-toto.io/Statement/v1"

// PredicateType is the only predicateType this implementation accepts
// (spec:3). A different version URI is rejected fail-closed; the verifier
// never attempts more than one construction (spec:98-103).
const PredicateType = "https://in-toto.io/attestation/adversarial-execution-evidence/v0.6"

// Closed vocabularies (spec:220-232, 355-436).
const (
	ResultPass     = "pass"
	ResultDegraded = "degraded"
	ResultFail     = "fail"

	BasisSubstrate = "substrate"
	BasisArtifact  = "artifact"

	MethodIntercepted   = "intercepted"
	MethodReconstructed = "reconstructed"

	KindInterception = "interception"
	KindArming       = "arming"
	KindSealed       = "sealed"
	KindExamination  = "examination"

	ActualLayerNone = "none"
)

// Subject is one in-toto statement subject.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Statement is a parsed in-toto statement carrying an AEE predicate.
type Statement struct {
	Type          string
	Subject       []Subject
	PredicateType string
	PredicateRaw  json.RawMessage
	Predicate     *Predicate

	// ParseCodes collects shape faults found while decoding members; GATE 0
	// folds them into its own code list.
	ParseCodes []Code
}

// Predicate is the decoded predicate body. Member presence is tracked
// explicitly wherever "absent" and "empty" differ normatively.
type Predicate struct {
	Raw map[string]json.RawMessage

	Result        string
	ResultPresent bool

	Env *Environment

	Coverage        *Coverage
	CoveragePresent bool

	Rows        []Row
	RowsPresent bool

	Records        []Record
	RecordsPresent bool

	BatchRoot        string
	BatchRootPresent bool

	IssuedAt        string
	IssuedAtPresent bool
}

// Environment is observationEnvironment (spec:290-316).
type Environment struct {
	Raw map[string]json.RawMessage

	Substrate      *DigestRef
	Corpus         *Corpus
	CatchPolicy    *DigestRef
	NetworkPosture *NetworkPosture
	Vocabulary     *Vocabulary
	RunEntropy     *DigestRef
}

// DigestRef is a named digest reference ({name?, digest:{sha256: ...}}).
type DigestRef struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Sha256 returns the sha256 member of the digest set ("" when absent).
func (d *DigestRef) Sha256() string {
	if d == nil || d.Digest == nil {
		return ""
	}
	return d.Digest["sha256"]
}

// Corpus carries the digest-committed corpus manifest (spec:294-297).
type Corpus struct {
	Name        string            `json:"name"`
	URI         string            `json:"uri"`
	Digest      map[string]string `json:"digest"`
	ManifestRaw json.RawMessage   `json:"manifest"`

	Classes map[string][]string `json:"-"`
}

// Sha256 returns the corpus digest sha256 ("" when absent).
func (c *Corpus) Sha256() string {
	if c == nil || c.Digest == nil {
		return ""
	}
	return c.Digest["sha256"]
}

// NetworkPosture is the substrate-authoritative egress posture pin.
type NetworkPosture struct {
	Posture string            `json:"posture"`
	Digest  map[string]string `json:"digest"`
}

// Sha256 returns the posture digest sha256 ("" when absent).
func (n *NetworkPosture) Sha256() string {
	if n == nil || n.Digest == nil {
		return ""
	}
	return n.Digest["sha256"]
}

// Vocabulary is observationVocabulary (spec:300-311).
type Vocabulary struct {
	Digest map[string]string `json:"digest"`
	Labels []string          `json:"labels"`
	Caught []string          `json:"caught"`

	LabelsPresent bool `json:"-"`
	CaughtPresent bool `json:"-"`
}

// Coverage is the coverage bound (spec:318-325).
type Coverage struct {
	AssessedClasses []string          `json:"assessedClasses"`
	OutOfScope      map[string]string `json:"outOfScope"`
	RoutedElsewhere map[string]string `json:"routedElsewhere"`
}

// Row is one attackResults row. Pointer members distinguish an absent member
// from an empty value: absent basis/method is fail-closed (spec:424-427),
// absent actualLayer is a malformed statement (spec:541-545).
type Row struct {
	Raw map[string]json.RawMessage

	AttackID            string
	ContainmentObserved string
	Basis               *string
	Method              *string
	ActualLayer         *string

	// RefsPresent and RefsRaw keep the member's raw shape so non-integer and
	// negative indexes are reportable (ref-malformed) rather than a decode
	// panic. Refs holds the resolved indexes when every entry is a valid
	// non-negative integer.
	RefsPresent bool
	RefsRaw     []json.RawMessage
	Refs        []int
	RefsErr     error
}

// IsSubstrate reports whether the row declares basis: substrate.
func (r *Row) IsSubstrate() bool {
	return r.Basis != nil && *r.Basis == BasisSubstrate
}

// Record is one observation record: a DSSE-shaped envelope (spec:570-575).
type Record struct {
	PayloadB64  string            `json:"payload"`
	PayloadType string            `json:"payloadType"`
	Signatures  []RecordSignature `json:"signatures"`
}

// RecordSignature matches the DSSE signature member shape. The keyid is an
// unauthenticated lookup hint and never the check itself (spec:678-681).
type RecordSignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// maxStatementBytes bounds the whole untrusted statement before it is
// unmarshaled. The JCS layer already caps per-record-payload size and nesting
// depth, but nothing bounded the outer statement, so a statement with very many
// records (or huge non-payload fields) could exhaust memory. The bound is
// generous relative to any legitimate AEE statement; it is a resource guard, not
// a conformance rule, and both reference rails apply the same limit.
const maxStatementBytes = 64 << 20 // 64 MiB

// ParseStatement decodes one complete in-toto statement. A nil error means
// the JSON decoded; shape faults that have their own registry code are
// collected into Statement.ParseCodes for GATE 0 rather than failing the
// parse, so one malformed member reports its named code instead of a generic
// failure.
func ParseStatement(b []byte) (*Statement, error) {
	if len(b) > maxStatementBytes {
		return nil, fmt.Errorf("%w: statement is %d bytes", ErrInputTooLarge, len(b))
	}
	var shadow struct {
		Type          *string         `json:"_type"`
		Subject       []Subject       `json:"subject"`
		PredicateType *string         `json:"predicateType"`
		Predicate     json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(b, &shadow); err != nil {
		return nil, fmt.Errorf("statement does not parse: %w", err)
	}
	s := &Statement{Subject: shadow.Subject, PredicateRaw: shadow.Predicate}
	if shadow.Type != nil {
		s.Type = *shadow.Type
	}
	if shadow.PredicateType != nil {
		s.PredicateType = *shadow.PredicateType
	}
	if len(shadow.Predicate) == 0 {
		return nil, errors.New("statement carries no predicate")
	}
	p, codes := parsePredicate(shadow.Predicate)
	s.Predicate = p
	s.ParseCodes = codes
	return s, nil
}

func parsePredicate(raw json.RawMessage) (*Predicate, []Code) {
	var codes []Code
	p := &Predicate{}
	if err := json.Unmarshal(raw, &p.Raw); err != nil {
		return p, appendCode(codes, CodeStatementMalformed)
	}

	if r, ok := p.Raw["result"]; ok {
		p.ResultPresent = true
		if err := json.Unmarshal(r, &p.Result); err != nil {
			codes = appendCode(codes, CodeResultVocabulary)
		}
	}

	if envRaw, ok := p.Raw["observationEnvironment"]; ok {
		env, envCodes := parseEnvironment(envRaw)
		p.Env = env
		for _, c := range envCodes {
			codes = appendCode(codes, c)
		}
	}

	if covRaw, ok := p.Raw["coverage"]; ok {
		p.CoveragePresent = true
		cov := &Coverage{}
		if err := json.Unmarshal(covRaw, cov); err != nil {
			codes = appendCode(codes, CodeStatementMalformed)
		} else {
			p.Coverage = cov
		}
	}

	if rowsRaw, ok := p.Raw["attackResults"]; ok {
		p.RowsPresent = true
		var rawRows []json.RawMessage
		if err := json.Unmarshal(rowsRaw, &rawRows); err != nil {
			codes = appendCode(codes, CodeStatementMalformed)
		} else {
			for _, rr := range rawRows {
				row, rowCodes := parseRow(rr)
				p.Rows = append(p.Rows, row)
				for _, c := range rowCodes {
					codes = appendCode(codes, c)
				}
			}
		}
	}

	if recRaw, ok := p.Raw["observationRecords"]; ok {
		p.RecordsPresent = true
		if err := json.Unmarshal(recRaw, &p.Records); err != nil {
			codes = appendCode(codes, CodeStatementMalformed)
		}
	}

	if brRaw, ok := p.Raw["batchRoot"]; ok {
		p.BatchRootPresent = true
		if err := json.Unmarshal(brRaw, &p.BatchRoot); err != nil {
			codes = appendCode(codes, CodeStatementMalformed)
		}
	}

	if iaRaw, ok := p.Raw["issuedAt"]; ok {
		p.IssuedAtPresent = true
		if err := json.Unmarshal(iaRaw, &p.IssuedAt); err != nil {
			codes = appendCode(codes, CodeIssuedAtMalformed)
		}
	}

	return p, codes
}

func parseEnvironment(raw json.RawMessage) (*Environment, []Code) {
	var codes []Code
	env := &Environment{}
	if err := json.Unmarshal(raw, &env.Raw); err != nil {
		return env, appendCode(codes, CodeStatementMalformed)
	}

	if r, ok := env.Raw["substrate"]; ok {
		env.Substrate = &DigestRef{}
		if err := json.Unmarshal(r, env.Substrate); err != nil {
			codes = appendCode(codes, CodeStatementMalformed)
			env.Substrate = nil
		}
	}
	if r, ok := env.Raw["corpus"]; ok {
		env.Corpus = &Corpus{}
		if err := json.Unmarshal(r, env.Corpus); err != nil {
			codes = appendCode(codes, CodeStatementMalformed)
			env.Corpus = nil
		} else if len(env.Corpus.ManifestRaw) > 0 {
			var manifest struct {
				Classes map[string][]string `json:"classes"`
			}
			if err := json.Unmarshal(env.Corpus.ManifestRaw, &manifest); err != nil {
				codes = appendCode(codes, CodeStatementMalformed)
			} else {
				env.Corpus.Classes = manifest.Classes
			}
		}
	}
	if r, ok := env.Raw["catchPolicy"]; ok {
		env.CatchPolicy = &DigestRef{}
		if err := json.Unmarshal(r, env.CatchPolicy); err != nil {
			codes = appendCode(codes, CodeStatementMalformed)
			env.CatchPolicy = nil
		}
	}
	if r, ok := env.Raw["networkPosture"]; ok {
		env.NetworkPosture = &NetworkPosture{}
		if err := json.Unmarshal(r, env.NetworkPosture); err != nil {
			codes = appendCode(codes, CodeStatementMalformed)
			env.NetworkPosture = nil
		}
	}
	if r, ok := env.Raw["observationVocabulary"]; ok {
		voc := &Vocabulary{}
		var members map[string]json.RawMessage
		if err := json.Unmarshal(r, &members); err != nil {
			codes = appendCode(codes, CodeStatementMalformed)
		} else {
			if err := json.Unmarshal(r, voc); err != nil {
				codes = appendCode(codes, CodeStatementMalformed)
			} else {
				_, voc.LabelsPresent = members["labels"]
				_, voc.CaughtPresent = members["caught"]
				env.Vocabulary = voc
			}
		}
	}
	if r, ok := env.Raw["runEntropy"]; ok {
		env.RunEntropy = &DigestRef{}
		if err := json.Unmarshal(r, env.RunEntropy); err != nil {
			codes = appendCode(codes, CodeStatementMalformed)
			env.RunEntropy = nil
		}
	}
	return env, codes
}

func parseRow(raw json.RawMessage) (Row, []Code) {
	var codes []Code
	row := Row{}
	if err := json.Unmarshal(raw, &row.Raw); err != nil {
		return row, appendCode(codes, CodeStatementMalformed)
	}

	decodeString := func(key string) *string {
		r, ok := row.Raw[key]
		if !ok {
			return nil
		}
		var v string
		if err := json.Unmarshal(r, &v); err != nil {
			codes = appendCode(codes, CodeStatementMalformed)
			return nil
		}
		return &v
	}

	if v := decodeString("attackId"); v != nil {
		row.AttackID = *v
	}
	if v := decodeString("containmentObserved"); v != nil {
		row.ContainmentObserved = *v
	}
	row.Basis = decodeString("basis")
	row.Method = decodeString("method")
	row.ActualLayer = decodeString("actualLayer")

	if refsRaw, ok := row.Raw["observationRefs"]; ok {
		row.RefsPresent = true
		if err := json.Unmarshal(refsRaw, &row.RefsRaw); err != nil {
			row.RefsErr = errors.New("observationRefs is not an array")
		} else {
			for _, el := range row.RefsRaw {
				idx, err := decodeRefIndex(el)
				if err != nil {
					row.RefsErr = err
					break
				}
				row.Refs = append(row.Refs, idx)
			}
		}
	}
	return row, codes
}

// decodeRefIndex enforces that an observationRefs entry is a non-negative
// JSON integer. Non-integer and negative entries are ref-malformed.
func decodeRefIndex(raw json.RawMessage) (int, error) {
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, fmt.Errorf("ref is not a number: %s", string(raw))
	}
	i, err := n.Int64()
	if err != nil || string(n) != fmt.Sprintf("%d", i) {
		return 0, fmt.Errorf("ref is not an integer: %s", string(n))
	}
	if i < 0 {
		return 0, fmt.Errorf("ref is negative: %d", i)
	}
	return int(i), nil
}
