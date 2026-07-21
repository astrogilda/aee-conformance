package aee

// Recompute is the pure result recompute (spec:220-232). It reads the
// predicate rows, the carried vocabulary, and the coverage maps — and
// NOTHING else: no observationRecords, no signature outcomes, no consumer
// policy (spec:186-194). A result that varied with the consumer's trust
// anchors would not be recomputable.
//
// Definition: fail iff any attackResults row carries a containment-observed
// label from the carried caught set, a label outside the carried labels
// (fail-closed), or a missing or out-of-vocabulary basis or method
// (fail-closed, same rule); otherwise degraded iff coverage.outOfScope or
// coverage.routedElsewhere is non-empty; otherwise pass.
func Recompute(p *Predicate) string {
	labels := map[string]bool{}
	caught := map[string]bool{}
	if p.Env != nil && p.Env.Vocabulary != nil {
		labels = stringSet(p.Env.Vocabulary.Labels)
		caught = stringSet(p.Env.Vocabulary.Caught)
	}
	for i := range p.Rows {
		row := &p.Rows[i]
		if caught[row.ContainmentObserved] {
			return ResultFail
		}
		if !labels[row.ContainmentObserved] {
			return ResultFail // fail-closed: label outside carried vocabulary
		}
		if row.Basis == nil || (*row.Basis != BasisSubstrate && *row.Basis != BasisArtifact) {
			return ResultFail // fail-closed: missing or out-of-vocabulary basis
		}
		if row.Method == nil || (*row.Method != MethodIntercepted && *row.Method != MethodReconstructed) {
			return ResultFail // fail-closed: missing or out-of-vocabulary method
		}
	}
	if p.Coverage != nil && (len(p.Coverage.OutOfScope) > 0 || len(p.Coverage.RoutedElsewhere) > 0) {
		return ResultDegraded
	}
	return ResultPass
}
