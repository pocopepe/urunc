// Copyright (c) 2023-2026, Nubificus LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package known provides suppression for already-catalogued findings so a
// fuzz target that has found a bug can keep searching past it.
//
// # Why this package exists
//
// Go's fuzzing engine has no concept of a known issue. Per the testing docs:
//
//	"When fuzzing, F.Fuzz does not return until a problem is found..."
//	"If ff fails for a set of arguments, those arguments will be added to
//	 the seed corpus."
//
// So the first time an oracle fires, the engine (a) stops immediately and
// (b) persists the failing input as a SEED, which means every later run dies
// during baseline before fuzzing even begins. Quarantining the seed file does
// not fix it either: for a defect that fires on a large fraction of the input
// space, mutation regenerates a fresh failing input within milliseconds.
//
// Measured on this project before this package existed: 11 of 35 targets were
// in this state, several for 20+ consecutive rounds, each contributing
// literally zero executions while still consuming a 30-minute slot.
//
// ClusterFuzz solves this by filing the crash to a bug tracker and carrying
// on. This package is the local equivalent, and it is the direct analogue of
// the suppression files real sanitizers ship (ASan's asan_ignorelist.txt).
//
// # The safety property that makes this sound
//
// A blanket "ignore failures from this target" would be worse than useless --
// it would silently mask NEW defects behind an already-known one. So
// Expected() takes a shapeOK predicate that must be true ONLY for the exact
// catalogued defect. A violation at a known site whose shape does not match
// is treated as a new finding and fails loudly.
//
// In other words the oracle is not weakened, it is made MORE specific: from
// "this property must hold" to "this property must hold, except for the one
// precisely-characterised way it is already known to fail".
package known

import (
	"fmt"
	"os"
	"sync"
)

// TB is the subset of *testing.T that Expected needs. It exists so this
// package builds under OSS-Fuzz/ClusterFuzzLite's Go pipeline too: that
// pipeline rewrites f.Fuzz(func(t *testing.T, ...)) to hand the closure
// AdamKorcz/go-118-fuzz-build's own *testing.T look-alike instead of the
// standard library's, and the two are different concrete types. Both satisfy
// this interface, so callers pass either one unchanged.
type TB interface {
	Helper()
	Fatalf(format string, args ...any)
}

// hits records which suppressions actually fired in this process, so a
// suppression that has gone stale (because the underlying bug was fixed, or
// its shape changed) can be detected rather than silently lingering forever.
var (
	mu   sync.Mutex
	hits = map[string]int{}
)

// Expected reports a property violation that is already catalogued in
// FUZZING_FINDINGS.md, allowing the fuzzing engine to continue past it.
//
//	id      -- stable identifier, conventionally the finding number
//	          ("finding-10"), used for staleness reporting.
//	shapeOK -- MUST be true only for the exact known defect. If false, the
//	          violation is a different bug and Expected fails the test.
//	format/args -- describes the violation, used only when shapeOK is false.
//
// Callers must have already established that a violation occurred; Expected
// does not evaluate the property itself.
func Expected(t TB, id string, shapeOK bool, format string, args ...any) {
	t.Helper()

	if !shapeOK {
		t.Fatalf("NEW defect at the site of catalogued %s -- the property was violated "+
			"in a way that does NOT match the known shape, so this is not the "+
			"already-reported bug:\n%s", id, fmt.Sprintf(format, args...))
		return
	}

	mu.Lock()
	hits[id]++
	mu.Unlock()
}

// Fired reports how many times each suppression triggered in this process.
// A suppression with zero hits across a full campaign round is a signal that
// the underlying defect may have been fixed, and that the suppression (and
// the finding it refers to) should be re-verified rather than trusted.
func Fired() map[string]int {
	mu.Lock()
	defer mu.Unlock()
	out := make(map[string]int, len(hits))
	for k, v := range hits {
		out[k] = v
	}
	return out
}

// ReportTo writes the suppression hit counts to path, one "id count" per
// line. Intended to be called from TestMain so scripts/fuzz_runner.sh can
// surface stale suppressions.
func ReportTo(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for id, n := range Fired() {
		if _, err := fmt.Fprintf(f, "%s %d\n", id, n); err != nil {
			return err
		}
	}
	return nil
}
