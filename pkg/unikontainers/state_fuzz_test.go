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

package unikontainers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	fuzzheaders "github.com/AdaLogics/go-fuzz-headers"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// State persistence is urunc's most-reused trust boundary: `create` writes
// state.json once, and every later command (start, exec, kill, delete, ps)
// reconstructs the container from it (issue #852).
//
// FuzzUruncConfigMapRoundTrip / FuzzUruncConfigFromMap already found two bugs
// here, but only as a pure in-memory map round trip -- they never touch
// saveContainerState, the real file, or the Spec->State annotation merge. This
// target uses the REAL saveContainerState/loadUnikontainerState (not mirrors,
// unlike finding 12's harness, which had to hand-mirror getMountInfo and paid
// for it with 0.0% coverage), so it is slower than the in-memory targets --
// accepted because the property under test is the write-then-read cycle
// itself.
func FuzzStatePersistenceRoundTrip(f *testing.F) {
	f.Add([]byte("urunc-state-seed"))
	f.Add([]byte("com.urunc.unikernel.binary"))

	f.Fuzz(func(t *testing.T, data []byte) {
		c := fuzzheaders.NewConsumer(data)

		specAnnots := map[string]string{}
		stateAnnots := map[string]string{}
		if err := c.FuzzMap(&specAnnots); err != nil {
			return
		}
		if err := c.FuzzMap(&stateAnnots); err != nil {
			return
		}

		// Force OVERLAP between the two annotation maps. Without it, P1's
		// merge-precedence check below is dead code -- FuzzMap generates the
		// maps independently, so a shared key is vanishingly unlikely and the
		// "state value must win" branch never runs. Mutation testing caught
		// exactly that: changing saveContainerState's "skip if present" guard
		// to an unconditional overwrite was missed by this target for that
		// reason. Overlap is the realistic case too -- it's why the guard
		// exists (nerdctl issue 133).
		for k, v := range specAnnots {
			if _, exists := stateAnnots[k]; !exists {
				// A distinct value, so "which one won" is observable.
				stateAnnots[k] = v + "-state"
			}
			break // one shared key is enough to exercise the branch
		}

		// json.Marshal silently substitutes U+FFFD for invalid UTF-8 (documented
		// stdlib behaviour, not urunc-specific). Filtered out here since it
		// would fire on nearly every mutation and bury the properties below.
		for k, v := range specAnnots {
			if !utf8.ValidString(k) || !utf8.ValidString(v) {
				return
			}
		}
		for k, v := range stateAnnots {
			if !utf8.ValidString(k) || !utf8.ValidString(v) {
				return
			}
		}
		// NOT t.TempDir(). t.TempDir() registers its cleanup on the *testing.T
		// and only removes the directory when the TEST ends -- which, for a
		// fuzz target, is the end of the whole 30-minute run, not the end of
		// this iteration. Measured consequence when this harness first used
		// it: directories accumulated at several thousand per second and the
		// exec rate decayed monotonically (1789/sec -> 242 -> 87 -> 24 -> 5
		// -> 0) until the worker died with "fuzzing process hung or
		// terminated unexpectedly: exit status 2" after ~3 minutes.
		//
		// MkdirTemp + an explicit per-iteration RemoveAll keeps the working
		// set at exactly one directory, so the rate stays flat.
		baseDir, err := os.MkdirTemp("", "urunc-state-fuzz-")
		if err != nil {
			t.Skipf("harness setup failed (not a finding): %v", err)
		}
		defer os.RemoveAll(baseDir)

		// saveContainerState mutates u.State.Annotations in place as part of
		// the merge, so snapshot the caller's pre-save view first.
		preState := make(map[string]string, len(stateAnnots))
		for k, v := range stateAnnots {
			preState[k] = v
		}

		u := &Unikontainer{
			BaseDir: baseDir,
			State: &specs.State{
				Version:     "1.0.2",
				ID:          "fuzz-container",
				Status:      "created",
				Bundle:      "/bundle",
				Annotations: stateAnnots,
			},
			Spec: &specs.Spec{
				Annotations: specAnnots,
			},
		}

		if err := u.saveContainerState(); err != nil {
			return // host or marshal failure, not the property under test
		}

		reloaded, err := loadUnikontainerState(filepath.Join(baseDir, stateFilename))
		if err != nil {
			t.Fatalf("state.json written by saveContainerState could not be read back by "+
				"loadUnikontainerState: %v", err)
		}
		if reloaded.Annotations == nil && len(preState) > 0 {
			t.Fatalf("state.json round trip produced nil annotations from a state that had %d",
				len(preState))
		}

		// P1: saveContainerState copies spec annotations into state only where
		// the key is absent, so a key in both must keep the state value, and
		// every spec key must end up present.
		for k, specVal := range specAnnots {
			got, ok := reloaded.Annotations[k]
			if !ok {
				t.Fatalf("annotation %q was in Spec.Annotations but is missing from the "+
					"reloaded state; saveContainerState propagates all spec annotations "+
					"into state on purpose (nerdctl issue 133)", k)
			}
			if stateVal, inBoth := preState[k]; inBoth {
				if got != stateVal {
					t.Fatalf("annotation %q is in BOTH Spec and State: the state value %q must "+
						"win, but the reloaded state has %q (spec value was %q)",
						k, stateVal, got, specVal)
				}
			} else if got != specVal {
				t.Fatalf("annotation %q came only from Spec with value %q but reloaded as %q",
					k, specVal, got)
			}
		}

		// P2: nothing the state already carried may be lost.
		for k, want := range preState {
			got, ok := reloaded.Annotations[k]
			if !ok {
				t.Fatalf("annotation %q was in State.Annotations before save but is absent "+
					"after the state.json round trip", k)
			}
			if got != want {
				t.Fatalf("annotation %q changed across the state.json round trip:\n"+
					"  before: %q\n  after:  %q", k, want, got)
			}
		}

		// P3 used to assert that the nested rootfsParams JSON blob survived the
		// round trip. Upstream 854b413 ("refactor: Select the rootfs in the
		// create step instead of Exec") moved rootfs selection into create and
		// deleted the annotRootfsParams annotation, so that blob is no longer
		// stored in state.json and there is nothing left to round-trip.

		// P4: the config urunc rebuilds from the reloaded state must match --
		// generalises findings 5/6 from an in-memory map to the real file.
		// Monitor names containing "." are skipped: that's finding 5 already,
		// and letting it re-fire here would double-count one known defect.
		for k := range reloaded.Annotations {
			if strings.HasPrefix(k, "urunc_config.monitors.") &&
				len(strings.Split(k, ".")) != 4 {
				return
			}
		}

		fromReloaded := UruncConfigFromMap(reloaded.Annotations)
		fromDirect := UruncConfigFromMap(preState)
		if fromReloaded == nil || fromDirect == nil {
			return
		}
		for name, want := range fromDirect.Monitors {
			got, ok := fromReloaded.Monitors[name]
			if !ok {
				t.Fatalf("monitor %q survives UruncConfigFromMap when read straight from the "+
					"in-memory map, but is gone once the same annotations make a real "+
					"state.json round trip", name)
			}
			if got != want {
				t.Fatalf("monitor %q differs depending on whether the annotations went through "+
					"a real state.json round trip:\n  direct:   %+v\n  via file: %+v",
					name, want, got)
			}
		}
	})
}
