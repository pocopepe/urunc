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

package hypervisors

import (
	"strconv"
	"testing"

	"github.com/urunc-dev/urunc/tests/fuzzing/known"
)

// FuzzBytesToStringMB checks the OCI-to-VMM memory conversion contract:
// callers such as qemu.go, hvt.go, spt.go and cloud_hypervisor.go embed the
// returned string directly into a VMM memory argument that is interpreted as
// binary MiB. The guest must therefore never end up with more memory than
// the OCI byte limit allowed.
func FuzzBytesToStringMB(f *testing.F) {
	// Seeds stay on the passing side of the boundary on purpose: the engine
	// has to reach the failing region by mutation rather than being handed a
	// reproducer, so a finding here is a genuine discovery.
	seeds := []uint64{
		0, 1, 999_999, 1_000_000, 1_048_576,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, argMem uint64) {
		got := BytesToStringMB(argMem)

		userMiB, err := strconv.ParseUint(got, 10, 64)
		if err != nil {
			t.Fatalf("BytesToStringMB(%d) returned non-numeric value %q: %v", argMem, got, err)
		}

		if argMem == 0 || argMem < 1_048_576 {
			// argMem == 0: explicit "use the default" path.
			// argMem < 1MiB: bytesToMiB truncates to 0 and BytesToStringMB
			// deliberately falls back to DefaultMemory (see urunc-dev/urunc#819
			// for the open discussion on whether sub-1MiB values should be
			// allowed at all) -- not the overshoot bug this fuzz target isolates.
			return
		}

		effectiveBytes := userMiB * 1024 * 1024
		if effectiveBytes <= argMem {
			return
		}

		// --- SUPPRESSION of the already-filed finding 7 (urunc-dev/urunc#818) --
		// FIXED. BytesToStringMB now converts with bytesToMiB, matching the
		// resolution the maintainer agreed to on #818 ("Ok, then we can use
		// MiB for all of them"). solo5_test.go's "custom MemSizeB renders
		// --mem in MiB" case was updated to match rather than being evidence
		// against the fix -- an earlier revision of this comment cited it as
		// a conflicting, maintainer-reviewed test, which was a misreading: it
		// tested decimal input/output pairs because the code was decimal, not
		// because decimal was the intended contract.
		//
		// With both sides of the property now using the same MiB truncation,
		// effectiveBytes <= argMem holds unconditionally, so the "return"
		// above this block fires on every input and this suppression is
		// unreachable. That is the expected, permanent state post-fix, and
		// exactly the "zero hits" signal section 8 of FUZZING_FINDINGS.md
		// describes as proof a suppressed finding was actually fixed --
		// verified directly: Fired()["finding-7"] is 0.
		//
		// Left in place as a regression guard, not deleted: if the overshoot
		// ever reappears (a future edit reverts to bytesToMB, or a new
		// backend introduces its own decimal conversion), this fires again
		// and the shape predicate below still isolates the exact known
		// arithmetic from a different, new defect.
		decimalMB := argMem / 1_000_000
		known.Expected(t, "finding-7", userMiB == decimalMB,
			"BytesToStringMB(%d) = %q MiB -> %d bytes once the VMM interprets it "+
				"as MiB, which exceeds the requested OCI memory limit of %d bytes "+
				"(overshoot: %d bytes). This is NOT the decimal-conversion shape of "+
				"urunc-dev/urunc#818, which would have returned %d.",
			argMem, got, effectiveBytes, argMem, effectiveBytes-argMem, decimalMB)
	})
}
