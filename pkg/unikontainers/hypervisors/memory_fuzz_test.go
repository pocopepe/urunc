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
)

// FuzzBytesToStringMB checks the OCI-to-VMM memory conversion contract:
// callers such as qemu.go, hvt.go, spt.go and cloud_hypervisor.go embed the
// returned string directly into a VMM memory argument that is interpreted as
// binary MiB. The guest must therefore never end up with more memory than
// the OCI byte limit allowed.
func FuzzBytesToStringMB(f *testing.F) {
	seeds := []uint64{
		0, 1, 999_999, 1_000_000, 1_048_576,
		256_000_000,                      // exact value reported in urunc-dev/urunc#818
		2_000_000, 4_000_000, 75_000_000, // range reported in urunc-dev/urunc#820
		1 << 32, 1 << 40,
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
		if effectiveBytes > argMem {
			t.Errorf("BytesToStringMB(%d) = %q MiB -> %d bytes once the VMM "+
				"interprets it as MiB, which exceeds the requested OCI memory "+
				"limit of %d bytes (overshoot: %d bytes)",
				argMem, got, effectiveBytes, argMem, effectiveBytes-argMem)
		}
	})
}
