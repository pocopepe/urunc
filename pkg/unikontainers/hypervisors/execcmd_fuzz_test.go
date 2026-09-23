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
	"github.com/urunc-dev/urunc/pkg/unikontainers/types"
)

// execCmdVMMs are every backend BuildExecCmd builds an argv for. Shared by
// execcmd_differential_fuzz_test.go.
// firecracker.go is excluded: its BuildExecCmd writes a JSON config to disk on
// every call, and per-iteration file I/O is a documented fuzz anti-pattern.
// hedge.go is excluded: BuildExecCmd is a stub that unconditionally returns
// "hedge not implemented yet" -- nothing to fuzz.
// hyperlight.go was missing from this map with no exclusion comment, unlike
// firecracker/hedge above -- its BuildExecCmd does no I/O and returns a real
// argv, so there was no structural reason to leave it out. Added.
func execCmdVMMs() map[string]types.VMM {
	return map[string]types.VMM{
		"hvt":              &HVT{binary: HvtBinary, binaryPath: "/usr/bin/" + HvtBinary},
		"spt":              &SPT{binary: SptBinary, binaryPath: "/usr/bin/" + SptBinary},
		"qemu":             &Qemu{binary: QemuBinary, binaryPath: "/usr/bin/" + QemuBinary},
		"cloud-hypervisor": &CloudHypervisor{binary: CloudHypervisorBinary, binaryPath: "/usr/bin/" + CloudHypervisorBinary},
		"hyperlight":       &Hyperlight{binary: HyperlightBinary, binaryPath: "/usr/bin/" + HyperlightBinary},
	}
}

// FuzzBuildExecCmd (the original empty-argv-element crash-only check) was
// retired: FuzzBuildExecCmdMemoryAgreement and FuzzBuildExecCmdCommandAgreement
// (execcmd_differential_fuzz_test.go) drive the exact same function with a
// differential oracle and found the two real bugs (F0/#818, F1) this target's
// weaker oracle drove straight past without noticing. Its own finding-19
// suppression (empty UnikernelPath) is also moot -- see
// FUZZING_FINDINGS.md section 3: validate() hard-fails container creation on
// an empty UnikernelBinary, so BuildExecCmd never actually sees one.
