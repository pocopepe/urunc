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
	"strings"
	"testing"

	"github.com/urunc-dev/urunc/pkg/unikontainers/types"
	"github.com/urunc-dev/urunc/pkg/unikontainers/unikernels"
	"github.com/urunc-dev/urunc/tests/fuzzing/known"
)

// Cross-backend semantic differentials for BuildExecCmd.
//
// There are five independent implementations of one logical operation: "turn
// ExecArgs into a monitor command line". That is the ideal shape for a
// differential oracle -- the test does not need to encode what the correct
// answer is, only that five implementations of the same contract must agree.
//
// The pre-existing FuzzBuildExecCmd asserts only that no argv element is
// empty. That oracle is too weak: it drove this exact code for a full 60s
// campaign at 4 cores without noticing either of the divergences below.
// Coverage was never the limiting factor; the assertion was. See
// tests/fuzzing/FUZZING_FINDINGS.md section 6, rule 4.

// diffExecCmdVMMs is execCmdVMMs (execcmd_fuzz_test.go), duplicated here
// rather than called across files. OSS-Fuzz/ClusterFuzzLite's Go build
// (go-118-fuzz-build) packages one target's containing file in isolation, so
// a helper defined in a sibling _test.go file is invisible to the generated
// harness ("undefined: execCmdVMMs"), confirmed by an actual local build.
// Keep the two in sync by hand if the VMM set changes.
func diffExecCmdVMMs() map[string]types.VMM {
	return map[string]types.VMM{
		"hvt":              &HVT{binary: HvtBinary, binaryPath: "/usr/bin/" + HvtBinary},
		"spt":              &SPT{binary: SptBinary, binaryPath: "/usr/bin/" + SptBinary},
		"qemu":             &Qemu{binary: QemuBinary, binaryPath: "/usr/bin/" + QemuBinary},
		"cloud-hypervisor": &CloudHypervisor{binary: CloudHypervisorBinary, binaryPath: "/usr/bin/" + CloudHypervisorBinary},
		"hyperlight":       &Hyperlight{binary: HyperlightBinary, binaryPath: "/usr/bin/" + HyperlightBinary},
	}
}

// memEncoding describes how one backend writes guest memory into its argv, so
// the value can be read back out and compared in bytes.
//
// These mirror the production encoders; if a backend changes how it emits
// memory, the matching entry here must be updated or it silently stops being
// faithful.
//
// Units are NOT a matter of opinion here: urunc-dev/urunc#818 established, with
// the Solo5 source as evidence, that qemu, cloud-hypervisor, spt and hvt all
// interpret their memory argument as binary MiB. Maintainer cmainas concluded
// the thread with "Ok, then we can use MiB for all of them."
const mib = uint64(1024 * 1024)

// extractMemBytes returns the guest memory, in bytes, that a backend's argv
// actually requests -- or ok=false if this helper does not model that backend.
func extractMemBytes(vmm string, argv []string) (uint64, bool) {
	atoiMiB := func(s string) (uint64, bool) {
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return 0, false
		}
		return n * mib, true
	}

	switch vmm {
	case "qemu":
		// "-m", "<N>M"
		for i := 0; i+1 < len(argv); i++ {
			if argv[i] == "-m" {
				return atoiMiB(strings.TrimSuffix(argv[i+1], "M"))
			}
		}
	case "cloud-hypervisor":
		// "--memory", "size=<N>M[,shared=on]"
		for i := 0; i+1 < len(argv); i++ {
			if argv[i] == "--memory" {
				v := argv[i+1]
				v = strings.TrimPrefix(v, "size=")
				if c := strings.IndexByte(v, ','); c >= 0 {
					v = v[:c]
				}
				return atoiMiB(strings.TrimSuffix(v, "M"))
			}
		}
	case "spt", "hvt":
		// a single "--mem=<N>" element
		for _, a := range argv {
			if strings.HasPrefix(a, "--mem=") {
				return atoiMiB(strings.TrimPrefix(a, "--mem="))
			}
		}
	}
	// hyperlight is deliberately NOT modelled: hyperlight.go:70-72 emits
	// "--memory <raw bytes>" with no unit conversion whatsoever, a third
	// convention distinct from both bytesToMiB (firecracker) and bytesToMB
	// (everyone else). Whether hyperlight's CLI expects bytes or MiB was not
	// verifiable from this repo, so asserting either way would be a guess.
	// Recorded as an open question in FUZZING_FINDINGS.md rather than encoded
	// as a expectation here.
	//
	// firecracker is absent from diffExecCmdVMMs() entirely (it writes a JSON
	// config to disk per call -- per-iteration file I/O is a fuzz anti-pattern).
	return 0, false
}

// FuzzBuildExecCmdMemoryAgreement checks that the guest memory each backend
// requests round-trips to the OCI byte limit it was given.
//
// Property: for a backend whose memory argument is binary MiB, the value it
// emits, multiplied back up, must equal MemSizeB truncated to whole MiB. Any
// other result means the container gets a different amount of RAM than the OCI
// spec asked for.
//
// This reproduced finding F0 (#818) directly while BytesToStringMB divided
// by 1,000,000 (decimal MB) and the result was read as binary MiB, causing
// every backend in this group to over-allocate by ~4.86%. Fixed: it now
// divides by bytesToMiB, matching every consumer's actual unit.
func FuzzBuildExecCmdMemoryAgreement(f *testing.F) {
	f.Add(uint64(256*1024*1024), uint64(1))
	f.Add(uint64(1024*1024*1024), uint64(2))
	f.Add(uint64(512*1000*1000), uint64(1))

	f.Fuzz(func(t *testing.T, memSizeB, vcpus uint64) {
		// Input realism: a container memory limit comes from
		// spec.Linux.Resources.Memory.Limit, an int64 required to be > 0, and
		// BytesToStringMB substitutes DefaultMemory below 1 unit. Stay inside
		// the range where a real limit lives, so the oracle tests the
		// conversion rather than the fallback.
		if memSizeB < mib || memSizeB > (1<<42) {
			return
		}
		if vcpus == 0 || vcpus > 256 {
			return
		}

		params := types.UnikernelParams{CmdLine: []string{"/init"}}
		execArgs := types.ExecArgs{
			MemSizeB:      memSizeB,
			VCPUs:         uint(vcpus),
			UnikernelPath: "/unikernel/app",
			Command:       "console=ttyS0",
		}

		u, err := unikernels.New(unikernels.LinuxUnikernel)
		if err != nil {
			return
		}
		if err := u.Init(params); err != nil {
			return
		}

		wantMiB := memSizeB / mib

		for vmmName, vmm := range diffExecCmdVMMs() {
			argv, err := vmm.BuildExecCmd(execArgs, u)
			if err != nil {
				continue
			}
			gotBytes, ok := extractMemBytes(vmmName, argv)
			if !ok {
				continue // backend not modelled (see extractMemBytes)
			}

			if gotBytes != wantMiB*mib {
				// SUPPRESSION of F0 / finding-7 (urunc-dev/urunc#818). FIXED:
				// see memory_fuzz_test.go for the full account. This branch
				// is now unreachable in practice -- BytesToStringMB and this
				// oracle compute the same MiB truncation, so gotBytes and
				// wantMiB*mib always agree. Left as a regression guard.
				//
				// SHAPE (of the retired defect): the decimal conversion always OVER-states memory,
				// because dividing by 1,000,000 yields a larger count than
				// dividing by 1,048,576 and that count is then scaled by the
				// larger binary unit. A backend that UNDER-allocates, or that
				// is off by something other than the decimal/binary ratio, is
				// a different defect and fails loudly.
				overAllocated := gotBytes > wantMiB*mib
				known.Expected(t, "finding-7", overAllocated,
					"%s requests %d bytes of guest memory for an OCI limit of %d "+
						"bytes (expected %d, i.e. %d MiB). The container's cgroup is "+
						"set from the OCI limit, so a guest that uses what it was "+
						"told it has can be OOM-killed by the host.\n  argv: %q",
					vmmName, gotBytes, memSizeB, wantMiB*mib, wantMiB, argv)
				return
			}
		}
	})
}

// FuzzBuildExecCmdCommandAgreement checks that every backend makes the SAME
// choice about how to represent an empty kernel command line.
//
// This reproduces finding F1. An image with no extra kernel arguments is
// ordinary and well-formed -- buildUnikernelCommand returns "" from
// CommandString() with nothing malformed involved. The backends then diverge:
//
//	qemu             append(exArgs, "-append", args.Command)     -> emits -append ""
//	cloud-hypervisor append(exArgs, "--cmdline", args.Command)   -> emits --cmdline ""
//	spt / hvt        if args.Command != "" { append(...) }       -> omits it entirely
//	hyperlight       never references args.Command               -> ignores it
//
// Same trusted input, different guest boot configuration, decided only by which
// monitor the image selected.
//
// Oracle: build twice, once with an empty Command and once with a non-empty
// one, and compare how each backend's argv length reacts. A backend that always
// represents the command line explicitly shows the same delta as every other
// such backend; one that conditionally omits it shows a different delta. The
// backends must not disagree about which strategy they use.
func FuzzBuildExecCmdCommandAgreement(f *testing.F) {
	f.Add("console=ttyS0")
	f.Add("init=/bin/sh")
	f.Add("x")

	f.Fuzz(func(t *testing.T, command string) {
		// The comparison is "empty vs non-empty", so a fuzzer-generated empty
		// string collapses both sides and tests nothing.
		if command == "" {
			return
		}

		params := types.UnikernelParams{CmdLine: []string{"/init"}}
		base := types.ExecArgs{
			MemSizeB:      256 * mib,
			VCPUs:         1,
			UnikernelPath: "/unikernel/app",
		}

		u, err := unikernels.New(unikernels.LinuxUnikernel)
		if err != nil {
			return
		}
		if err := u.Init(params); err != nil {
			return
		}

		// deltas[vmm] = len(argv with Command) - len(argv with Command == "")
		deltas := make(map[string]int)
		for vmmName, vmm := range diffExecCmdVMMs() {
			withEmpty := base
			withEmpty.Command = ""
			argvEmpty, err := vmm.BuildExecCmd(withEmpty, u)
			if err != nil {
				continue
			}

			withCmd := base
			withCmd.Command = command
			argvCmd, err := vmm.BuildExecCmd(withCmd, u)
			if err != nil {
				continue
			}

			deltas[vmmName] = len(argvCmd) - len(argvEmpty)
		}

		// Backends that never reference Command at all (hyperlight) are a
		// separate, documented gap -- not the divergence under test here.
		interesting := make(map[string]int, len(deltas))
		for name, d := range deltas {
			if name == "hyperlight" {
				continue
			}
			interesting[name] = d
		}

		var first string
		for name := range interesting {
			if first == "" || name < first {
				first = name
			}
		}
		if first == "" {
			return
		}

		for name, d := range interesting {
			if d == interesting[first] {
				continue
			}
			// SUPPRESSION of F1. SHAPE: the disagreement is exactly between
			// backends that emit the flag/value pair unconditionally (delta 0,
			// because an empty value still occupies an argv slot) and those
			// that guard on Command != "" (delta 1, the value appears only when
			// non-empty). Any other delta means a backend changed how it
			// represents the command line and is a different defect.
			knownShape := (d == 0 || d == 1) &&
				(interesting[first] == 0 || interesting[first] == 1)
			known.Expected(t, "finding-cmdline-divergence", knownShape,
				"backends disagree on how an empty kernel command line is "+
					"represented: %s changes argv length by %d when Command goes "+
					"from \"\" to %q, but %s changes it by %d. The same image "+
					"boots with a different kernel command line depending only on "+
					"which monitor was selected.\n  all deltas: %v",
				name, d, command, first, interesting[first], deltas)
			return
		}
	})
}
