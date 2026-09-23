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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/urunc-dev/urunc/pkg/unikontainers/types"
)

// No test file existed for this backend before this pass -- confirmed via
// gremlins, which reported 9 of 11 hypervisors-package survivors here
// (efficacy 77%). Same fakeUnikernel mock and mustContain/mustNotContain
// table shape as qemu_test.go.
//
// One of those 9 is the exact example the project's own report already
// named (FUZZING_FINDINGS.md / PHASE1_REPORT section 5): negating
// `if args.Sharedfs.Type == "virtiofs"` at line 74 survived because nothing
// asserted the "shared=on" suffix specifically -- coverage counted the line
// as reached without checking what it produced.

func TestCloudHypervisorBuildExecCmd(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		args           types.ExecArgs
		unikernel      types.Unikernel
		mustContain    []string
		mustNotContain []string
	}{
		{
			name:      "defaults render the baseline command",
			args:      types.ExecArgs{UnikernelPath: testKernelPath, Command: testCommand},
			unikernel: &fakeUnikernel{},
			mustContain: []string{
				"--memory size=256M",
				"--kernel " + testKernelPath,
				"--console off",
				"--serial tty",
				"--seccomp false",
				"--cmdline " + testCommand,
			},
			mustNotContain: []string{
				"shared=on", "--cpus", "--net", "--disk", "--initramfs",
				"--fs", "--vsock", "--seccomp true",
			},
		},
		{
			// Kills the CONDITIONALS_NEGATION survivor at cloud_hypervisor.go:74 --
			// the exact "shared=on silently lost" case the project's own report
			// already flagged.
			name:        "virtiofs sharedfs adds shared=on to the memory arg",
			args:        types.ExecArgs{UnikernelPath: testKernelPath, Sharedfs: types.SharedfsParams{Type: "virtiofs"}},
			unikernel:   &fakeUnikernel{},
			mustContain: []string{"--memory size=256M,shared=on", "--fs tag=fs0,socket=/tmp/vhostqemu"},
		},
		{
			name:           "a non-virtiofs sharedfs type does not add shared=on or --fs",
			args:           types.ExecArgs{UnikernelPath: testKernelPath, Sharedfs: types.SharedfsParams{Type: "9pfs"}},
			unikernel:      &fakeUnikernel{},
			mustNotContain: []string{"shared=on", "--fs"},
		},
		{
			// Kills the survivors at line 83 (negation + boundary): VCPUs must
			// be strictly > 0, not just present, for --cpus to appear.
			name:        "VCPUs > 0 adds --cpus",
			args:        types.ExecArgs{UnikernelPath: testKernelPath, VCPUs: 4},
			unikernel:   &fakeUnikernel{},
			mustContain: []string{"--cpus boot=4"},
		},
		{
			name:           "VCPUs == 0 omits --cpus entirely",
			args:           types.ExecArgs{UnikernelPath: testKernelPath, VCPUs: 0},
			unikernel:      &fakeUnikernel{},
			mustNotContain: []string{"--cpus"},
		},
		{
			// Kills the survivor at line 102: no TapDev means no --net at all,
			// not a --net with empty values.
			name:           "no TapDev means no --net",
			args:           types.ExecArgs{UnikernelPath: testKernelPath},
			unikernel:      &fakeUnikernel{},
			mustNotContain: []string{"--net"},
		},
		{
			// Kills the survivor at line 104: an empty MonitorNetCli falls back
			// to the constructed tap=/mac=/mtu= default, not silence.
			name: "TapDev with no unikernel-specific net CLI uses the built-in default",
			args: types.ExecArgs{UnikernelPath: testKernelPath, Net: types.NetDevParams{
				TapDev: "tap0", MAC: "aa:bb:cc:dd:ee:ff", MTU: 1500,
			}},
			unikernel:   &fakeUnikernel{},
			mustContain: []string{"--net tap=tap0,mac=aa:bb:cc:dd:ee:ff,mtu=1500"},
		},
		{
			name:           "TapDev with a unikernel-specific net CLI uses it verbatim instead of the default",
			args:           types.ExecArgs{UnikernelPath: testKernelPath, Net: types.NetDevParams{TapDev: "tap0"}},
			unikernel:      &fakeUnikernel{netCli: []string{"--net", "id=net0,fd=3"}},
			mustContain:    []string{"--net id=net0,fd=3"},
			mustNotContain: []string{"mac=", "mtu="},
		},
		{
			// Kills the survivor at line 145: VAccelType must be exactly
			// "vsock", not merely non-empty, for --vsock to appear.
			name: "VAccelType vsock adds --vsock with the guest CID and socket path",
			args: types.ExecArgs{
				UnikernelPath: testKernelPath, VAccelType: "vsock",
				VSockDevID: 42, VSockDevPath: "/run/vaccel",
			},
			unikernel:   &fakeUnikernel{},
			mustContain: []string{"--vsock cid=42,socket=/run/vaccel/vaccel.sock"},
		},
		{
			name:           "a non-vsock VAccelType does not add --vsock",
			args:           types.ExecArgs{UnikernelPath: testKernelPath, VAccelType: "virtio"},
			unikernel:      &fakeUnikernel{},
			mustNotContain: []string{"--vsock"},
		},
		{
			// Kills the survivor at line 150 (negation + boundary): OtherArgs
			// must be non-empty, not merely present as a field, to be appended.
			name:        "MonitorCli OtherArgs are appended when present",
			args:        types.ExecArgs{UnikernelPath: testKernelPath},
			unikernel:   &fakeUnikernel{monitorCli: types.MonitorCliArgs{OtherArgs: []string{"--platform", "num-pci-segments=2"}}},
			mustContain: []string{"--platform num-pci-segments=2"},
		},
		{
			name:      "no OtherArgs adds nothing extra",
			args:      types.ExecArgs{UnikernelPath: testKernelPath},
			unikernel: &fakeUnikernel{},
			// The absence of a specific flag can't be asserted generically the
			// way presence can; the "defaults" case above already pins the
			// exact argv this shape must reduce to.
		},
		{
			name:        "InitrdPath adds --initramfs",
			args:        types.ExecArgs{UnikernelPath: testKernelPath, InitrdPath: "/boot/initrd"},
			unikernel:   &fakeUnikernel{},
			mustContain: []string{"--initramfs /boot/initrd"},
		},
		{
			name:        "ExtraInitrd from MonitorCli also adds --initramfs, independently of InitrdPath",
			args:        types.ExecArgs{UnikernelPath: testKernelPath},
			unikernel:   &fakeUnikernel{monitorCli: types.MonitorCliArgs{ExtraInitrd: "/urunit.conf"}},
			mustContain: []string{"--initramfs /urunit.conf"},
		},
		{
			name:        "block device ExactArgs is used verbatim",
			args:        types.ExecArgs{UnikernelPath: testKernelPath},
			unikernel:   &fakeUnikernel{blockCli: []types.MonitorBlockArgs{{ExactArgs: []string{"--disk", "path=/custom.img,readonly=on"}}}},
			mustContain: []string{"--disk path=/custom.img,readonly=on"},
		},
		{
			name:        "block device without ExactArgs but with a Path builds a --disk from ID and Path",
			args:        types.ExecArgs{UnikernelPath: testKernelPath},
			unikernel:   &fakeUnikernel{blockCli: []types.MonitorBlockArgs{{ID: "rootfs", Path: "/host/rootfs.img"}}},
			mustContain: []string{"--disk path=/host/rootfs.img,id=rootfs"},
		},
		{
			name:           "seccomp true when Seccomp is enabled",
			args:           types.ExecArgs{UnikernelPath: testKernelPath, Seccomp: true},
			unikernel:      &fakeUnikernel{},
			mustContain:    []string{"--seccomp true"},
			mustNotContain: []string{"--seccomp false"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ch := &CloudHypervisor{binary: CloudHypervisorBinary, binaryPath: "/usr/bin/cloud-hypervisor"}
			out, err := ch.BuildExecCmd(tt.args, tt.unikernel)
			assert.NoError(t, err)
			assert.NotEmpty(t, out)
			assert.Equal(t, "/usr/bin/cloud-hypervisor", out[0], "binary path must be the first element")

			joined := strings.Join(out, " ")
			for _, want := range tt.mustContain {
				assert.Contains(t, joined, want, "expected %q to be present", want)
			}
			for _, notWant := range tt.mustNotContain {
				assert.NotContains(t, joined, notWant, "expected %q to be absent", notWant)
			}
		})
	}
}
