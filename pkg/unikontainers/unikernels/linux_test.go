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

package unikernels

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/urunc-dev/urunc/pkg/unikontainers/types"
)

// These are content assertions, not crash-only checks -- the gap the report's
// mutation-testing numbers named directly. FuzzUnikernelInit (structaware_fuzz_test.go)
// already proves all six unikernel types survive arbitrary structured input
// without panicking; it deliberately asserts nothing about what CommandString,
// MonitorBlockCli, MonitorCli or MonitorSharedfsCli actually produce. That gap
// is why pkg/unikontainers/unikernels scored 50% mutation efficacy: a mutant
// that changes what a branch produces (not whether it panics) survives an
// oracle that only checks for panics.
//
// Every expected string below was obtained by running the real code and
// reading back its actual output, not hand-computed from reading the source --
// string concatenation is exactly where a hand-computed expectation goes
// subtly wrong, silently baking in the same mistake the production code made.

func TestLinuxCommandString(t *testing.T) {
	cases := []struct {
		name string
		l    Linux
		want string
	}{
		{
			name: "block rootfs, no net, no env, no app",
			l:    Linux{RootFsType: "block"},
			want: "panic=-1 console=ttyS0 root=/dev/vda rw",
		},
		{
			name: "initrd rootfs",
			l:    Linux{RootFsType: "initrd"},
			want: "panic=-1 console=ttyS0 root=/dev/ram0 rw",
		},
		{
			name: "9pfs rootfs",
			l:    Linux{RootFsType: "9pfs"},
			want: "panic=-1 console=ttyS0 root=fs0 rw rootfstype=9p rootflags=trans=virtio,version=9p2000.L,msize=5000000,cache=mmap,posixacl",
		},
		{
			name: "virtiofs rootfs",
			l:    Linux{RootFsType: "virtiofs"},
			want: "panic=-1 console=ttyS0 root=fs0 rw rootfstype=virtiofs",
		},
		{
			// Kills a mutant that turns the RootFsType switch's implicit
			// default (no case matches, nothing added) into a fallthrough or
			// a wrong branch. An unrecognised type must add nothing.
			name: "unrecognised RootFsType adds no root= params",
			l:    Linux{RootFsType: "bogus"},
			want: "panic=-1 console=ttyS0",
		},
		{
			// Kills a mutant that swaps the qemu/arm64 console string, or
			// flips the && to ||, or negates the condition. Only reachable
			// as "not arm64" on this CI/dev architecture (amd64); the
			// console=ttyAMA0 side of runtime.GOARCH=="arm64" is untested
			// here for that reason. Still worth having: on amd64, a mutant
			// that turns "&&" into "||" or flips "==" would make this
			// qemu case wrongly emit ttyAMA0, and this assertion catches
			// that even without arm64 hardware.
			name: "qemu on non-arm64 still gets ttyS0",
			l:    Linux{RootFsType: "block", Monitor: "qemu"},
			want: "panic=-1 console=ttyS0 root=/dev/vda rw",
		},
		{
			name: "network configured, address inside the gateway's subnet",
			l: Linux{RootFsType: "block", Net: LinuxNet{
				Address: "10.0.0.5", Gateway: "10.0.0.1", Mask: "255.0.0.0",
			}},
			want: "panic=-1 console=ttyS0 root=/dev/vda rw ip=10.0.0.5::10.0.0.1:255.0.0.0:urunc:eth0:off",
		},
		{
			// Kills a mutant that negates IsIPInSubnet's result or drops the
			// URUNIT_DEFROUTE append. Address (10.0.0.5) and gateway
			// (192.168.1.1) are deliberately in different /24s.
			name: "network configured, address outside the gateway's subnet adds URUNIT_DEFROUTE",
			l: Linux{RootFsType: "block", Net: LinuxNet{
				Address: "10.0.0.5", Gateway: "192.168.1.1", Mask: "255.255.255.0",
			}},
			want: "panic=-1 console=ttyS0 root=/dev/vda rw ip=10.0.0.5::192.168.1.1:255.255.255.0:urunc:eth0:off URUNIT_DEFROUTE=1",
		},
		{
			// Kills a mutant that drops the env loop or joins with the wrong
			// separator.
			name: "env vars appended raw when not using urunit",
			l:    Linux{RootFsType: "block", Env: []string{"A=1", "B=2"}},
			want: "panic=-1 console=ttyS0 root=/dev/vda rw A=1 B=2",
		},
		{
			// Kills a mutant that swaps which URUNIT_CONFIG line is used for
			// which RootFsType, or drops "retain_initrd".
			name: "InitrdConf with initrd rootfs uses the plain URUNIT_CONFIG line",
			l:    Linux{RootFsType: "initrd", InitrdConf: true},
			want: "panic=-1 console=ttyS0 root=/dev/ram0 rw URUNIT_CONFIG=/urunit.conf",
		},
		{
			name: "InitrdConf with non-initrd rootfs uses retain_initrd and the /sys path",
			l:    Linux{RootFsType: "block", InitrdConf: true},
			want: "panic=-1 console=ttyS0 root=/dev/vda rw retain_initrd URUNIT_CONFIG=/sys/firmware/initrd",
		},
		{
			// Kills a mutant that drops "--", swaps App/Command order, or
			// loses the rdinit prefix logic.
			name: "App and Command produce the init= line",
			l:    Linux{RootFsType: "block", App: "/sbin/init", Command: "arg1 arg2"},
			want: "panic=-1 console=ttyS0 root=/dev/vda rw init=/sbin/init -- arg1 arg2",
		},
		{
			// "rd" + "init=" == "rdinit=" is the actual Linux kernel
			// parameter name for handing init to an initrd -- not a
			// coincidental string concatenation. A mutant that changes the
			// rdinit prefix breaks a real kernel boot parameter.
			name: "App on initrd rootfs produces rdinit= instead of init=",
			l:    Linux{RootFsType: "initrd", App: "/sbin/init"},
			want: "panic=-1 console=ttyS0 root=/dev/ram0 rw rdinit=/sbin/init -- ",
		},
		{
			// Kills a mutant that makes the init= line unconditional.
			name: "no App means no init= line at all",
			l:    Linux{RootFsType: "block"},
			want: "panic=-1 console=ttyS0 root=/dev/vda rw",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.l.CommandString()
			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestLinuxMonitorBlockCli(t *testing.T) {
	blk := []types.BlockDevParams{
		{ID: "rootfs", Source: "/rootfs.img"},
		{ID: "vol1", Source: "/vol1.img"},
	}

	t.Run("qemu emits ExactArgs with a virtio-blk-pci device per disk", func(t *testing.T) {
		got := (&Linux{Monitor: "qemu", Blk: blk}).MonitorBlockCli()
		want := []types.MonitorBlockArgs{
			{ExactArgs: []string{
				"-device", "virtio-blk-pci,serial=rootfs,drive=rootfs",
				"-drive", "format=raw,if=none,id=rootfs,file=/rootfs.img",
			}},
			{ExactArgs: []string{
				"-device", "virtio-blk-pci,serial=vol1,drive=vol1",
				"-drive", "format=raw,if=none,id=vol1,file=/vol1.img",
			}},
		}
		assert.Equal(t, want, got)
	})

	t.Run("firecracker prefixes every ID with FC, including rootfs", func(t *testing.T) {
		// Kills a mutant that only prefixes non-rootfs IDs, or drops the
		// "FC" prefix's literal casing.
		got := (&Linux{Monitor: "firecracker", Blk: blk}).MonitorBlockCli()
		want := []types.MonitorBlockArgs{
			{ID: "FCrootfs", Path: "/rootfs.img"},
			{ID: "FCvol1", Path: "/vol1.img"},
		}
		assert.Equal(t, want, got)
	})

	t.Run("cloud-hypervisor uses IDs verbatim, unlike firecracker", func(t *testing.T) {
		// Kills a mutant that copy-pastes firecracker's "FC" prefix into
		// this branch, or collapses the two cases into one.
		got := (&Linux{Monitor: "cloud-hypervisor", Blk: blk}).MonitorBlockCli()
		want := []types.MonitorBlockArgs{
			{ID: "rootfs", Path: "/rootfs.img"},
			{ID: "vol1", Path: "/vol1.img"},
		}
		assert.Equal(t, want, got)
	})

	t.Run("unrecognised monitor returns nil, not an empty slice", func(t *testing.T) {
		got := (&Linux{Monitor: "hvt", Blk: blk}).MonitorBlockCli()
		assert.Nil(t, got)
	})

	t.Run("no block devices returns nil regardless of monitor", func(t *testing.T) {
		got := (&Linux{Monitor: "qemu"}).MonitorBlockCli()
		assert.Nil(t, got)
	})
}

func TestLinuxMonitorCli(t *testing.T) {
	cases := []struct {
		name       string
		monitor    string
		initrdConf bool
		rootFsType string
		want       types.MonitorCliArgs
	}{
		{
			name:    "qemu always gets -no-reboot -nodefaults",
			monitor: "qemu",
			want:    types.MonitorCliArgs{OtherArgs: []string{"-no-reboot", "-nodefaults"}},
		},
		{
			// Kills a mutant that drops the RootFsType != "initrd" guard,
			// which would set ExtraInitrd even when the rootfs already IS
			// the initrd (nothing extra to attach in that case).
			name:       "qemu with InitrdConf on a non-initrd rootfs sets ExtraInitrd",
			monitor:    "qemu",
			initrdConf: true,
			rootFsType: "block",
			want: types.MonitorCliArgs{
				OtherArgs:   []string{"-no-reboot", "-nodefaults"},
				ExtraInitrd: urunitConfPath,
			},
		},
		{
			name:       "qemu with InitrdConf on an initrd rootfs sets no ExtraInitrd",
			monitor:    "qemu",
			initrdConf: true,
			rootFsType: "initrd",
			want:       types.MonitorCliArgs{OtherArgs: []string{"-no-reboot", "-nodefaults"}},
		},
		{
			// Kills a mutant that drifts firecracker/cloud-hypervisor's
			// shared branch away from qemu's OtherArgs (they must have none).
			name:       "firecracker with InitrdConf sets ExtraInitrd and no OtherArgs",
			monitor:    "firecracker",
			initrdConf: true,
			rootFsType: "block",
			want:       types.MonitorCliArgs{ExtraInitrd: urunitConfPath},
		},
		{
			name:       "cloud-hypervisor shares firecracker's branch",
			monitor:    "cloud-hypervisor",
			initrdConf: true,
			rootFsType: "block",
			want:       types.MonitorCliArgs{ExtraInitrd: urunitConfPath},
		},
		{
			name:       "unrecognised monitor gets the zero value",
			monitor:    "hvt",
			initrdConf: true,
			rootFsType: "block",
			want:       types.MonitorCliArgs{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := &Linux{Monitor: tc.monitor, InitrdConf: tc.initrdConf, RootFsType: tc.rootFsType}
			assert.Equal(t, tc.want, l.MonitorCli())
		})
	}
}

func TestLinuxMonitorSharedfsCli(t *testing.T) {
	t.Run("qemu with 9pfs returns the fsdev/device pair", func(t *testing.T) {
		got := (&Linux{Monitor: "qemu"}).MonitorSharedfsCli("9pfs", "/mnt/rootfs")
		want := []string{
			"-fsdev", "local,id=rootfs9p,security_model=none,multidevs=remap,path=/mnt/rootfs",
			"-device", "virtio-9p-pci,fsdev=rootfs9p,mount_tag=fs0",
		}
		assert.Equal(t, want, got)
	})

	t.Run("qemu with a non-9pfs fsType returns nil", func(t *testing.T) {
		// Kills a mutant that drops the fsType == "9pfs" half of the guard.
		got := (&Linux{Monitor: "qemu"}).MonitorSharedfsCli("virtiofs", "/mnt/rootfs")
		assert.Nil(t, got)
	})

	t.Run("non-qemu monitor returns nil even with 9pfs", func(t *testing.T) {
		// Kills a mutant that drops the Monitor == "qemu" half of the guard --
		// this is qemu-specific PCI transport wiring, not a generic 9p path.
		got := (&Linux{Monitor: "firecracker"}).MonitorSharedfsCli("9pfs", "/mnt/rootfs")
		assert.Nil(t, got)
	})
}
