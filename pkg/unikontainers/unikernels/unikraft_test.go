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
	"github.com/stretchr/testify/require"

	"github.com/urunc-dev/urunc/pkg/unikontainers/types"
)

// Content assertions for Unikraft -- see linux_test.go for why this class of
// test exists. Unikraft's Init has the most branching logic of any guest type
// here: a version comparison against UnikraftCompatVersion selects between two
// entirely different argument-naming schemes (setCompatArgs vs setCurrentArgs),
// and getting that selection wrong silently produces boot parameters the
// running unikraft image does not recognise.

func TestUnikraftInit(t *testing.T) {
	baseParams := func(version, rootFsType, dns string) types.UnikernelParams {
		return types.UnikernelParams{
			CmdLine: []string{"/init"},
			EnvVars: []string{"A=1"},
			Version: version,
			Rootfs:  types.RootfsParams{Type: rootFsType},
			Net:     types.NetDevParams{IP: "10.0.0.5", Gateway: "10.0.0.1", Mask: "255.255.255.0", DNSServer: dns},
		}
	}

	t.Run("no version at all falls back to current args and returns ErrUndefinedVersion", func(t *testing.T) {
		// The error is non-fatal by design (see structaware_fuzz_test.go /
		// buildUnikernelCommand): callers log it and keep going with the
		// fallback args this test locks in.
		u := &Unikraft{}
		err := u.Init(baseParams("", "block", ""))
		require.ErrorIs(t, err, ErrUndefinedVersion)
		assert.Equal(t, "netdev.ip=10.0.0.5/24:10.0.0.1:8.8.8.8", u.Net.Address, "missing DNSServer must default to 8.8.8.8")
		assert.Equal(t, []string{"A=1"}, u.Env, "current-args path keeps env vars")
	})

	t.Run("an unparseable version falls back to current args and returns ErrVersionParsing", func(t *testing.T) {
		u := &Unikraft{}
		err := u.Init(baseParams("not-a-version", "9pfs", ""))
		require.ErrorIs(t, err, ErrVersionParsing)
		assert.Equal(t, `vfs.fstab=[ "fs0:/:9pfs:::" ]`, u.VFS.RootFS)
	})

	t.Run("a version at or above the compat threshold uses current args", func(t *testing.T) {
		// Kills a mutant that flips GreaterThanOrEqual to GreaterThan, which
		// would wrongly route the exact compat version (0.16.1 itself) into
		// setCompatArgs instead of setCurrentArgs.
		u := &Unikraft{}
		err := u.Init(baseParams(UnikraftCompatVersion, "block", ""))
		assert.NoError(t, err)
		assert.Equal(t, "netdev.ip=10.0.0.5/24:10.0.0.1:8.8.8.8", u.Net.Address)
		assert.Equal(t, []string{"A=1"}, u.Env, "current-args path never clears env")
	})

	t.Run("a version above the compat threshold uses current args and a custom DNS server", func(t *testing.T) {
		u := &Unikraft{}
		err := u.Init(baseParams("0.20.0", "9pfs", "1.1.1.1"))
		assert.NoError(t, err)
		assert.Equal(t, "netdev.ip=10.0.0.5/24:10.0.0.1:1.1.1.1", u.Net.Address)
		assert.Equal(t, `vfs.fstab=[ "fs0:/:9pfs:::" ]`, u.VFS.RootFS)
	})

	t.Run("current-args rootfs switch: initrd", func(t *testing.T) {
		u := &Unikraft{}
		require.NoError(t, u.Init(baseParams("0.20.0", "initrd", "")))
		assert.Equal(t, `vfs.fstab=[ "initrd0:/:extract:::" ]`, u.VFS.RootFS)
	})

	t.Run("current-args rootfs switch: unrecognised type sets no VFS.RootFS", func(t *testing.T) {
		// Kills a mutant that makes the default case fall through to one of
		// the named cases instead of leaving RootFS empty.
		u := &Unikraft{}
		require.NoError(t, u.Init(baseParams("0.20.0", "bogus", "")))
		assert.Equal(t, "", u.VFS.RootFS)
	})

	t.Run("a version below the compat threshold uses compat args and clears env vars", func(t *testing.T) {
		// Kills a mutant that drops "u.Env = nil" in the old-version branch --
		// old Unikraft images do not support env vars at all, so silently
		// keeping them would produce boot parameters the image can't use.
		u := &Unikraft{}
		err := u.Init(baseParams("0.10.0", "block", ""))
		assert.NoError(t, err)
		assert.Nil(t, u.Env)
		assert.Equal(t, "netdev.ipv4_addr=10.0.0.5", u.Net.Address)
		assert.Equal(t, "netdev.ipv4_gw_addr=10.0.0.1", u.Net.Gateway)
		assert.Equal(t, "netdev.ipv4_subnet_mask=255.255.255.0", u.Net.Mask)
	})

	t.Run("compat-args rootfs switch: initrd", func(t *testing.T) {
		u := &Unikraft{}
		require.NoError(t, u.Init(baseParams("0.10.0", "initrd", "")))
		assert.Equal(t, "vfs.rootfs=initrd", u.VFS.RootFS)
	})

	t.Run("compat-args rootfs switch: anything else (including 9pfs) sets no VFS.RootFS", func(t *testing.T) {
		// Kills a mutant that gives compat args a 9pfs case like current args
		// has -- the old scheme never supported one; see the setCompatArgs
		// TODO about lacking block/sharedfs support entirely.
		u := &Unikraft{}
		require.NoError(t, u.Init(baseParams("0.10.0", "9pfs", "")))
		assert.Equal(t, "", u.VFS.RootFS)
	})
}

func TestUnikraftCommandString(t *testing.T) {
	// CommandString is a fixed 7-slot Sprintf; empty fields still occupy
	// their slot, which is why the "current-args, no rootfs" case below has
	// visibly doubled spaces. That is locked in as real, current behavior,
	// not fixed as part of this pass -- if it is ever intentionally
	// tightened (e.g. via strings.Join(nonEmptyFields, " ")), this is where
	// that change would need updating.
	cases := []struct {
		name string
		u    Unikraft
		want string
	}{
		{
			name: "current-args shape, no rootfs, has env",
			u: Unikraft{
				AppName: "Unikraft", Env: []string{"A=1"}, Command: "/init",
				Net: UnikraftNet{Address: "netdev.ip=10.0.0.5/24:10.0.0.1:8.8.8.8"},
			},
			want: "Unikraft  env.vars=[ A=1 ] netdev.ip=10.0.0.5/24:10.0.0.1:8.8.8.8    -- /init",
		},
		{
			name: "current-args shape with a rootfs and no env",
			u: Unikraft{
				AppName: "Unikraft", Command: "/init",
				Net: UnikraftNet{Address: "netdev.ip=10.0.0.5/24:10.0.0.1:8.8.8.8"},
				VFS: UnikraftVFS{RootFS: `vfs.fstab=[ "fs0:/:9pfs:::" ]`},
			},
			want: `Unikraft   netdev.ip=10.0.0.5/24:10.0.0.1:8.8.8.8   vfs.fstab=[ "fs0:/:9pfs:::" ] -- /init`,
		},
		{
			name: "compat-args shape: Address/Gateway/Mask are separate fields, not one combined string",
			u: Unikraft{
				AppName: "Unikraft", Command: "/init",
				Net: UnikraftNet{
					Address: "netdev.ipv4_addr=10.0.0.5",
					Gateway: "netdev.ipv4_gw_addr=10.0.0.1",
					Mask:    "netdev.ipv4_subnet_mask=255.255.255.0",
				},
				VFS: UnikraftVFS{RootFS: "vfs.rootfs=initrd"},
			},
			want: "Unikraft   netdev.ipv4_addr=10.0.0.5 netdev.ipv4_gw_addr=10.0.0.1 netdev.ipv4_subnet_mask=255.255.255.0 vfs.rootfs=initrd -- /init",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.u.CommandString()
			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestUnikraftMonitorSharedfsCli(t *testing.T) {
	// Same qemu+9pfs-only shape as Linux's MonitorSharedfsCli -- both guard
	// on Monitor and fsType independently, so both halves need their own
	// case to kill a mutant that drops either one.
	t.Run("qemu with 9pfs returns the fsdev/device pair", func(t *testing.T) {
		got := (&Unikraft{Monitor: "qemu"}).MonitorSharedfsCli("9pfs", "/mnt/rootfs")
		want := []string{
			"-fsdev", "local,id=rootfs9p,security_model=none,multidevs=remap,path=/mnt/rootfs",
			"-device", "virtio-9p-pci,fsdev=rootfs9p,mount_tag=fs0",
		}
		assert.Equal(t, want, got)
	})

	t.Run("qemu with a non-9pfs fsType returns nil", func(t *testing.T) {
		assert.Nil(t, (&Unikraft{Monitor: "qemu"}).MonitorSharedfsCli("virtiofs", "/mnt/rootfs"))
	})

	t.Run("non-qemu monitor returns nil even with 9pfs", func(t *testing.T) {
		assert.Nil(t, (&Unikraft{Monitor: "firecracker"}).MonitorSharedfsCli("9pfs", "/mnt/rootfs"))
	})
}

func TestUnikraftUnsupportedSurfaces(t *testing.T) {
	// Kills mutants that flip these fixed "not yet supported" returns --
	// both are documented as deliberate gaps in the source comments, not
	// oversights, so a test locking them in is what stops a well-meaning
	// future change from silently claiming Unikraft supports block devices
	// it has not actually been wired up for.
	u := &Unikraft{}
	assert.False(t, u.SupportsBlock())
	assert.Nil(t, u.MonitorBlockCli())
	assert.Nil(t, u.MonitorNetCli("tap0", "aa:bb:cc:dd:ee:ff"))
	assert.Equal(t, types.MonitorCliArgs{}, u.MonitorCli())
}

func TestUnikraftSupportsFS(t *testing.T) {
	u := &Unikraft{}
	assert.True(t, u.SupportsFS("9pfs"))
	assert.False(t, u.SupportsFS("ext4"), "only 9pfs is supported today")
}
