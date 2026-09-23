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

func TestMirageInitSubnetMask(t *testing.T) {
	tests := []struct {
		name        string
		mask        string
		ip          string
		gateway     string
		wantAddress string
		wantGateway string
	}{
		{
			name:        "non-/24 mask is used correctly",
			mask:        "255.255.255.240",
			ip:          "10.0.0.1",
			gateway:     "10.0.0.14",
			wantAddress: "--ipv4=10.0.0.1/28",
			wantGateway: "--ipv4-gateway=10.0.0.14",
		},
		{
			name:        "/24 mask still works",
			mask:        "255.255.255.0",
			ip:          "192.168.1.5",
			gateway:     "192.168.1.1",
			wantAddress: "--ipv4=192.168.1.5/24",
			wantGateway: "--ipv4-gateway=192.168.1.1",
		},
		{
			name:        "no network when mask is empty",
			mask:        "",
			ip:          "",
			gateway:     "",
			wantAddress: "",
			wantGateway: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newMirage()
			params := types.UnikernelParams{
				Net: types.NetDevParams{
					IP:      tt.ip,
					Mask:    tt.mask,
					Gateway: tt.gateway,
				},
			}
			err := m.Init(params)
			assert.NoError(t, err)
			assert.Equal(t, tt.wantAddress, m.Net.Address)
			assert.Equal(t, tt.wantGateway, m.Net.Gateway)
		})
	}
}

func TestMirageNetDevName(t *testing.T) {
	t.Run("uses net device name from annotation", func(t *testing.T) {
		t.Parallel()
		m := &Mirage{}
		err := m.Init(types.UnikernelParams{Monitor: "hvt", NetDevName: "management"})
		assert.NoError(t, err)
		cli := m.MonitorNetCli("tap0", "aa:bb:cc:dd:ee:ff")
		assert.Contains(t, cli, "--net:management=tap0")
		assert.Contains(t, cli, "--net-mac:management=aa:bb:cc:dd:ee:ff")
	})

	t.Run("falls back to service when annotation is absent", func(t *testing.T) {
		t.Parallel()
		m := &Mirage{}
		err := m.Init(types.UnikernelParams{Monitor: "hvt"})
		assert.NoError(t, err)
		cli := m.MonitorNetCli("tap0", "aa:bb:cc:dd:ee:ff")
		assert.Contains(t, cli, "--net:service=tap0")
		assert.Contains(t, cli, "--net-mac:service=aa:bb:cc:dd:ee:ff")
	})
}

func TestMirageBlkDevName(t *testing.T) {
	t.Run("uses block device name from annotation", func(t *testing.T) {
		t.Parallel()
		m := &Mirage{}
		err := m.Init(types.UnikernelParams{
			Monitor:    "hvt",
			BlkDevName: "database",
			Block:      []types.BlockDevParams{{Source: "/path/to/img"}},
		})
		assert.NoError(t, err)
		args := m.MonitorBlockCli()
		assert.Len(t, args, 1)
		assert.Equal(t, "database", args[0].ID)
		assert.Equal(t, "/path/to/img", args[0].Path)
	})

	t.Run("falls back to storage when annotation is absent", func(t *testing.T) {
		t.Parallel()
		m := &Mirage{}
		err := m.Init(types.UnikernelParams{
			Monitor: "hvt",
			Block:   []types.BlockDevParams{{Source: "/path/to/img"}},
		})
		assert.NoError(t, err)
		args := m.MonitorBlockCli()
		assert.Len(t, args, 1)
		assert.Equal(t, "storage", args[0].ID)
	})
}

// The functions below are additions on top of the upstream file above -- see
// linux_test.go for why this class of test exists. A recreated duplicate of
// TestMirageInitSubnetMask was dropped from this set once the real upstream
// function (above) was restored -- see FUZZING_FINDINGS.md for that history.

func TestMirageInitNetworkNaming(t *testing.T) {
	// Init's comment explains the real contract: Mirage prefixes a network
	// device's flags with its device name, UNLESS that name is "service"
	// (the default device), in which case the plain --ipv4/--ipv4-gateway
	// flags are used instead. Getting the "service" special-case wrong means
	// urunc's own default device gets a --service-ipv4 flag Mirage does not
	// expect for it. Distinct from TestMirageNetDevName above: that tests
	// netDevName's effect through MonitorNetCli's --net:X= flags; this tests
	// its effect on Net.Address/Net.Gateway's --ipv4 flags directly -- two
	// different fields, two different code paths.
	cases := []struct {
		name        string
		netDevName  string
		wantAddress string
		wantGateway string
	}{
		{
			name:        "empty NetDevName behaves like the default device",
			netDevName:  "",
			wantAddress: "--ipv4=10.0.0.5/24",
			wantGateway: "--ipv4-gateway=10.0.0.1",
		},
		{
			// Kills a mutant that drops the second half of the
			// `!= "" && != "service"` guard, which would make "service"
			// wrongly take the prefixed branch.
			name:        `explicit "service" is the same as empty -- both are the default device`,
			netDevName:  "service",
			wantAddress: "--ipv4=10.0.0.5/24",
			wantGateway: "--ipv4-gateway=10.0.0.1",
		},
		{
			name:        "a named, non-default device gets its name as a flag prefix",
			netDevName:  "management",
			wantAddress: "--management-ipv4=10.0.0.5/24",
			wantGateway: "--management-ipv4-gateway=10.0.0.1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &Mirage{}
			err := m.Init(types.UnikernelParams{
				CmdLine:    []string{"/init"},
				NetDevName: tc.netDevName,
				Net:        types.NetDevParams{IP: "10.0.0.5", Gateway: "10.0.0.1", Mask: "255.255.255.0"},
			})
			require.NoError(t, err)
			assert.Equal(t, tc.wantAddress, m.Net.Address)
			assert.Equal(t, tc.wantGateway, m.Net.Gateway)
		})
	}

	t.Run("no mask means no networking at all -- Net stays zero", func(t *testing.T) {
		m := &Mirage{}
		require.NoError(t, m.Init(types.UnikernelParams{CmdLine: []string{"/init"}}))
		assert.Equal(t, MirageNet{}, m.Net)
	})
}

func TestMirageInitNetDevNaming(t *testing.T) {
	// netDevName's default-to-"service" runs unconditionally, separately
	// from the address-formatting logic TestMirageInitNetworkNaming already
	// covers (that logic only runs when a mask is configured; this one
	// always does). Kills a mutant that flips the guard or the default.
	cases := []struct {
		name           string
		netDevName     string
		wantDeviceName string
	}{
		{"empty NetDevName defaults to service", "", "service"},
		{"an explicit name is used verbatim", "management", "management"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &Mirage{}
			require.NoError(t, m.Init(types.UnikernelParams{CmdLine: []string{"/init"}, NetDevName: tc.netDevName}))
			assert.Equal(t, tc.wantDeviceName, m.netDevName)
		})
	}
}

func TestMirageInitBlockDevNaming(t *testing.T) {
	// Same defaulting pattern as netDevName, for the block device name used
	// by MonitorBlockCli.
	cases := []struct {
		name           string
		blkDevName     string
		wantDeviceName string
	}{
		{"empty BlkDevName defaults to storage", "", "storage"},
		{"an explicit name is used verbatim", "data0", "data0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &Mirage{}
			require.NoError(t, m.Init(types.UnikernelParams{CmdLine: []string{"/init"}, BlkDevName: tc.blkDevName}))
			assert.Equal(t, tc.wantDeviceName, m.blkDevName)
		})
	}
}

func TestMirageInitBlockList(t *testing.T) {
	// Kills a mutant that drops a field in the BlockDevParams -> MirageBlock
	// copy, or that reuses the source slice instead of building a fresh one.
	m := &Mirage{}
	require.NoError(t, m.Init(types.UnikernelParams{
		CmdLine: []string{"/init"},
		Block: []types.BlockDevParams{
			{ID: "vol1", Source: "/host/vol1.img"},
			{ID: "vol2", Source: "/host/vol2.img"},
		},
	}))
	assert.Equal(t, []MirageBlock{
		{ID: "vol1", HostPath: "/host/vol1.img"},
		{ID: "vol2", HostPath: "/host/vol2.img"},
	}, m.Block)
}

func TestMirageCommandString(t *testing.T) {
	cases := []struct {
		name string
		m    Mirage
		want string
	}{
		{
			name: "address, gateway and command all present",
			m:    Mirage{Net: MirageNet{Address: "--ipv4=10.0.0.5/24", Gateway: "--ipv4-gateway=10.0.0.1"}, Command: "/init"},
			want: "--ipv4=10.0.0.5/24 --ipv4-gateway=10.0.0.1 /init",
		},
		{
			// Kills a mutant that guards the network fields on emptiness --
			// CommandString has no such guard, it always Sprintfs all three
			// slots, so no network configured produces leading spaces.
			name: "no network configured leaves both leading fields blank",
			m:    Mirage{Command: "/init"},
			want: "  /init",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.m.CommandString()
			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestMirageMonitorBlockCli(t *testing.T) {
	t.Run("hvt/spt report the single configured block device ID and its host path", func(t *testing.T) {
		// Kills a mutant that reads Block[1] instead of Block[0], or that
		// uses Block[0].ID instead of the separately-tracked blkDevName --
		// see the same "only one block device today" TODO as Rumprun's.
		m := &Mirage{Monitor: "hvt", blkDevName: "storage", Block: []MirageBlock{{ID: "vol1", HostPath: "/host/vol1.img"}}}
		want := []types.MonitorBlockArgs{{ID: "storage", Path: "/host/vol1.img"}}
		assert.Equal(t, want, m.MonitorBlockCli())
	})

	t.Run("spt shares hvt's branch", func(t *testing.T) {
		m := &Mirage{Monitor: "spt", blkDevName: "storage", Block: []MirageBlock{{ID: "vol1", HostPath: "/host/vol1.img"}}}
		want := []types.MonitorBlockArgs{{ID: "storage", Path: "/host/vol1.img"}}
		assert.Equal(t, want, m.MonitorBlockCli())
	})

	t.Run("any other monitor gets nil even with a block device configured", func(t *testing.T) {
		m := &Mirage{Monitor: "qemu", blkDevName: "storage", Block: []MirageBlock{{ID: "vol1", HostPath: "/host/vol1.img"}}}
		assert.Nil(t, m.MonitorBlockCli())
	})

	t.Run("no block devices returns nil regardless of monitor", func(t *testing.T) {
		// Kills a mutant that drops the len(m.Block) == 0 guard and falls
		// through to a switch that would otherwise construct a bogus entry.
		m := &Mirage{Monitor: "hvt"}
		assert.Nil(t, m.MonitorBlockCli())
	})
}

func TestMirageMonitorNetCli(t *testing.T) {
	cases := []struct {
		name    string
		monitor string
		want    []string
	}{
		{"hvt uses the configured net device name as the flag prefix", "hvt", []string{"--net:storage=tap0", "--net-mac:storage=aa:bb:cc:dd:ee:ff"}},
		{"spt shares hvt's branch", "spt", []string{"--net:storage=tap0", "--net-mac:storage=aa:bb:cc:dd:ee:ff"}},
		{"any other monitor gets nil", "qemu", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// netDevName deliberately reused as "storage" here just to prove
			// MonitorNetCli reads whatever netDevName Init set, not a
			// hardcoded string -- unrelated to it normally being a net name.
			m := &Mirage{Monitor: tc.monitor, netDevName: "storage"}
			assert.Equal(t, tc.want, m.MonitorNetCli("tap0", "aa:bb:cc:dd:ee:ff"))
		})
	}
}

func TestMirageUnsupportedSurfaces(t *testing.T) {
	m := &Mirage{}
	assert.True(t, m.SupportsBlock())
	assert.False(t, m.SupportsFS("9pfs"), "Mirage does not support any shared filesystem")
	assert.Nil(t, m.MonitorSharedfsCli("9pfs", "/mnt/rootfs"))
	assert.Equal(t, types.MonitorCliArgs{}, m.MonitorCli())
}
