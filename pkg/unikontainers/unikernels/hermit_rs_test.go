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

// Content assertions for Hermit -- see linux_test.go for why this class of
// test exists. Hermit's CommandString has two INDEPENDENT guards (Address,
// Gateway can each be present or absent on their own) plus a separator that
// only appears when both a net arg AND a command exist -- three orthogonal
// conditions worth their own cases rather than one "everything on" case.

func TestHermitCommandString(t *testing.T) {
	cases := []struct {
		name string
		h    Hermit
		want string
	}{
		{
			name: "nothing configured produces an empty string",
			h:    Hermit{},
			want: "",
		},
		{
			// Kills a mutant that ties Address's guard to Gateway also being
			// set -- they are independent per the source.
			name: "address alone, no gateway, no command",
			h:    Hermit{Net: HermitNet{Address: "10.0.0.5", Mask: 24}},
			want: "ip=10.0.0.5/24",
		},
		{
			// Kills a mutant that ties Gateway's guard to Address also being
			// set.
			name: "gateway alone, no address, no command",
			h:    Hermit{Net: HermitNet{Gateway: "10.0.0.1"}},
			want: "gateway=10.0.0.1",
		},
		{
			name: "address and gateway, no command -- no trailing separator",
			h:    Hermit{Net: HermitNet{Address: "10.0.0.5", Mask: 24, Gateway: "10.0.0.1"}},
			want: "ip=10.0.0.5/24 gateway=10.0.0.1",
		},
		{
			// Kills a mutant that makes the separator unconditional -- a
			// command with no net args must not get a leading "--".
			name: "command alone, no net args -- no separator",
			h:    Hermit{Command: "arg1 arg2"},
			want: "arg1 arg2",
		},
		{
			// Kills a mutant that drops "len(args) > 0 &&" from the
			// separator guard (leaving only the appArgs != "" half), which
			// would insert a spurious leading "--" here too.
			name: "address and command together -- separator appears",
			h:    Hermit{Net: HermitNet{Address: "10.0.0.5", Mask: 24}, Command: "arg1"},
			want: "ip=10.0.0.5/24 -- arg1",
		},
		{
			name: "address, gateway and command together",
			h:    Hermit{Net: HermitNet{Address: "10.0.0.5", Mask: 24, Gateway: "10.0.0.1"}, Command: "arg1"},
			want: "ip=10.0.0.5/24 gateway=10.0.0.1 -- arg1",
		},
		{
			// Kills a mutant that drops strings.TrimSpace on Command --
			// whitespace-only "commands" must be treated the same as none.
			name: "whitespace-only command behaves like no command at all",
			h:    Hermit{Net: HermitNet{Address: "10.0.0.5", Mask: 24}, Command: "   "},
			want: "ip=10.0.0.5/24",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.h.CommandString()
			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestHermitInit(t *testing.T) {
	t.Run("a mask converts to CIDR and populates Net", func(t *testing.T) {
		h := &Hermit{}
		require.NoError(t, h.Init(types.UnikernelParams{
			CmdLine: []string{"/init", "arg1"},
			Net:     types.NetDevParams{IP: "10.0.0.5", Gateway: "10.0.0.1", Mask: "255.255.255.0"},
		}))
		assert.Equal(t, HermitNet{Address: "10.0.0.5", Mask: 24, Gateway: "10.0.0.1"}, h.Net)
		assert.Equal(t, "/init arg1", h.Command)
	})

	t.Run("no mask leaves Net at its zero value entirely", func(t *testing.T) {
		// Kills a mutant that partially populates Net (e.g. sets Address
		// but not Gateway) when there is no mask -- the guard covers the
		// whole block, not just Mask itself.
		h := &Hermit{}
		require.NoError(t, h.Init(types.UnikernelParams{
			CmdLine: []string{"/init"},
			Net:     types.NetDevParams{IP: "10.0.0.5", Gateway: "10.0.0.1"},
		}))
		assert.Equal(t, HermitNet{}, h.Net)
	})
}

func TestHermitMonitorNetCli(t *testing.T) {
	t.Run("qemu on non-arm64 uses virtio-net-pci with the legacy flag disabled", func(t *testing.T) {
		// Same untestable-on-this-machine caveat as Linux's console=ttyAMA0
		// branch: only the non-arm64 half of runtime.GOARCH=="arm64" is
		// exercised here, but asserting it still catches a mutant that
		// flips the condition and would wrongly pick the arm64 device
		// string on this (amd64) architecture.
		h := &Hermit{Monitor: "qemu"}
		want := []string{
			"-netdev", "tap,id=net0,ifname=tap0,script=no,downscript=no",
			"-device", "virtio-net-pci,netdev=net0,disable-legacy=on",
		}
		assert.Equal(t, want, h.MonitorNetCli("tap0", ""))
	})

	t.Run("a non-empty MAC is appended to the device args", func(t *testing.T) {
		// Kills a mutant that drops the `if mac != ""` guard or the append.
		h := &Hermit{Monitor: "qemu"}
		want := []string{
			"-netdev", "tap,id=net0,ifname=tap0,script=no,downscript=no",
			"-device", "virtio-net-pci,netdev=net0,disable-legacy=on,mac=aa:bb:cc:dd:ee:ff",
		}
		assert.Equal(t, want, h.MonitorNetCli("tap0", "aa:bb:cc:dd:ee:ff"))
	})

	t.Run("any other monitor gets nil", func(t *testing.T) {
		h := &Hermit{Monitor: "hvt"}
		assert.Nil(t, h.MonitorNetCli("tap0", "aa:bb:cc:dd:ee:ff"))
	})
}

func TestHermitMonitorCli(t *testing.T) {
	// Unconditional, unlike every other guest type checked so far -- kills
	// a mutant that makes this depend on Monitor when the source has no
	// such branch at all.
	assert.Equal(t, types.MonitorCliArgs{OtherArgs: []string{"-no-reboot"}}, (&Hermit{Monitor: "qemu"}).MonitorCli())
	assert.Equal(t, types.MonitorCliArgs{OtherArgs: []string{"-no-reboot"}}, (&Hermit{Monitor: "hvt"}).MonitorCli())
}

func TestHermitSupportsFS(t *testing.T) {
	h := &Hermit{}
	assert.True(t, h.SupportsFS("initrd"))
	assert.False(t, h.SupportsFS("9pfs"), "only initrd is supported today")
}

func TestHermitUnsupportedSurfaces(t *testing.T) {
	h := &Hermit{}
	assert.False(t, h.SupportsBlock())
	assert.Nil(t, h.MonitorBlockCli())
	assert.Nil(t, h.MonitorSharedfsCli("9pfs", "/mnt/rootfs"))
}
