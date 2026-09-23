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

func TestMewzCommandString(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		mewz     *Mewz
		expected string
	}{
		{
			name:     "no network configured",
			mewz:     &Mewz{},
			expected: "",
		},
		{
			name: "with network configured",
			mewz: &Mewz{
				Net: MewzNet{
					Address: "10.0.0.2",
					Mask:    24,
					Gateway: "10.0.0.1",
				},
			},
			expected: "ip=10.0.0.2/24 gateway=10.0.0.1",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result, err := tc.mewz.CommandString()
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// The functions below are additions on top of the upstream file above -- see
// linux_test.go for why this class of test exists. Kept separate rather than
// merged into TestMewzCommandString so the upstream test stays untouched.

func TestMewzInit(t *testing.T) {
	t.Run("a mask on the spec is converted to CIDR via subnetMaskToCIDR", func(t *testing.T) {
		m := &Mewz{}
		require.NoError(t, m.Init(types.UnikernelParams{
			CmdLine: []string{"/init"},
			Net:     types.NetDevParams{IP: "10.0.0.5", Gateway: "10.0.0.1", Mask: "255.255.255.0"},
		}))
		assert.Equal(t, MewzNet{Address: "10.0.0.5", Mask: 24, Gateway: "10.0.0.1"}, m.Net)
	})

	t.Run("no mask on the spec defaults to /24, not zero", func(t *testing.T) {
		// Kills a mutant that drops the "else mask = 24" default, which
		// would silently produce a /0 mask instead.
		m := &Mewz{}
		require.NoError(t, m.Init(types.UnikernelParams{
			CmdLine: []string{"/init"},
			Net:     types.NetDevParams{IP: "10.0.0.5", Gateway: "10.0.0.1"},
		}))
		assert.Equal(t, 24, m.Net.Mask)
	})
}

func TestMewzMonitorNetCli(t *testing.T) {
	t.Run("qemu gets the fixed virtio-net device/netdev pair", func(t *testing.T) {
		m := &Mewz{Monitor: "qemu"}
		want := []string{
			"-device", "virtio-net-pci,netdev=net0,disable-legacy=on,disable-modern=off,mac=aa:bb:cc:dd:ee:ff",
			"-netdev", "tap,script=no,downscript=no,id=net0,ifname=tap0",
		}
		assert.Equal(t, want, m.MonitorNetCli("tap0", "aa:bb:cc:dd:ee:ff"))
	})

	t.Run("any other monitor gets nil -- Mewz only runs on qemu today", func(t *testing.T) {
		m := &Mewz{Monitor: "hvt"}
		assert.Nil(t, m.MonitorNetCli("tap0", "aa:bb:cc:dd:ee:ff"))
	})
}

func TestMewzMonitorCli(t *testing.T) {
	t.Run("qemu gets isa-debug-exit wired up for guest exit-code reporting", func(t *testing.T) {
		m := &Mewz{Monitor: "qemu"}
		want := types.MonitorCliArgs{OtherArgs: []string{"-no-reboot", "-device", "isa-debug-exit,iobase=0x501,iosize=2"}}
		assert.Equal(t, want, m.MonitorCli())
	})

	t.Run("any other monitor gets the zero value", func(t *testing.T) {
		m := &Mewz{Monitor: "hvt"}
		assert.Equal(t, types.MonitorCliArgs{}, m.MonitorCli())
	})
}

func TestMewzUnsupportedSurfaces(t *testing.T) {
	m := &Mewz{}
	assert.False(t, m.SupportsBlock())
	assert.False(t, m.SupportsFS("9pfs"))
	assert.Nil(t, m.MonitorBlockCli())
	assert.Nil(t, m.MonitorSharedfsCli("9pfs", "/mnt/rootfs"))
}
