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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/urunc-dev/urunc/pkg/unikontainers/types"
)

// Content assertions for Rumprun's hand-rolled JSON encoder -- see linux_test.go
// for why this class of test exists. All expected strings were obtained by
// running the real code, not hand-computed.

func TestRumprunCommandString(t *testing.T) {
	cases := []struct {
		name string
		r    Rumprun
		want string
	}{
		{
			name: "command only, no env, no net, no block",
			r:    Rumprun{Command: "/init arg1"},
			want: `{"cmdline":"/init arg1"}`,
		},
		{
			// Kills a mutant that drops the brace-stripping or the comma join.
			name: "single env var",
			r:    Rumprun{Command: "/init", Envs: []string{"A=1"}},
			want: `{"cmdline":"/init","env":"A=1"}`,
		},
		{
			name: "network configured",
			r: Rumprun{Command: "/init", Net: RumprunNet{
				Interface: "ukvmif0", Cloner: "True", Type: "inet", Method: "static",
				Address: "10.0.0.5", Mask: "1", Gateway: "10.0.0.1",
			}},
			want: `{"cmdline":"/init","net":{"if":"ukvmif0","cloner":"True","type":"inet","method":"static","addr":"10.0.0.5","mask":"1","gw":"10.0.0.1"}}`,
		},
		{
			// Kills a mutant that negates the Blk.Source != "" guard.
			name: "block device configured",
			r: Rumprun{Command: "/init", Blk: RumprunBlk{
				Source: "etfs", Path: "/dev/ld0a", FsType: "blk", Mountpoint: "/data",
			}},
			want: `{"cmdline":"/init","blk":{"source":"etfs","path":"/dev/ld0a","fstype":"blk","mountpoint":"/data"}}`,
		},
		{
			// Kills a mutant that reorders the env/net/blk concatenation --
			// Rumprun's own (non-standard) parser may be positional.
			name: "env, net and block all together, in that order",
			r: Rumprun{Command: "/init", Envs: []string{"A=1"},
				Net: RumprunNet{Interface: "ukvmif0", Cloner: "True", Type: "inet", Method: "static", Address: "10.0.0.5", Mask: "1", Gateway: "10.0.0.1"},
				Blk: RumprunBlk{Source: "etfs", Path: "/dev/ld0a", FsType: "blk", Mountpoint: "/data"},
			},
			want: `{"cmdline":"/init","env":"A=1","net":{"if":"ukvmif0","cloner":"True","type":"inet","method":"static","addr":"10.0.0.5","mask":"1","gw":"10.0.0.1"},"blk":{"source":"etfs","path":"/dev/ld0a","fstype":"blk","mountpoint":"/data"}}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.r.CommandString()
			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestRumprunRepeatedEnvKeyIsTheWireFormat guards a deliberately non-standard
// wire format, not a bug (FUZZING_FINDINGS.md, F7's retirement writeup).
// CommandString emits one {"env":"K=V"} fragment per variable, joined as
// sibling keys, producing a JSON object with a repeated literal "env" key.
// That looks like a duplicate-key collision to a standard decoder, but
// Rumprun's actual guest-side parser (rumprun/lib/librumprun_base/config.c)
// is a linear token scanner that calls putenv() once per "env" occurrence --
// repetition IS the format it expects, not data loss.
//
// This exists to catch the opposite mistake: a well-meaning refactor that
// "fixes" the repeated key into a single "env":["A=1","B=2"] array would look
// like a correctness improvement and would actually break every Rumprun
// guest, since config.c's handle_env only knows how to consume one string
// value per dispatch, not an array. If this test starts failing, check
// config.c's actual expectations before assuming the new shape is correct.
func TestRumprunRepeatedEnvKeyIsTheWireFormat(t *testing.T) {
	r := Rumprun{Command: "/init", Envs: []string{"A=1", "B=2", "C=3"}}
	got, err := r.CommandString()
	assert.NoError(t, err)

	occurrences := strings.Count(got, `"env":`)
	if occurrences != len(r.Envs) {
		t.Fatalf("expected one \"env\" key per variable (%d), got %d occurrences -- "+
			"Rumprun's parser dispatches putenv() once per key, so this count must "+
			"match the input exactly, not collapse into an array.\n  got: %s",
			len(r.Envs), occurrences, got)
	}
	for _, want := range r.Envs {
		if !strings.Contains(got, `"env":"`+want+`"`) {
			t.Fatalf("expected %q to appear as its own \"env\" fragment, not just "+
				"survive as some other key's value.\n  got: %s", want, got)
		}
	}
}

func TestRumprunInitNetworkConfiguration(t *testing.T) {
	t.Run("a mask on the incoming spec configures static networking with the fixed /1 workaround", func(t *testing.T) {
		// Locks in the documented FIXME at rumprun.go:186-198: regardless of
		// what mask the OCI spec actually supplies, Init hardcodes
		// SubnetMask125 ("128.0.0.0", CIDR /1) rather than converting the
		// caller's mask. Kills a mutant that starts passing data.Net.Mask
		// through instead, which would be a silent behavior change worth
		// noticing even though the current behavior is the known workaround.
		r := &Rumprun{}
		err := r.Init(types.UnikernelParams{
			CmdLine: []string{"/init"},
			Net:     types.NetDevParams{IP: "10.0.0.5", Gateway: "10.0.0.1", Mask: "255.255.255.0"},
		})
		assert.NoError(t, err)
		assert.Equal(t, RumprunNet{
			Interface: "ukvmif0", Cloner: "True", Type: "inet", Method: "static",
			Address: "10.0.0.5", Mask: "1", Gateway: "10.0.0.1",
		}, r.Net)
	})

	t.Run("no mask on the incoming spec means no networking at all", func(t *testing.T) {
		r := &Rumprun{}
		err := r.Init(types.UnikernelParams{CmdLine: []string{"/init"}})
		assert.NoError(t, err)
		assert.Equal(t, RumprunNet{}, r.Net)
	})
}

func TestRumprunInitBlockConfiguration(t *testing.T) {
	t.Run("a block device configures the fixed etfs/ld0a shape", func(t *testing.T) {
		r := &Rumprun{}
		err := r.Init(types.UnikernelParams{
			CmdLine: []string{"/init"},
			Block:   []types.BlockDevParams{{ID: "rootfs", Source: "/host/rootfs.img", MountPoint: "/data"}},
		})
		assert.NoError(t, err)
		assert.Equal(t, RumprunBlk{
			HostPath: "/host/rootfs.img", Source: "etfs", Path: "/dev/ld0a",
			FsType: "blk", Mountpoint: "/data",
		}, r.Blk)
	})

	t.Run("no block devices leaves Blk at its zero value", func(t *testing.T) {
		r := &Rumprun{}
		err := r.Init(types.UnikernelParams{CmdLine: []string{"/init"}})
		assert.NoError(t, err)
		assert.Equal(t, RumprunBlk{}, r.Blk)
	})

	t.Run("only the first block device is used when several are given", func(t *testing.T) {
		// Kills a mutant that indexes data.Block[1] or otherwise drifts from
		// "always the first" -- Rumprun.Init only ever reads data.Block[0].
		r := &Rumprun{}
		err := r.Init(types.UnikernelParams{
			CmdLine: []string{"/init"},
			Block: []types.BlockDevParams{
				{ID: "first", Source: "/host/first.img", MountPoint: "/a"},
				{ID: "second", Source: "/host/second.img", MountPoint: "/b"},
			},
		})
		assert.NoError(t, err)
		assert.Equal(t, "/host/first.img", r.Blk.HostPath)
		assert.Equal(t, "/a", r.Blk.Mountpoint)
	})
}

func TestRumprunMonitorNetCli(t *testing.T) {
	cases := []struct {
		name    string
		monitor string
		want    []string
	}{
		{"hvt gets the tap/mac pair", "hvt", []string{"--net:tap=tap0", "--net-mac:tap=aa:bb:cc:dd:ee:ff"}},
		{"spt shares hvt's branch", "spt", []string{"--net:tap=tap0", "--net-mac:tap=aa:bb:cc:dd:ee:ff"}},
		{"any other monitor gets nil", "qemu", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Rumprun{Monitor: tc.monitor}
			assert.Equal(t, tc.want, r.MonitorNetCli("tap0", "aa:bb:cc:dd:ee:ff"))
		})
	}
}

func TestRumprunMonitorBlockCli(t *testing.T) {
	t.Run("hvt/spt always report a single fixed rootfs ID regardless of Blk contents", func(t *testing.T) {
		// Kills a mutant that starts reading r.Blk.Source or .Path into the
		// ID instead of the hardcoded "rootfs" -- see the TODO at
		// rumprun.go:155: urunc deliberately does not yet support arbitrary
		// Solo5 block IDs for Rumprun.
		r := &Rumprun{Monitor: "hvt", Blk: RumprunBlk{HostPath: "/host/rootfs.img"}}
		want := []types.MonitorBlockArgs{{ID: "rootfs", Path: "/host/rootfs.img"}}
		assert.Equal(t, want, r.MonitorBlockCli())
	})

	t.Run("any other monitor gets nil", func(t *testing.T) {
		r := &Rumprun{Monitor: "qemu", Blk: RumprunBlk{HostPath: "/host/rootfs.img"}}
		assert.Nil(t, r.MonitorBlockCli())
	})
}
