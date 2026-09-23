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

	fuzzheaders "github.com/AdaLogics/go-fuzz-headers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/urunc-dev/urunc/pkg/unikontainers/types"
)

// allUnikernelTypes is every type unikernels.New dispatches on.
var allUnikernelTypes = []string{
	RumprunUnikernel, UnikraftUnikernel, MirageUnikernel,
	MewzUnikernel, LinuxUnikernel, HermitUnikernel,
}

// FuzzUnikernelInit drives the full per-unikernel command-line construction
// path with a structure-aware input, the same technique runc's OSS-Fuzz
// harnesses use (cncf-fuzzing/projects/runc/specconv_fuzzer.go builds a whole
// specs.Spec with gofuzzheaders.GenerateStruct rather than fuzzing a string).
// Here the generated value is a types.UnikernelParams -- the struct urunc
// assembles from the OCI spec, the image annotations and the network setup --
// and it is pushed through Init and then every accessor a monitor invocation
// touches, for all six supported unikernel types.
//
// Oracle: none of this may panic for any generated parameter set, on any of
// the six types.
//
// An earlier revision of this harness also asserted that a successful
// CommandString must be non-empty. That was withdrawn as a false positive:
// Mewz legitimately returns ("", nil) when no network address is configured,
// and an empty command reaches the monitors only as `-append ""` /
// `--cmdline ""`, which is harmless. There is no documented contract that a
// unikernel must produce a non-empty command line.
func FuzzUnikernelInit(f *testing.F) {
	f.Add([]byte("mirage-seed-input-padding-0000000000"))
	f.Add([]byte("linux-seed-input-padding-00000000000"))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 16 {
			return
		}
		c := fuzzheaders.NewConsumer(data)

		params := types.UnikernelParams{}
		if err := c.GenerateStruct(&params); err != nil {
			return
		}

		for _, ut := range allUnikernelTypes {
			u, err := New(ut)
			if err != nil {
				t.Fatalf("New(%q) failed although it is a supported type: %v", ut, err)
			}
			if err := u.Init(params); err != nil {
				continue
			}

			if _, err := u.CommandString(); err != nil {
				continue
			}

			// Accessors a monitor invocation reaches after Init.
			_ = u.SupportsBlock()
			_ = u.SupportsFS(params.Rootfs.Type)
			_ = u.MonitorNetCli(params.Net.TapDev, params.Net.MAC)
			_ = u.MonitorBlockCli()
			_ = u.MonitorCli()
		}
	})
}

// TestUnikernelNew was FuzzUnikernelNew: a fixed, seven-way switch dispatcher
// has no adversarial shape to explore -- every input either matches one of
// six hardcoded strings or doesn't, and fuzzing that finite a decision found
// nothing across every campaign. A plain table test covers the same property
// (the six identifiers dispatch, everything else is rejected) with the same
// confidence for less machinery.
func TestUnikernelNew(t *testing.T) {
	for _, k := range allUnikernelTypes {
		t.Run(k, func(t *testing.T) {
			u, err := New(k)
			require.NoError(t, err)
			require.NotNil(t, u)
		})
	}

	for _, bad := range []string{"", "nonsense", "Linux", " linux"} {
		t.Run("rejects "+bad, func(t *testing.T) {
			_, err := New(bad)
			assert.Error(t, err)
		})
	}
}
