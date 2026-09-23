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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/urunc-dev/urunc/pkg/unikontainers/types"
)

func TestHyperlightBuildExecCmd(t *testing.T) {
	h := &Hyperlight{
		binaryPath: "/usr/local/bin/hyperlight-unikraft",
	}
	args := types.ExecArgs{
		UnikernelPath: "/path/to/unikernel",
		InitrdPath:    "/path/to/initrd",
		MemSizeB:      1024 * 1024 * 256,
	}

	cmd, err := h.BuildExecCmd(args, nil)
	assert.NoError(t, err)
	assert.Equal(t, []string{"/usr/local/bin/hyperlight-unikraft", "/path/to/unikernel", "--initrd", "/path/to/initrd", "--memory", "268435456"}, cmd)
}

// TestHyperlightBuildExecCmdZeroMemory kills a CONDITIONALS_BOUNDARY survivor
// at hyperlight.go:70 (`if args.MemSizeB > 0`). MemSizeB is a uint64, so it can
// never be negative -- `> 0` and `>= 0` are only distinguishable at exactly
// zero, and neither existing case here reaches it. A mutant flipping to `>= 0`
// would append "--memory 0" instead of omitting the flag.
func TestHyperlightBuildExecCmdZeroMemory(t *testing.T) {
	h := &Hyperlight{binaryPath: "/usr/local/bin/hyperlight-unikraft"}
	args := types.ExecArgs{UnikernelPath: "/path/to/unikernel"}

	cmd, err := h.BuildExecCmd(args, nil)
	assert.NoError(t, err)
	assert.Equal(t, []string{"/usr/local/bin/hyperlight-unikraft", "/path/to/unikernel"}, cmd)
}

func TestHyperlightBuildExecCmdNoInitrd(t *testing.T) {
	h := &Hyperlight{
		binaryPath: "/usr/local/bin/hyperlight-unikraft",
	}
	args := types.ExecArgs{
		UnikernelPath: "/path/to/unikernel",
		MemSizeB:      1024 * 1024 * 256,
	}

	cmd, err := h.BuildExecCmd(args, nil)
	assert.NoError(t, err)
	assert.Equal(t, []string{"/usr/local/bin/hyperlight-unikraft", "/path/to/unikernel", "--memory", "268435456"}, cmd)
}
