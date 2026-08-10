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

package unikontainers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzGetConfigFromJSON feeds arbitrary bytes as the contents of urunc.json,
// the fallback config source read straight from the guest rootfs whenever
// the OCI spec annotations are absent or fail validation. The only oracle is
// "no panic": json.Unmarshal and the subsequent base64 decode() pass must
// handle arbitrary, untrusted file content from a filesystem urunc does not
// control.
func FuzzGetConfigFromJSON(f *testing.F) {
	valid, _ := json.Marshal(&UnikernelConfig{
		UnikernelType:   "type1",
		UnikernelBinary: "binary1",
		Hypervisor:      "hypervisor1",
	})
	f.Add(valid)
	f.Add([]byte("{}"))
	f.Add([]byte("invalid json"))
	f.Add([]byte(`{"com.urunc.unikernel.block": "` + strings.Repeat("A", 4096) + `"}`))
	f.Add([]byte(`{"com.urunc.unikernel.hypervisor": null}`))
	f.Add([]byte(`{"com.urunc.unikernel.hypervisor": 12345}`))
	f.Add([]byte(`{"com.urunc.unikernel.hypervisor": ["a","b"]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		rootfsDir := filepath.Join(dir, rootfsDirName)
		if err := os.Mkdir(rootfsDir, 0o755); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(rootfsDir, uruncJSONFilename)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}

		conf, err := getConfigFromJSON(path)
		if err != nil {
			return
		}
		// decode() must not panic on any value json.Unmarshal was willing to
		// put into a string field, whatever those bytes happen to be.
		_ = conf.decode()
	})
}

// FuzzUnikernelConfigJSONDecode exercises the same json.Unmarshal + decode()
// path as FuzzGetConfigFromJSON, but entirely in-memory instead of round
// tripping through a temp file per iteration. getConfigFromJSON's file I/O
// caps that harness at ~600-5000 execs/sec; this one runs the same untrusted
// -input parse at native in-memory fuzzing throughput.
func FuzzUnikernelConfigJSONDecode(f *testing.F) {
	valid, _ := json.Marshal(&UnikernelConfig{
		UnikernelType:   "type1",
		UnikernelBinary: "binary1",
		Hypervisor:      "hypervisor1",
	})
	f.Add(valid)
	f.Add([]byte("{}"))
	f.Add([]byte("invalid json"))
	f.Add([]byte(`{"com.urunc.unikernel.block": "` + strings.Repeat("A", 4096) + `"}`))
	f.Add([]byte(`{"com.urunc.unikernel.hypervisor": null}`))
	f.Add([]byte(`{"com.urunc.unikernel.hypervisor": 12345}`))
	f.Add([]byte(`{"com.urunc.unikernel.hypervisor": ["a","b"]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var conf UnikernelConfig
		if err := json.Unmarshal(data, &conf); err != nil {
			return
		}
		// decode() must not panic on any value json.Unmarshal was willing to
		// put into a string field, whatever those bytes happen to be.
		_ = conf.decode()
	})
}
