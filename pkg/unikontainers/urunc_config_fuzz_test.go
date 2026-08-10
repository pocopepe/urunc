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
	"testing"

	"github.com/BurntSushi/toml"
)

// FuzzUruncConfigTOML feeds arbitrary strings as /etc/urunc/config.toml
// content through the same toml.Decode call LoadUruncConfig and
// ParseLogMetricsConfig make (minus the file I/O, decoded in-memory instead
// for fuzzing throughput -- the same design choice FuzzUnikernelConfigJSONDecode
// makes for the OCI-annotation JSON parser). The oracle: decoding arbitrary,
// untrusted TOML must never panic, and Map() must not panic on whatever
// toml.Decode was willing to put into UruncConfig's fields, however it was
// partially populated.
func FuzzUruncConfigTOML(f *testing.F) {
	seeds := []string{
		"",
		"[log]\nlevel = \"info\"\nsyslog = true\n",
		"[timestamps]\nenabled = true\ndestination = \"/tmp/x\"\n",
		"[monitors.qemu]\ndefault_memory_mb = 512\ndefault_vcpus = 2\n",
		"[monitors.qemu]\nbinary_path = \"/usr/bin/qemu\"\n",
		"[extra_binaries.virtiofsd]\npath = \"/a\"\noptions = \"--cache always\"\n",
		"not valid toml {{{",
		"[monitors]\nqemu = \"not-a-table\"\n",
		"[[monitors]]\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data string) {
		var cfg UruncConfig
		if _, err := toml.Decode(data, &cfg); err != nil {
			return
		}
		// Map() must not panic regardless of how sparsely/oddly toml.Decode
		// populated cfg from arbitrary input.
		_ = cfg.Map()

		var lmc LogMetricsUruncConfig
		_, _ = toml.Decode(data, &lmc)
	})
}
