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
	"strconv"
	"strings"
	"testing"

	"github.com/urunc-dev/urunc/tests/fuzzing/known"
)

// FuzzUruncConfigTOML (decode arbitrary bytes as config.toml, assert only that
// it doesn't panic) was retired: crash-only oracle, found nothing across every
// campaign run, and TOML parsing is BurntSushi/toml's problem to fuzz, not
// urunc's -- urunc's own contribution here is Map()'s handling of a sparsely
// populated struct, which FuzzUruncConfigFromMap already exercises directly.

// FuzzUruncConfigFromMap feeds arbitrary "key=value" lines, encoding an
// arbitrary state.json urunc_config.* map, through UruncConfigFromMap -- the
// state-restore counterpart to LoadUruncConfig, called on every container
// resume/exec with a map this process did not necessarily produce itself.
// Go's fuzzing engine only mutates the primitive types testing.F.Add
// accepts (no map[string]string), so the map is round-tripped through a
// newline-delimited "key=value" blob and rebuilt inside the harness.
//
// Confirmed bug (reproduced by hand before writing this harness):
// LoadUruncConfig re-applies defaultMonitorMemoryMB/defaultMonitorVCPUs to
// any monitor entry the TOML decode left at zero (see the fixup loop in
// urunc_config.go), but UruncConfigFromMap has no equivalent fixup. A monitor
// name outside the five built-ins (qemu/hvt/spt/firecracker/cloud-hypervisor)
// that appears in cfgMap without an explicit default_memory_mb/default_vcpus
// entry is left with DefaultMemoryMB=0, DefaultVCPUs=0 -- and
// unikontainers.go reads those two fields directly as the VM's memory/vCPU
// count whenever the OCI spec does not override them. This oracle encodes
// that invariant so every newly-discovered monitor name in the corpus gets
// checked against it.
func FuzzUruncConfigFromMap(f *testing.F) {
	seeds := []string{
		"",
		"urunc_config.monitors.qemu.default_memory_mb=512",
		"urunc_config.monitors.qemu.default_vcpus=2\nurunc_config.monitors.qemu.binary_path=/usr/bin/qemu",
		"urunc_config.monitors.qemu.vhost=true",
		"urunc_config.monitors.qemu.vhost=not-a-bool",
		"urunc_config.monitors.qemu.default_memory_mb=-1",
		"urunc_config.monitors.qemu.default_memory_mb=99999999999999999999",
		"urunc_config.extra_binaries.virtiofsd.path=/a\nurunc_config.extra_binaries.virtiofsd.options=--cache always",
		"not_urunc_config_prefixed=value",
		"urunc_config.monitors.a.b.c.d=x",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, blob string) {
		cfgMap := make(map[string]string)
		for _, line := range strings.Split(blob, "\n") {
			key, val, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			cfgMap[key] = val
		}

		cfg := UruncConfigFromMap(cfgMap)
		if cfg == nil {
			t.Fatalf("UruncConfigFromMap(%v) returned nil", cfgMap)
		}
		// Map() must not panic on whatever UruncConfigFromMap built from
		// arbitrary keys/values.
		_ = cfg.Map()

		// Finding 6: LoadUruncConfig re-applies defaultMonitorMemoryMB /
		// defaultMonitorVCPUs to any monitor left at zero; its state.json
		// counterpart UruncConfigFromMap does not. Fires whenever a monitor
		// arrives without explicit numeric keys, which wedged this target.
		//
		// SHAPE: the map genuinely did not carry an explicit non-zero value
		// for that monitor's field. If the map DID specify a value and it
		// still came back zero, that is data loss, a different defect.
		for hv, mon := range cfg.Monitors {
			if mon.DefaultMemoryMB == 0 || mon.DefaultVCPUs == 0 {
				memKey := "urunc_config.monitors." + hv + ".default_memory_mb"
				cpuKey := "urunc_config.monitors." + hv + ".default_vcpus"
				// A value only counts as "supplied" if it actually parses to a
				// non-zero number. Absent, empty, "0", or unparseable garbage
				// like "A" all mean the same thing to UruncConfigFromMap:
				// nothing usable arrived, so the field stays zero. That is
				// exactly finding 6's shape.
				// Deliberately NOT TrimSpace: production parses the raw string
				// with strconv.Atoi, so " 1" fails there and leaves the field
				// zero. Trimming here would make the predicate more lenient
				// than the code and mis-label finding 6 as a new defect.
				// Mirrors urunc_config.go's acceptance test EXACTLY:
				//     if intVal, err := strconv.Atoi(val); err == nil && intVal > 0
				// so "", "0", "-1", " 1" and "A" are all equally "not supplied"
				// as far as the production code is concerned. Getting this
				// predicate even slightly more lenient than the code mislabels
				// finding 6 as a new defect -- which it did, three times, until
				// this was copied verbatim from the source.
				validNonZero := func(v string) bool {
					n, err := strconv.Atoi(v)
					return err == nil && n > 0
				}
				suppliedMem := cfgMap[memKey]
				suppliedCPU := cfgMap[cpuKey]
				knownShape := (mon.DefaultMemoryMB != 0 || !validNonZero(suppliedMem)) &&
					(mon.DefaultVCPUs != 0 || !validNonZero(suppliedCPU))
				known.Expected(t, "finding-6", knownShape,
					"UruncConfigFromMap(%v) left monitor %q with a zero "+
						"default (mem=%d vcpus=%d) even though the map supplied "+
						"mem=%q vcpus=%q -- that is data loss, not the missing-fixup defect",
					cfgMap, hv, mon.DefaultMemoryMB, mon.DefaultVCPUs, suppliedMem, suppliedCPU)
				return
			}
		}
	})
}
