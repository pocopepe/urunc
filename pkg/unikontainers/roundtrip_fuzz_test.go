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
	"github.com/urunc-dev/urunc/tests/fuzzing/known"
	"io"
	"strings"
	"testing"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"github.com/urunc-dev/urunc/pkg/unikontainers/types"
)

// discardLogs silences logrus for the duration of a fuzz run. The parsers
// under test log a WithFields record per call, and per-iteration I/O is a
// documented fuzz-target anti-pattern
// (https://github.com/google/fuzzing/blob/master/docs/good-fuzz-target.md):
// it both caps throughput and, over an overnight run, writes gigabytes of
// noise. Harnesses in this file call it before f.Fuzz.
func discardLogs() {
	logrus.SetOutput(io.Discard)
	logrus.SetLevel(logrus.PanicLevel)
}

// FuzzUruncConfigMapRoundTrip checks the round-trip contract between
// (*UruncConfig).Map and UruncConfigFromMap. These two are declared inverses:
// Map serialises a UruncConfig into the state.json annotation map
// (unikontainers.go writes it in New), and UruncConfigFromMap reconstructs
// the config from that same map when a later urunc invocation reloads the
// container (unikontainers.go:138, in Get). Anything urunc writes for a
// container it must be able to read back identically for that same
// container; a field that does not survive the round trip is silently
// changing a running sandbox's configuration between the create call and
// every subsequent start/exec/delete call.
//
// This is a far stronger oracle than "does not panic": Go is memory safe, so
// a parser fuzzed only for panics has almost nothing to fail on, while a
// round-trip property fails on any lossy or ambiguous encoding.
func FuzzUruncConfigMapRoundTrip(f *testing.F) {
	discardLogs()

	f.Add("qemu", uint(256), uint(1), "/usr/bin/qemu-system-x86_64", "/usr/share/qemu", false,
		"virtiofsd", "/usr/libexec/virtiofsd", "--cache always --sandbox none")
	f.Add("hvt", uint(512), uint(2), "", "", true, "virtiofsd", "/a", "")
	f.Add("cloud-hypervisor", uint(1024), uint(4), "/x", "/y", true, "eb", "/p", "-o")
	f.Add("", uint(256), uint(1), "", "", false, "", "", "")

	f.Fuzz(func(t *testing.T, mon string, mem, vcpus uint, binPath, dataPath string, vhost bool,
		ebName, ebPath, ebOpts string) {
		orig := &UruncConfig{
			Monitors: map[string]types.MonitorConfig{
				mon: {
					DefaultMemoryMB: mem,
					DefaultVCPUs:    vcpus,
					BinaryPath:      binPath,
					DataPath:        dataPath,
					Vhost:           vhost,
				},
			},
			ExtraBins: map[string]types.ExtraBinConfig{
				ebName: {Path: ebPath, Options: ebOpts},
			},
		}

		got := UruncConfigFromMap(orig.Map())
		if got == nil {
			t.Fatalf("UruncConfigFromMap returned nil for %#v", orig)
		}

		// Finding 5: Map() writes urunc_config.monitors.<name>.<field>, and
		// UruncConfigFromMap recovers the name by splitting on "." and
		// requiring exactly 4 parts. A monitor name containing a dot yields
		// 5+ parts and the whole entry is silently dropped. Fires on any
		// dotted name, which wedged this target.
		//
		// SHAPE: the monitor name contains a ".". A DOT-FREE name being
		// dropped is a different defect and fails loudly.
		gotMon, ok := got.Monitors[mon]
		if !ok {
			known.Expected(t, "finding-5", strings.Contains(mon, "."),
				"monitor %q was written to the state.json map by Map() but "+
					"UruncConfigFromMap did not read it back at all (map: %#v)",
				mon, orig.Map())
			return
		}
		// The SAME missing-fixup defect (finding 6) also shows up here as a
		// value mismatch rather than a dropped monitor: a field written as 0
		// reads back as the built-in default. SHAPE: every field that differs
		// was ZERO when written. Any other difference is real data corruption
		// and fails loudly.
		if gotMon != orig.Monitors[mon] {
			w, r := orig.Monitors[mon], gotMon
			onlyZeroFieldsChanged := (w.DefaultMemoryMB == r.DefaultMemoryMB || w.DefaultMemoryMB == 0) &&
				(w.DefaultVCPUs == r.DefaultVCPUs || w.DefaultVCPUs == 0) &&
				w.BinaryPath == r.BinaryPath && w.DataPath == r.DataPath && w.Vhost == r.Vhost
			known.Expected(t, "finding-6", onlyZeroFieldsChanged,
				"monitor %q did not survive the Map()/UruncConfigFromMap "+
					"round trip through state.json:\n  wrote: %#v\n  read:  %#v",
				mon, orig.Monitors[mon], gotMon)
		}

		// Extra binaries are keyed the same way as monitors, so finding 5's
		// dot-splitting defect applies identically here.
		gotEB, ok := got.ExtraBins[ebName]
		if !ok {
			known.Expected(t, "finding-5", strings.Contains(ebName, "."),
				"extra binary %q was written by Map() but UruncConfigFromMap "+
					"did not read it back at all (map: %#v)", ebName, orig.Map())
			return
		}
		if gotEB != orig.ExtraBins[ebName] {
			known.Expected(t, "finding-5", strings.Contains(ebName, "."),
				"extra binary %q did not survive the Map()/UruncConfigFromMap "+
					"round trip through state.json:\n  wrote: %#v\n  read:  %#v",
				ebName, orig.ExtraBins[ebName], gotEB)
			return
		}
	})
}

// FuzzUnikernelConfigSpecRoundTrip checks the same inverse property for the
// OCI-annotation side: (*UnikernelConfig).Map produces the
// com.urunc.unikernel.* annotation set that the containerd shim attaches to
// the container (guest_rootfs.go), and getConfigFromSpec parses that same
// annotation set back out of the OCI spec. A field that does not survive
// this round trip means the unikernel is launched with a different
// configuration than the image asked for.
func FuzzUnikernelConfigSpecRoundTrip(f *testing.F) {
	discardLogs()

	// UnikernelCmd was removed from UnikernelConfig upstream, so the struct and
	// this target now carry ten fields rather than eleven.
	f.Add("qemu", "1.0", "/unikernel/app", "hvt", "/initrd", "/.boot/disk", "/data", "true", "tap0", "blk0")
	f.Add("", "", "", "", "", "", "", "", "", "")
	f.Add("rumprun", "", "bin", "spt", "", "", "", "false", "", "")

	f.Fuzz(func(t *testing.T, ukType, ukVer, bin, hv, initrd, block, blkMnt, mountRootfs, netDev, blkDev string) {
		orig := UnikernelConfig{
			UnikernelType:    ukType,
			UnikernelVersion: ukVer,
			UnikernelBinary:  bin,
			Hypervisor:       hv,
			Initrd:           initrd,
			Block:            block,
			BlkMntPoint:      blkMnt,
			MountRootfs:      mountRootfs,
			NetDev:           netDev,
			BlkDev:           blkDev,
		}

		spec := &specs.Spec{Annotations: orig.Map()}
		got := getConfigFromSpec(spec)
		if got == nil {
			t.Fatalf("getConfigFromSpec returned nil for annotations %#v", spec.Annotations)
		}
		if *got != orig {
			t.Fatalf("UnikernelConfig did not survive the Map()/getConfigFromSpec "+
				"round trip through the OCI annotations:\n  wrote: %#v\n  read:  %#v\n  annotations: %#v",
				orig, *got, spec.Annotations)
		}
	})
}
