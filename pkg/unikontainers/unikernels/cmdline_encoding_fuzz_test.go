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

	"github.com/urunc-dev/urunc/pkg/unikontainers/types"

	"github.com/urunc-dev/urunc/tests/fuzzing/known"
)

// Guest kernel command-line encoding.
//
// (*Linux).CommandString builds the guest's boot command line by space-joining
// fragments:
//
//	bootParams += " " + eVar        // linux.go:111, for every spec.Process.Env entry
//
// The Linux kernel splits its command line on WHITESPACE. So this is a format
// boundary: urunc encodes into a whitespace-delimited format consumed by a
// different codebase (the guest kernel), with no escaping and no validation.
//
// PR #858 ("replace string concatenation in CLI construction") eliminated this
// class on the MONITOR side, where argv is now built with append() on a
// []string. The GUEST side was not part of that change and still concatenates.
//
// Reached whenever InitrdConf is false, i.e.
// `l.InitrdConf = strings.Contains(l.App, "urunit")` (linux.go:248) -- any Linux
// guest whose binary is not urunit. That is an ordinary deployment, not an edge
// case.

// kernelFields splits a command line the way the Linux kernel does, and NOT the
// way Go's strings.Fields does.
//
// This distinction is load-bearing. The kernel's parser (kernel/params.c,
// next_arg/parse_args) is byte-oriented and separates parameters on ASCII space
// and tab. strings.Fields uses unicode.IsSpace, so it also splits on U+2000 EN
// QUAD, U+00A0 NBSP and friends -- which the kernel would happily keep inside a
// single parameter as UTF-8 bytes.
//
// An earlier revision of this harness used strings.Fields as the reference and
// reported "= " as a new defect. It was not: the oracle's model of the
// consumer was wrong. A differential is only as good as its model of the other
// side, so the model has to come from the consumer's actual parsing rule rather
// than from whatever the standard library makes convenient.
func kernelFields(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t'
	})
}

// FuzzLinuxCmdlineEnvEncoding checks that a guest env entry survives encoding
// into the kernel command line as exactly one kernel parameter.
//
// Property: spec.Process.Env is a []string of opaque KEY=VALUE entries. OCI
// places no constraint on the VALUE, and a value containing a space is entirely
// ordinary (`docker run -e "GREETING=hello world"`). Encoding N entries into a
// whitespace-delimited command line must not produce more than N parameters from
// them, or the guest kernel sees parameters urunc never intended to set.
//
// Measured consequence, from the seed corpus: an entry of "A=1 root=/dev/sda1"
// emits
//
//	panic=-1 console=ttyS0 root=/dev/vda rw A=1 root=/dev/sda1 init=... --
//
// The env-derived root= appears AFTER urunc's own root=, and the kernel honours
// the last occurrence, so the guest's root device is silently redirected.
func FuzzLinuxCmdlineEnvEncoding(f *testing.F) {
	f.Add("PATH=/usr/bin", "block")
	f.Add("GREETING=hello world", "block")
	f.Add("A=1 root=/dev/sda1", "block")
	f.Add("MSG=x init=/bin/sh", "initrd")

	f.Fuzz(func(t *testing.T, envEntry, rootfsType string) {
		// Input realism: these are the rootfs types Linux guests actually
		// support; anything else exercises the harness, not the encoder.
		switch rootfsType {
		case "block", "initrd", "9pfs", "virtiofs":
		default:
			return
		}
		// An env entry is KEY=VALUE. An entry with no "=" is not something the
		// OCI runtime would hand over, and filtering it keeps the oracle aimed
		// at the encoding rather than at malformed input.
		if !strings.Contains(envEntry, "=") {
			return
		}

		l := newLinux()
		err := l.Init(types.UnikernelParams{
			// App must not contain "urunit", or InitrdConf flips true and the
			// env entries are not written to the cmdline at all (linux.go:248).
			CmdLine: []string{"/sbin/myinit"},
			EnvVars: []string{envEntry},
			Monitor: "qemu",
			Rootfs:  types.RootfsParams{Type: rootfsType},
		})
		if err != nil {
			return
		}
		if l.InitrdConf {
			return // urunit path -- covered by FuzzBuildUrunitConfig instead
		}

		out, err := l.CommandString()
		if err != nil {
			return
		}

		// The entry must appear as a contiguous, single parameter. The predicate
		// is "contains an ASCII space or tab", matching kernelFields above.
		//
		// This harness got the predicate wrong twice, and the loud branch below
		// caught both within seconds -- worth recording, because both were the
		// same mistake in different clothes:
		//
		//  1. using len(strings.Fields(entry)) > 1 as a proxy. Fields strips
		//     leading/trailing whitespace, so " =" counted as one field and fell
		//     through to the verbatim check, which it could not pass.
		//  2. verifying with strings.Fields(out), which is Unicode-aware, so
		//     "= " looked fragmented even though the kernel would keep it
		//     whole.
		//
		// Both were the oracle mis-modelling the consumer. That is the failure
		// mode differential testing is most prone to, and the reason the
		// reference model belongs in a named function with its source cited.
		if strings.ContainsAny(envEntry, " \t") {
			// SUPPRESSION of F6. SHAPE: ASCII space/tab in the entry means it
			// cannot survive as a single parameter in a whitespace-delimited
			// format. An entry with NO whitespace that still fails to survive
			// is a different defect and fails loudly below.
			known.Expected(t, "finding-cmdline-env-split", true,
				"env entry %q was encoded into the guest kernel command line as "+
					"multiple kernel parameters instead of 1. The kernel splits "+
					"its command line on whitespace and honours the LAST occurrence "+
					"of a repeated parameter, so an ordinary env value can silently "+
					"override a boot parameter urunc set earlier "+
					"(root=, init=, console=, panic=).\n  cmdline: %s",
				envEntry, out)
			return
		}

		// No whitespace in the entry: it must survive verbatim as one field.
		found := false
		for _, field := range kernelFields(out) {
			if field == envEntry {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("env entry %q did not survive encoding into the kernel command "+
				"line as a single parameter, and it contains no ASCII space or tab -- "+
				"this is "+
				"not the known whitespace-splitting shape:\n  cmdline: %s", envEntry, out)
		}
	})
}
