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
	"slices"
	"strings"
	"testing"

	"github.com/urunc-dev/urunc/tests/fuzzing/known"

	"github.com/urunc-dev/urunc/pkg/unikontainers/types"
)

// section returns the lines strictly between the start and end marker lines.
func section(lines []string, start, end string) ([]string, bool) {
	s, e := -1, -1
	for i, l := range lines {
		if l == start && s == -1 {
			s = i
		} else if l == end && s != -1 {
			e = i
			break
		}
	}
	if s == -1 || e == -1 {
		return nil, false
	}
	return lines[s+1 : e], true
}

// FuzzBuildUrunitConfig checks the structural integrity of the urunit config
// blob. buildUrunitConfig serialises the guest's environment, process config
// and block mounts into a newline-delimited format delimited by the UES/UEE,
// UCS/UCE and UBS/UBE marker lines, which urunit parses inside the guest.
// Every value it writes -- env entries, working directory, block IDs and
// mount points -- comes from the OCI spec and is therefore controlled by
// whoever supplies the image.
//
// Oracle: the environment section must contain exactly the entries that went
// in. If a value can introduce a newline or forge a marker line, the guest
// parses a different configuration than urunc intended.
func FuzzBuildUrunitConfig(f *testing.F) {
	f.Add("PATH=/usr/bin", "HOME=/root", "/work", uint32(0), uint32(0), "blk0", "/data", "qemu")
	f.Add("A=1", "B=2", "/", uint32(1000), uint32(1000), "id", "/mnt", "firecracker")
	f.Add("", "", "", uint32(0), uint32(0), "", "", "")

	f.Fuzz(func(t *testing.T, env1, env2, workDir string, uid, gid uint32,
		blkID, blkMP, monitor string) {
		l := &Linux{
			Env:        []string{env1, env2},
			Monitor:    monitor,
			ProcConfig: types.ProcessConfig{UID: uid, GID: gid, WorkDir: workDir},
			Blk:        []types.BlockDevParams{{ID: blkID, MountPoint: blkMP}},
		}

		out := l.buildUrunitConfig()
		lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")

		envLines, ok := section(lines, envStartMarker, envEndMarker)
		if !ok {
			t.Fatalf("buildUrunitConfig produced no well-formed %s/%s section for "+
				"env %q -- the guest cannot locate the environment block:\n%s",
				envStartMarker, envEndMarker, l.Env, out)
		}
		// Finding 3: env values are written raw into a newline-delimited
		// format, so a value can forge a line boundary in TWO distinct ways --
		// see tests/fuzzing/known for the root cause. Both were meant to be
		// covered by this suppression from the start (the message below has
		// always said "a line boundary or a marker"), but only the newline
		// half was actually implemented in shapeOK until a background fuzz
		// campaign's own accumulated corpus found the second one live: an env
		// value of exactly "UEE" (env1=["UEE","0"]) forged the env section's
		// own end marker one line early, with NO embedded newline anywhere in
		// the input. That is a STRICTLY EASIER trigger than the newline case
		// -- any six-character exact match, no multi-line value required --
		// so it is folded into finding-3 (same root cause: unescaped
		// marker-delimited serialization) rather than tracked as a separate
		// finding.
		//
		// SHAPE of the known defect: some env value either contains a
		// newline, OR one of its newline-split lines exactly equals one of
		// the six marker strings this format uses. A structural break that
		// matches neither is a different defect and fails loudly.
		envHasNewline := false
		envHasMarkerLine := false
		markers := []string{envStartMarker, envEndMarker, lpcStartMarker, lpcEndMarker, blkStartMarker, blkEndMarker}
		for _, e := range l.Env {
			if strings.ContainsAny(e, "\n\r") {
				envHasNewline = true
			}
			for _, line := range strings.Split(e, "\n") {
				if slices.Contains(markers, line) {
					envHasMarkerLine = true
				}
			}
		}
		knownShape := envHasNewline || envHasMarkerLine

		if len(envLines) != len(l.Env) {
			known.Expected(t, "finding-3", knownShape,
				"buildUrunitConfig wrote %d environment line(s) for %d "+
					"environment entries %q -- a value forged a line boundary or a "+
					"marker, so urunit reads a different environment than urunc set:\n%s",
				len(envLines), len(l.Env), l.Env, out)
			return
		}
		for i, got := range envLines {
			if got != l.Env[i] {
				known.Expected(t, "finding-3", knownShape,
					"environment entry %d round-tripped as %q instead of %q:\n%s",
					i, got, l.Env[i], out)
				return
			}
		}
	})
}

// FuzzParseCmdLine checks the quoting scheme parseCmdLine applies to the
// image's command line. It wraps any argument containing a space in single
// quotes so urunit can re-split it, but performs no escaping of quotes
// already present in the argument.
//
// Oracle: the emitted command must carry balanced single quotes. An argument
// that contributes an odd number of quote characters leaves the rest of the
// command line inside or outside a quoted region depending on where the
// splitter happens to be, which silently changes the guest's argv.
func FuzzParseCmdLine(f *testing.F) {
	f.Add("/bin/sh", "-c", "echo hi")
	f.Add("app", "arg with space", "plain")
	f.Add("app", "", "")

	f.Fuzz(func(t *testing.T, a0, a1, a2 string) {
		l := newLinux()
		if err := l.parseCmdLine([]string{a0, a1, a2}); err != nil {
			return
		}
		joined := l.App + " " + l.Command
		if n := strings.Count(joined, "'"); n%2 != 0 {
			// SUPPRESSION of finding-4 (dup of upstream #897): parseCmdLine
			// wraps any arg containing a space in single quotes but never
			// escapes a quote already present in the arg itself. SHAPE: one
			// of the raw arguments contains a literal "'" -- that's the only
			// way this class of imbalance can occur.
			quoteInInput := strings.ContainsAny(a0+a1+a2, "'")
			known.Expected(t, "finding-4", quoteInInput,
				"parseCmdLine(%q) produced %q, which contains %d single "+
					"quote(s) -- unbalanced, so urunit's re-split of this command "+
					"line does not recover the original arguments",
				[]string{a0, a1, a2}, joined, n)
			return
		}
	})
}
