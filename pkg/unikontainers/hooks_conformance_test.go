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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/urunc-dev/urunc/tests/fuzzing/known"
)

// OCI hook conformance.
//
// These targets check urunc's hook execution against explicit MUST clauses in
// the OCI runtime spec (v1.2.1, config.md). They are deliberately framed as
// CONFORMANCE checks, not security checks: maintainer feedback on urunc-dev/
// urunc#797 established the project's position that hooks come from the
// host-side engine (containerd/kubelet) and are trusted -- "whoever can set a
// hook is already executing arbitrary binaries". So the question these ask is
// not "can a hook do something bad" but "does urunc run a well-formed,
// trusted hook the way the spec says it must".
//
// Both findings below fire on completely legal, well-formed hook definitions.
// No malformed input is involved.

// uruncHookArgv mirrors the argv that executeHook (utils.go:345) actually
// builds:
//
//	args := hook.Args
//	if len(args) > 0 { args = args[1:] }
//	cmd := exec.CommandContext(ctx, hook.Path, args...)
//
// exec.CommandContext sets cmd.Args = append([]string{path}, args...), so
// argv[0] ends up being hook.Path.
//
// Copied rather than extracted so this file makes no production change. If
// executeHook's argv handling changes, this mirror must be updated or it
// silently stops being faithful.
func uruncHookArgv(h specs.Hook) []string {
	args := h.Args
	if len(args) > 0 {
		args = args[1:]
	}
	return append([]string{h.Path}, args...)
}

// ociHookArgv builds the argv the OCI runtime spec requires, which is what
// runc produces.
//
// config.md:555 defines hooks[].args as having "the same semantics as IEEE
// Std 1003.1-2008 execv's argv" -- i.e. args IS the full argv, args[0] being
// the program name. runc implements this literally
// (libcontainer/configs/config.go:595):
//
//	cmd := exec.Cmd{Path: c.Path, Args: c.Args, ...}
//
// os/exec falls back to []string{Path} when Args is empty, so the empty case
// agrees with urunc's.
func ociHookArgv(h specs.Hook) []string {
	if len(h.Args) == 0 {
		return []string{h.Path}
	}
	return h.Args
}

// FuzzHookArgvConstruction differentially compares the argv urunc builds for a
// hook against the argv the OCI spec mandates.
//
// This is a pure-function differential: no process is spawned, so it runs at
// full fuzzing speed. The two implementations must agree for every legal hook
// definition.
//
// Finding: they disagree whenever a hook supplies args at all and args[0] is
// not byte-identical to path. urunc drops args[0] and substitutes path, so the
// executed program sees a different argv[0] than the spec requires. This
// matters concretely for multi-call binaries -- busybox and friends dispatch
// on argv[0], so `path: /bin/busybox, args: ["wget", "-q", url]` runs the
// wrong applet under urunc.
func FuzzHookArgvConstruction(f *testing.F) {
	f.Add("/bin/busybox", "wget", "-q")
	f.Add("/usr/bin/cnitool", "cnitool", "add")
	f.Add("/bin/sh", "/bin/sh", "-c")
	f.Add("/bin/true", "", "")

	f.Fuzz(func(t *testing.T, path, arg0, arg1 string) {
		// A hook path is REQUIRED and MUST be absolute (config.md:554), so an
		// empty path is not a legal hook -- filtering it is input realism,
		// not hiding a defect.
		if path == "" {
			return
		}

		h := specs.Hook{Path: path}
		// Model the three legal shapes: no args, argv[0] only, argv[0]+one arg.
		switch {
		case arg0 == "" && arg1 == "":
			// leave Args nil
		case arg1 == "":
			h.Args = []string{arg0}
		default:
			h.Args = []string{arg0, arg1}
		}

		got := uruncHookArgv(h)
		want := ociHookArgv(h)

		if len(got) != len(want) {
			known.Expected(t, "finding-hook-argv", len(h.Args) > 0,
				"urunc built a %d-element argv where the OCI spec requires %d "+
					"for hook %#v:\n  urunc: %q\n  spec:  %q",
				len(got), len(want), h, got, want)
			return
		}
		for i := range got {
			if got[i] != want[i] {
				// SHAPE of the known defect: urunc replaces argv[0] with
				// hook.Path. Only index 0 may differ, and only when the hook
				// actually supplied args. A mismatch at any later index is a
				// different bug and fails loudly.
				knownShape := i == 0 && len(h.Args) > 0 && got[0] == h.Path
				known.Expected(t, "finding-hook-argv", knownShape,
					"argv element %d differs from what the OCI spec requires "+
						"for hook %#v:\n  urunc: %q\n  spec:  %q",
					i, h, got, want)
				return
			}
		}
	})
}

// TestHookArgvZeroIsPath is the deterministic, end-to-end proof of the argv[0]
// finding. It runs a real hook through the real executeHook and observes the
// argv[0] the spawned process actually saw.
//
// The hook deliberately exits non-zero: executeHook only surfaces the child's
// stdout inside its error string, so failing is the only way to read it back.
//
// Assertion is INVERTED, per the convention in tests/fuzzing/FUZZING_FINDINGS.md
// section 8: this is a characterization test for a tracked, unfixed finding, so
// it FAILS if the symptom ever stops reproducing -- which would mean urunc
// became spec-conformant and the catalogue needs updating, not that something
// newly broke.
func TestHookArgvZeroIsPath(t *testing.T) {
	const shell = "/bin/sh"
	if _, err := os.Stat(shell); err != nil {
		t.Skipf("harness needs %s (not a finding): %v", shell, err)
	}

	const canary = "CANARY_ARGV0"
	hook := specs.Hook{
		Path: shell,
		// Legal per config.md:555 -- args[0] is the program name, and it is
		// entirely normal for it to differ from path.
		Args: []string{canary, "-c", `printf "%s" "$0"; exit 1`},
	}

	err := executeHook(hook, []byte("{}"))
	if err == nil {
		t.Fatalf("harness problem: the hook was supposed to exit non-zero so its " +
			"stdout would be surfaced, but executeHook returned nil")
	}
	got := err.Error()

	if strings.Contains(got, canary) {
		t.Fatalf("expected the tracked hook-argv finding to still reproduce, but it "+
			"didn't: the hook saw argv[0]=%q, which is what the OCI spec requires. "+
			"urunc may now be conformant -- update FUZZING_FINDINGS.md instead of "+
			"this test.\n  executeHook error: %s", canary, got)
	}
	if !strings.Contains(got, shell) {
		t.Fatalf("hook saw neither the spec-mandated argv[0] (%q) nor urunc's "+
			"substituted path (%q); executeHook's argv handling changed in a way "+
			"this test does not model:\n  %s", canary, shell, got)
	}
}

// TestHookExecutionOrderIsNotPreserved is the deterministic proof that urunc
// violates config.md:589, "Hooks MUST be called in the listed order."
//
// ExecuteHooks (unikontainers.go:1035) dispatches to executeHooksConcurrently
// behind a hardcoded `if true`, spawning every hook in a goroutine at once. The
// code's own comment concedes the uncertainty: "It is possible that the
// concurrent execution of the hooks may cause some unknown problems down the
// line."
//
// runc executes them sequentially (libcontainer/configs/config.go:549).
//
// Real-world consequence: any ordered hook chain races. A createRuntime list
// where hook 1 provisions a resource and hook 2 configures it is a normal,
// spec-sanctioned pattern that urunc cannot run correctly.
//
// The first hook sleeps so that concurrent execution produces a deterministic
// INVERSION rather than a flaky interleaving.
//
// Assertion is INVERTED, same convention as above.
func TestHookExecutionOrderIsNotPreserved(t *testing.T) {
	const shell = "/bin/sh"
	if _, err := os.Stat(shell); err != nil {
		t.Skipf("harness needs %s (not a finding): %v", shell, err)
	}

	outFile := filepath.Join(t.TempDir(), "order.txt")

	mkHook := func(script string) specs.Hook {
		return specs.Hook{
			Path: shell,
			Args: []string{"sh", "-c", script},
		}
	}

	u := &Unikontainer{
		State: &specs.State{ID: "hook-order-conformance"},
		Spec: &specs.Spec{
			Hooks: &specs.Hooks{
				Poststart: []specs.Hook{
					// Listed first, so it MUST complete first.
					mkHook(fmt.Sprintf("sleep 0.4; printf 'FIRST' >> %q", outFile)),
					mkHook(fmt.Sprintf("printf 'SECOND' >> %q", outFile)),
				},
			},
		},
	}

	if err := u.ExecuteHooks("Poststart"); err != nil {
		t.Fatalf("harness problem: hooks themselves failed: %v", err)
	}

	raw, err := os.ReadFile(outFile) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatalf("harness problem: could not read hook output: %v", err)
	}
	got := string(raw)

	if got == "FIRSTSECOND" {
		t.Fatalf("expected the tracked hook-ordering finding to still reproduce, but "+
			"the hooks ran in the spec-mandated listed order (%q). urunc may now be "+
			"conformant with config.md:589 -- update FUZZING_FINDINGS.md instead of "+
			"this test.", got)
	}
	if got != "SECONDFIRST" {
		t.Fatalf("hooks produced %q, which is neither the spec-mandated order "+
			"(%q) nor the concurrent inversion this finding describes (%q); "+
			"ExecuteHooks changed in a way this test does not model.",
			got, "FIRSTSECOND", "SECONDFIRST")
	}
}
