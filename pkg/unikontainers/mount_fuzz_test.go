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
)

// FuzzSplitMountOptions checks that no mount option is silently dropped.
//
// splitMountOptions is reached from applyMount (mount.go:392) with
// m.Options taken straight from the OCI spec's mounts[].options, so every
// string here is supplied by whoever wrote the container config. It sorts each
// option into one of three buckets: a propagation flag, a VFS flag folded into
// a bitmask, or an opaque option forwarded to containerd.
//
// Conservation property: every input option must be accounted for in exactly
// the bucket the code's own rules dictate. Concretely, an option that is
// neither a propagation flag nor (for bind mounts) a VFS flag has nowhere else
// to go and must appear in containerdOpts. An option that vanishes is a mount
// silently performed with different semantics than the spec asked for --
// dropping "ro" or "nosuid" weakens the sandbox rather than strengthening it.
//
// The oracle also asserts the VFS bitmask, and the story of why is worth
// keeping. An earlier version of this comment argued the opposite:
//
//	"The oracle deliberately does not assert an exact vfsFlags value: the
//	 clear flags ("rw" clears MS_RDONLY) make the result order-dependent by
//	 design, and pinning a specific bitmask would encode the implementation
//	 rather than a contract."
//
// The hazard it names is real -- recomputing the mask the same way the
// implementation does and comparing would be circular, testing nothing. But
// the conclusion was wrong, and MUTATION TESTING proved it: flipping the
// implementation's `vfsFlags &^= flag` (clear) to `|=` (set) was caught by
// nothing here, which means a bug that silently failed to apply "nosuid" or
// "ro" to a mount would have gone unnoticed indefinitely.
//
// Order-dependence is not a reason to assert nothing; it is the clue to what
// the actual contract is: LAST WRITER WINS per flag bit. For each flag any
// option mentions, find the last option that mentions it -- the bit must be
// set iff that option was the setting variant. That is expressed purely in
// terms of mapVFSFlag's semantics, so it stays a contract rather than a copy
// of the loop.
func FuzzSplitMountOptions(f *testing.F) {
	f.Add("ro", "nosuid", "rprivate", true)
	f.Add("rw", "size=65536k", "", false)
	f.Add("nodev", "noexec", "slave", true)
	f.Add("", "", "", false)
	f.Add("relatime", "norelatime", "mode=755", false)

	f.Fuzz(func(t *testing.T, o1, o2, o3 string, isBind bool) {
		options := []string{o1, o2, o3}

		containerdOpts, propagation, vfsFlags := splitMountOptions(options, isBind)

		// Last-writer-wins per flag bit (see the comment above for why this
		// specific property, and how mutation testing forced it).
		type lastRef struct {
			clear bool
			opt   string
		}
		lastFor := map[uintptr]lastRef{}
		for _, o := range options {
			if _, err := mapRootfsPropagationFlag(o); err == nil {
				continue // consumed as propagation, never folded into the mask
			}
			flag, clear, err := mapVFSFlag(o)
			if err != nil {
				continue
			}
			lastFor[flag] = lastRef{clear: clear, opt: o}
		}
		for flag, ref := range lastFor {
			got := vfsFlags&flag != 0
			want := !ref.clear
			if got != want {
				verb := "set"
				if ref.clear {
					verb = "cleared"
				}
				t.Fatalf("splitMountOptions(%q, isBind=%v) returned VFS mask %#x, but the last "+
					"option affecting flag %#x was %q, which should have %s it (bit=%v want=%v). "+
					"This mask goes to mount(2), so a wrong bit means the mount silently gets "+
					"different protection flags than the spec asked for.",
					options, isBind, vfsFlags, flag, ref.opt, verb, got, want)
			}
		}

		inContainerd := make(map[string]int, len(containerdOpts))
		for _, o := range containerdOpts {
			inContainerd[o]++
		}

		wantPropagation := 0
		for _, o := range options {
			if _, err := mapRootfsPropagationFlag(o); err == nil {
				wantPropagation++
				// A propagation flag is consumed into the propagation slice and
				// must not also be forwarded to containerd.
				continue
			}
			if _, _, err := mapVFSFlag(o); err == nil && isBind {
				// For bind mounts a VFS flag is folded into the bitmask and
				// applied separately, so it is intentionally not forwarded.
				continue
			}
			// Everything else has no other bucket: it must reach containerd.
			if inContainerd[o] == 0 {
				t.Fatalf("splitMountOptions(%q, isBind=%v) dropped option %q: it is "+
					"not a propagation flag, it is not a VFS flag being folded into "+
					"the bitmask, and it does not appear in the containerd options "+
					"either.\n  containerdOpts=%q propagation=%v",
					options, isBind, o, containerdOpts, propagation)
			}
			inContainerd[o]--
		}

		if len(propagation) != wantPropagation {
			t.Fatalf("splitMountOptions(%q, isBind=%v) returned %d propagation "+
				"flag(s) but %d of the options are propagation flags",
				options, isBind, len(propagation), wantPropagation)
		}
	})
}

// FuzzMapVFSFlag locks down the disjointness the option sorting depends on.
//
// splitMountOptions consults mapRootfsPropagationFlag FIRST and `continue`s on
// success, so any option accepted by both tables would be silently swallowed as
// a propagation flag and never folded into the VFS bitmask -- a mount would
// then be performed without the flag the spec asked for. The two tables are
// disjoint today; this target keeps them that way against future edits.
//
// It also asserts that an accepted option never maps to a zero bitmask, since
// such an option would parse successfully and then have no effect at all.
//
// An earlier revision of this target also required every flag to have an
// opposite-clear counterpart ("ro"/"rw"). That was withdrawn as a false
// positive: `dirsync` legitimately has no `nodirsync`, matching mount(8) in
// util-linux, so the asymmetry is correct rather than a defect.
func FuzzMapVFSFlag(f *testing.F) {
	for _, s := range []string{
		"ro", "rw", "nosuid", "dirsync", "rprivate", "slave", "bogus", "",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, opt string) {
		flag, _, vfsErr := mapVFSFlag(opt)
		_, propErr := mapRootfsPropagationFlag(opt)

		if vfsErr == nil && propErr == nil {
			t.Fatalf("option %q is accepted by BOTH mapVFSFlag and "+
				"mapRootfsPropagationFlag. splitMountOptions checks propagation "+
				"first and skips the rest, so this option would never reach the "+
				"VFS bitmask and the mount would lose that flag", opt)
		}
		if vfsErr == nil && flag == 0 {
			t.Fatalf("mapVFSFlag(%q) reported success but returned a zero bitmask, "+
				"so the option parses cleanly and then has no effect on the mount", opt)
		}
	})
}
