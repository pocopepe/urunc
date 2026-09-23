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
	"bufio"
	"fmt"
	"github.com/urunc-dev/urunc/tests/fuzzing/known"
	"strings"
	"testing"
	"unicode"
)

// getMountInfo (block.go:59) hardcodes /proc/self/mountinfo as a local
// variable, not a parameter, so it can't take fuzzer-controlled content
// without a production code change -- and parsing a real, host-dependent file
// per iteration is a documented fuzz anti-pattern anyway.
//
// matchMountInfoLine is a byte-for-byte mirror of getMountInfo's inner
// per-line matching loop (block.go:72-105), so the matching ALGORITHM can be
// fuzzed with synthetic, deterministic content. If block.go's loop changes,
// this copy must be updated by hand -- nothing ties the two together.
func matchMountInfoLine(mountinfoContent string, path string) (source, fsType, mountOptions string, found bool) {
	nonSpecialSources := make(map[string]struct{})
	scanner := bufio.NewScanner(strings.NewReader(mountinfoContent))

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, " - ")
		if len(parts) != 2 {
			continue // malformed synthetic line; not the property under test
		}

		preDash := strings.Fields(parts[0])
		if len(preDash) < 6 {
			continue
		}
		postDash := strings.Fields(parts[1])
		if len(postDash) < 2 {
			continue
		}
		if preDash[4] == path {
			source = postDash[1]
			fsType = postDash[0]
			mountOptions = preDash[5]
			found = true
			continue
		}
		if postDash[0] != postDash[1] {
			nonSpecialSources[postDash[1]] = struct{}{}
		}
	}

	if !found {
		return "", "", "", false
	}
	if _, ok := nonSpecialSources[source]; ok {
		return "", "", "", false
	}
	return source, fsType, mountOptions, true
}

// kernelEscapeMountPoint mirrors the Linux kernel's mangling of special
// characters when it writes a mount point into /proc/self/mountinfo (see
// mangle_path / the seq_file octal-escape convention used by show_mountinfo
// in fs/proc_namespace.c): space, tab, newline and backslash are each
// replaced by their octal escape. Any real mount point containing one of
// these bytes appears in mountinfo escaped, never raw.
func kernelEscapeMountPoint(path string) string {
	var b strings.Builder
	for i := 0; i < len(path); i++ {
		switch path[i] {
		case ' ':
			b.WriteString(`\040`)
		case '\t':
			b.WriteString(`\011`)
		case '\n':
			b.WriteString(`\012`)
		case '\\':
			b.WriteString(`\134`)
		default:
			b.WriteByte(path[i])
		}
	}
	return b.String()
}

// FuzzGetMountInfoMatcher checks that the mirrored getMountInfo matching
// algorithm finds a mount point that is genuinely present, once the kernel's
// escaping is accounted for. Formalises a hand-written property @Anand-240
// described in urunc-dev/urunc#852 into a fuzzer, so it runs against
// arbitrary paths rather than hand-picked ones.
//
// Reachable via tryContainerBlockRootfs (rootfs.go:230), which calls
// getMountInfo(rs.cntrRootfs) -- the real host path every block-rootfs
// container's rootfs mounts under. A rootfs path containing a space (legal,
// if unusual) is exactly the failure mode this target searches for.
func FuzzGetMountInfoMatcher(f *testing.F) {
	f.Add("/var/lib/containers/storage/overlay/abc123/merged", "overlay", "overlay")
	f.Add("/run/containerd/io.containerd.runtime.v2.task/default/id/rootfs", "ext4", "/dev/sda1")

	f.Fuzz(func(t *testing.T, path, fsType, source string) {
		// fsType/source must not contain characters that break the synthetic
		// line's own field structure -- that's a harness artifact, not a
		// property of getMountInfo. path is deliberately NOT filtered this way:
		// mount points containing spaces are the whole point of this target.
		//
		// LESSON (withdrawn false positive): this filter originally hand-picked
		// four characters ( \t\n\\ ) instead of checking unicode.IsSpace. A
		// missing "\v" let the fuzzer put a vertical tab in source/fsType,
		// which strings.Fields silently treated as a field boundary -- a
		// self-inflicted parse mismatch, not a getMountInfo defect.
		for _, s := range []string{fsType, source} {
			if s == "" || strings.ContainsAny(s, "\\") || strings.IndexFunc(s, unicode.IsSpace) >= 0 {
				return
			}
		}
		if path == "" {
			return
		}

		escaped := kernelEscapeMountPoint(path)

		// kernelEscapeMountPoint escapes only four characters; other unicode
		// whitespace (\r, \v, \f) passes through and would split the synthetic
		// line at a boundary the harness introduced itself -- the same class of
		// bug as above, now checked as an invariant instead of a character list.
		if strings.IndexFunc(escaped, unicode.IsSpace) >= 0 {
			return
		}

		line := fmt.Sprintf("36 25 0:30 / %s rw,relatime shared:1 - %s %s rw",
			escaped, fsType, source)

		// getMountInfo splits pre-dash/post-dash on the literal token " - ", and
		// the kernel doesn't escape "-", so a field whose value is exactly "-"
		// introduces a second separator and makes the line ambiguous. That's a
		// distinct separator-collision concern from finding 12's escaping
		// defect, so skip it here rather than let this suppression hide it.
		if len(strings.Split(line, " - ")) != 2 {
			return
		}

		// Finding 12: the kernel octal-escapes space/tab/newline/backslash when
		// it writes a mount point into /proc/self/mountinfo, but getMountInfo
		// compares the RAW field byte-for-byte against its path argument, so an
		// escaped mount point never matches. Fires on any path containing one
		// of those four characters, which wedged this target.
		//
		// SHAPE: the path genuinely contains a character the kernel escapes,
		// i.e. escaping actually changed the string. A path that needed NO
		// escaping and still failed to match is a different defect.
		needsEscaping := escaped != path

		gotSource, gotFsType, _, found := matchMountInfoLine(line, path)
		if !found {
			known.Expected(t, "finding-12", needsEscaping,
				"mount point %q is present in mountinfo (as kernel-escaped "+
					"%q) but getMountInfo's matcher did not find it:\n  line: %q",
				path, escaped, line)
			return
		}
		if gotSource != source || gotFsType != fsType {
			t.Fatalf("getMountInfo matched mount point %q but returned "+
				"source=%q fsType=%q, want source=%q fsType=%q",
				path, gotSource, gotFsType, source, fsType)
		}
	})
}
