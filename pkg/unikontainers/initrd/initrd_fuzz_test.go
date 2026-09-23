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

package initrd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/opencontainers/runtime-spec/specs-go"
)

// FuzzMergeFileMountsIntoInitrdPreservesOriginalOnError generalizes the 5
// hand-picked corruption cases in
// TestMergeFileMountsIntoInitrdInvalidTrailerDoesNotMutateOriginal (missing
// trailer, empty file, truncated trailer, non-zero trailer size, bad trailer
// name) into a property that must hold for ANY byte content: MergeFileMounts-
// IntoInitrd now parses the existing archive with inspectInitrd/
// validateTrailerAt before it writes anything (post-rebase 2026-09-10; the
// prior O_APPEND-with-no-parsing version had nothing to fuzz here). If that
// parse fails, the on-disk file must be byte-for-byte unchanged -- the
// existing tests check 5 specific corruptions; the fuzzer searches the rest
// of the space the hand-picked cases don't cover (odd offsets, partial
// headers, non-hex size/inode fields, names that collide with "." after
// archiveLookupPath normalization, etc).
func FuzzMergeFileMountsIntoInitrdPreservesOriginalOnError(f *testing.F) {
	f.Add([]byte("not a cpio archive"))
	f.Add([]byte(""))
	f.Add([]byte("070701" + string(make([]byte, 106)))) // header-shaped, all-zero fields
	f.Add([]byte("TRAILER!!!"))                         // trailer name with no header at all

	f.Fuzz(func(t *testing.T, existing []byte) {
		dir := t.TempDir()
		initrdPath := filepath.Join(dir, "initrd.cpio")
		if err := os.WriteFile(initrdPath, existing, 0o600); err != nil {
			t.Fatalf("could not seed initrd file: %v", err)
		}
		source := writeSource(t, dir, "mounted", "new-content")

		err := MergeFileMountsIntoInitrd(initrdPath, []specs.Mount{
			{Type: "bind", Source: source, Destination: "/mounted"},
		})

		after, readErr := os.ReadFile(initrdPath)
		if readErr != nil {
			t.Fatalf("could not read back %s after MergeFileMountsIntoInitrd: %v", initrdPath, readErr)
		}

		if err != nil {
			// Parse (or truncate/seek) failed: the file must be exactly what
			// it was before the call. A silent partial write here would
			// corrupt the guest's initrd on the NEXT successful boot, not
			// this one -- the failure is invisible until a later container.
			if !bytesEqual(existing, after) {
				t.Fatalf("MergeFileMountsIntoInitrd returned an error (%v) but still "+
					"modified the on-disk file.\n  before (%d bytes): %x\n  after  (%d bytes): %x",
					err, len(existing), existing, len(after), after)
			}
			return
		}

		// Success path: whatever MergeFileMountsIntoInitrd just wrote must
		// itself be a valid, re-parseable archive -- if inspectInitrd can't
		// read its own output back, the NEXT merge (or the guest's initramfs
		// unpacker) is the one that discovers the corruption, not this call.
		result, err := os.Open(initrdPath)
		if err != nil {
			t.Fatalf("could not reopen %s: %v", initrdPath, err)
		}
		defer result.Close()
		if _, _, _, err := inspectInitrd(result); err != nil {
			t.Fatalf("MergeFileMountsIntoInitrd reported success, but its own output at "+
				"%s is not a valid archive: %v", initrdPath, err)
		}
	})
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
