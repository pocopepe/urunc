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

import "testing"

// FuzzHandleExplicitBlockImages exercises the comma-separated block
// image/mountpoint annotation parser against arbitrary annotation values.
// It never asserts a specific parse result, only that the function does not
// panic and that its own documented invariants hold whenever it reports
// success: no block carries an empty source/mountpoint, and at most one
// block is mounted at "/".
func FuzzHandleExplicitBlockImages(f *testing.F) {
	seeds := []struct{ imgs, mounts string }{
		{"/.boot/disk1, /.boot/disk2", "/data1, /data2"},
		{"/.boot/rootfs", "/"},
		{"", ""},
		{"/a,/b", "/data"},
		{"/.boot/rootfs,/.boot/data", "/,/data"},
		{"/a,,/c", "/1,/2,/3"},
		{"/a,/b", "/1,"},
		{",", ","},
		{" , ", " , "},
		{"/a,/b,/c", "/,/,/"},
	}
	for _, s := range seeds {
		f.Add(s.imgs, s.mounts)
	}

	f.Fuzz(func(t *testing.T, imgs, mounts string) {
		blocks, err := handleExplicitBlockImages(imgs, mounts)
		if err != nil {
			return
		}

		rootfsCount := 0
		for _, b := range blocks {
			if b.Source == "" || b.MountPoint == "" {
				t.Fatalf("handleExplicitBlockImages(%q, %q) returned a block "+
					"with an empty field despite reporting success: %+v",
					imgs, mounts, b)
			}
			if b.MountPoint == "/" {
				rootfsCount++
			}
		}
		if rootfsCount > 1 {
			t.Fatalf("handleExplicitBlockImages(%q, %q) returned %d blocks "+
				"mounted at / (ambiguous rootfs, breaks blockDevNodes/rootfs "+
				"resolution which assumes at most one)", imgs, mounts, rootfsCount)
		}
	})
}
