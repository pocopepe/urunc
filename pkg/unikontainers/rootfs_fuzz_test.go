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

	"github.com/urunc-dev/urunc/pkg/unikontainers/unikernels"
)

// rootfsUnikernelTypes mirrors fuzzUnikernelTypes in the hypervisors package:
// every type unikernels.New dispatches on, exercised without a real VMM or
// filesystem, which tryInitrd/tryExplicitBlock never touch.
var rootfsUnikernelTypes = []string{
	unikernels.RumprunUnikernel, unikernels.UnikraftUnikernel,
	unikernels.MirageUnikernel, unikernels.MewzUnikernel,
	unikernels.LinuxUnikernel, unikernels.HermitUnikernel,
}

// FuzzTryInitrd checks the bijection tryInitrd is documented to implement:
// initrd-based rootfs is selected exactly when the com.urunc.unikernel.initrd
// annotation is non-empty, carrying that exact path through unchanged.
//
// unikontainers.go's rootfs-selection chain (unikontainers.go:333-347) tries
// this first, ahead of the explicit-block and container-rootfs paths, so a
// wrong result here silently overrides the whole priority chain.
func FuzzTryInitrd(f *testing.F) {
	f.Add("/boot/initrd.img")
	f.Add("")

	f.Fuzz(func(t *testing.T, initrdPath string) {
		rs := &rootfsSelector{
			annot:      map[string]string{annotInitrd: initrdPath},
			cntrRootfs: "/rootfs",
		}
		result, ok := rs.tryInitrd()

		if initrdPath == "" {
			if ok {
				t.Fatalf("tryInitrd() selected initrd rootfs with no initrd "+
					"annotation set: %+v", result)
			}
			return
		}
		if !ok {
			t.Fatalf("tryInitrd() did not select initrd rootfs despite "+
				"initrd annotation = %q", initrdPath)
		}
		if result.Type != "initrd" || result.Path != initrdPath {
			t.Fatalf("tryInitrd() with initrd annotation %q returned %+v, "+
				"want Type=\"initrd\" Path=%q", initrdPath, result, initrdPath)
		}
	})
}

// FuzzTryExplicitBlock checks the necessary conditions tryExplicitBlock's own
// comment documents: explicit-block rootfs may be selected only when the
// block annotation is non-empty, it is mounted at "/", and the unikernel
// actually supports block devices at all.
//
// This is a safety property, not just a parsing one: choosing block-device
// rootfs for a unikernel that does not support block devices, or for a block
// mounted somewhere other than "/", would hand the guest a boot configuration
// it cannot use. The oracle checks the three conditions independently (each
// individually necessary) rather than reproducing the exact boolean formula,
// so it stays meaningful if the formula's combination logic changes later.
func FuzzTryExplicitBlock(f *testing.F) {
	f.Add("/.boot/disk.img", "/", unikernels.MirageUnikernel)
	f.Add("/.boot/disk.img", "/data", unikernels.MirageUnikernel)
	f.Add("", "/", unikernels.LinuxUnikernel)

	f.Fuzz(func(t *testing.T, blockPath, blockMntPoint, ukType string) {
		u, err := unikernels.New(ukType)
		if err != nil {
			return
		}

		rs := &rootfsSelector{
			annot: map[string]string{
				annotBlock:         blockPath,
				annotBlockMntPoint: blockMntPoint,
			},
			unikernel:  u,
			cntrRootfs: "/rootfs",
		}
		result, ok := rs.tryExplicitBlock()
		if !ok {
			return
		}

		if blockPath == "" {
			t.Fatalf("tryExplicitBlock() selected block rootfs with an empty "+
				"block annotation: %+v", result)
		}
		if blockMntPoint != "/" {
			t.Fatalf("tryExplicitBlock() selected block rootfs mounted at %q, "+
				"not \"/\": a block device not mounted at the guest root was "+
				"used as the guest root anyway: %+v", blockMntPoint, result)
		}
		if !u.SupportsBlock() {
			t.Fatalf("tryExplicitBlock() selected block rootfs for %s, which "+
				"reports SupportsBlock() == false: %+v", ukType, result)
		}
		if result.Type != "block" || result.Path != blockPath {
			t.Fatalf("tryExplicitBlock() with block=%q returned %+v, want "+
				"Type=\"block\" Path=%q", blockPath, result, blockPath)
		}
	})
}
