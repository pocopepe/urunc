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
	"net"
	"testing"

	"github.com/urunc-dev/urunc/tests/fuzzing/known"
)

// FuzzSubnetMaskToCIDR differentially tests subnetMaskToCIDR against the
// stdlib's canonical interpretation of an IPv4 netmask. subnetMaskToCIDR
// feeds the guest's network configuration for mirage, mewz, hermit and
// rumprun, so a wrong prefix length is a wrong guest routing table.
//
// Oracle: whenever subnetMaskToCIDR reports success, the input must really be
// a valid dotted-quad IPv4 mask, and the prefix length must match
// net.IPMask.Size(). Size() returns bits==0 precisely for a non-contiguous
// mask, which is not a legal netmask at all.
func FuzzSubnetMaskToCIDR(f *testing.F) {
	for _, s := range []string{
		"255.255.255.0", "255.255.0.0", "255.0.0.0", "0.0.0.0",
		"255.255.255.255", "255.255.254.0", "not.a.mask.x", "1.2.3", "",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, mask string) {
		got, err := subnetMaskToCIDR(mask)
		if err != nil {
			return
		}

		// Finding 2: subnetMaskToCIDR counts 1-bits per octet without checking
		// the value is a valid dotted quad or that the bits are contiguous, so
		// it accepts masks it should reject. That fires on a large fraction of
		// all inputs, which permanently wedged this target (see
		// tests/fuzzing/known for the root cause).
		//
		// SHAPE of the known defect: the INPUT is genuinely not a valid
		// contiguous netmask and was accepted anyway. A mask that IS valid and
		// contiguous but yields the wrong prefix is a DIFFERENT bug, and still
		// fails loudly via shapeOK=false below.
		ip := net.ParseIP(mask)
		if ip == nil || ip.To4() == nil {
			known.Expected(t, "finding-2", true,
				"subnetMaskToCIDR(%q) = /%d with no error, but %q is not a "+
					"valid dotted-quad IPv4 address at all", mask, got, mask)
			return
		}

		ones, bits := net.IPMask(ip.To4()).Size()
		if bits == 0 {
			known.Expected(t, "finding-2", true,
				"subnetMaskToCIDR(%q) = /%d with no error, but %q is not a "+
					"contiguous netmask, so no prefix length can represent it",
				mask, got, mask)
			return
		}
		if ones != got {
			known.Expected(t, "finding-2", false,
				"subnetMaskToCIDR(%q) = /%d, but %q IS a valid contiguous mask whose "+
					"canonical prefix length is /%d", mask, got, mask, ones)
		}
	})
}

// FuzzIsIPInSubnet checks that IsIPInSubnet does not fail open. It gates
// Linux guest network setup (linux.go:121 rejects the config when it returns
// false), so returning true for input it could not even parse would let an
// invalid address/gateway/mask combination through that gate.
//
// Oracle: a true result is a positive claim that the address lies inside the
// gateway's subnet. That claim is only meaningful if all three components
// actually parsed as IPv4.
func FuzzIsIPInSubnet(f *testing.F) {
	f.Add("192.168.1.10", "192.168.1.1", "255.255.255.0")
	f.Add("10.0.0.5", "10.0.0.1", "255.0.0.0")
	f.Add("1.2.3.4", "9.9.9.9", "255.255.255.0")

	f.Fuzz(func(t *testing.T, addr, gw, mask string) {
		if !IsIPInSubnet(LinuxNet{Address: addr, Gateway: gw, Mask: mask}) {
			return
		}
		// Finding 1: IsIPInSubnet FAILS OPEN. net.ParseIP returns nil for
		// unparseable input, IP.Mask(nil) is nil, and nil.Equal(nil) is true,
		// so the gate passes on anything it could not parse -- which is most
		// random input, hence the permanent wedge.
		//
		// SHAPE of the known defect: at least one of the three values is
		// unparseable. If all three parse cleanly and the function still
		// claims "in subnet" when the stdlib disagrees, that is a different
		// defect and fails loudly.
		anyUnparseable := false
		for _, c := range []struct{ name, val string }{
			{"address", addr}, {"gateway", gw}, {"mask", mask},
		} {
			if ip := net.ParseIP(c.val); ip == nil || ip.To4() == nil {
				anyUnparseable = true
				known.Expected(t, "finding-1", true,
					"IsIPInSubnet(addr=%q, gw=%q, mask=%q) = true, but the "+
						"%s %q is not a valid IPv4 value -- the subnet check passed "+
						"on input it could not parse", addr, gw, mask, c.name, c.val)
			}
		}
		if anyUnparseable {
			return
		}

		// All three parse: the differential against the stdlib must now hold.
		m := net.IPMask(net.ParseIP(mask).To4())
		if _, bits := m.Size(); bits == 0 {
			return // non-contiguous mask is finding 2's territory, not this one
		}
		if !net.ParseIP(addr).To4().Mask(m).Equal(net.ParseIP(gw).To4().Mask(m)) {
			known.Expected(t, "finding-1", false,
				"IsIPInSubnet(addr=%q, gw=%q, mask=%q) = true and all three values parse "+
					"cleanly, but net.IPMask says %q is NOT in %q/%q -- this is not the "+
					"known fail-open defect", addr, gw, mask, addr, gw, mask)
		}
	})
}
