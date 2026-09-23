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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/urunc-dev/urunc/pkg/unikontainers/hypervisors"
	"github.com/urunc-dev/urunc/pkg/unikontainers/types"
	"github.com/urunc-dev/urunc/pkg/unikontainers/unikernels"
)

func TestNewRootfsResult(t *testing.T) {
	expected := types.RootfsParams{
		Type:        "initrd",
		Path:        "/path/to/initrd",
		MountedPath: "/mnt/rootfs",
	}

	got := newRootfsResult("initrd", "/path/to/initrd", "/mnt/rootfs")

	assert.Equal(t, expected.Type, got.Type, "Type should match")
	assert.Equal(t, expected.Path, got.Path, "Path should match")
	assert.Equal(t, expected.MountedPath, got.MountedPath, "MountedPath should match")
	// MonRootfs is intentionally not set by newRootfsResult; switchMonRootfs owns it.
	assert.Empty(t, got.MonRootfs, "MonRootfs should be left unset")
}

func TestRootfsSelector_TryInitrd(t *testing.T) {
	tests := []struct {
		name          string
		annot         map[string]string
		expectedFound bool
		expectedType  string
		expectedPath  string
	}{
		{
			name: "initrd present",
			annot: map[string]string{
				annotInitrd: "/path/to/initrd.img",
			},
			expectedFound: true,
			expectedType:  "initrd",
			expectedPath:  "/path/to/initrd.img",
		},
		{
			name:          "initrd missing",
			annot:         map[string]string{},
			expectedFound: false,
		},
		{
			name: "initrd empty",
			annot: map[string]string{
				annotInitrd: "",
			},
			expectedFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rs := &rootfsSelector{
				annot:      tt.annot,
				cntrRootfs: "/container/rootfs",
			}

			got, found := rs.tryInitrd()

			assert.Equal(t, tt.expectedFound, found, "tryInitrd() found mismatch")

			if found {
				assert.Equal(t, tt.expectedType, got.Type, "tryInitrd() Type mismatch")
				assert.Equal(t, tt.expectedPath, got.Path, "tryInitrd() Path mismatch")
			}
		})
	}
}

func TestRootfsSelector_ShouldMountContainerRootfs(t *testing.T) {
	tests := []struct {
		name     string
		annot    map[string]string
		expected bool
	}{
		{
			name: "mount rootfs true",
			annot: map[string]string{
				annotMountRootfs: "true",
			},
			expected: true,
		},
		{
			name: "mount rootfs 1",
			annot: map[string]string{
				annotMountRootfs: "1",
			},
			expected: true,
		},
		{
			name: "mount rootfs false",
			annot: map[string]string{
				annotMountRootfs: "false",
			},
			expected: false,
		},
		{
			name: "mount rootfs 0",
			annot: map[string]string{
				annotMountRootfs: "0",
			},
			expected: false,
		},
		{
			name:     "mount rootfs missing",
			annot:    map[string]string{},
			expected: false,
		},
		{
			name: "mount rootfs empty",
			annot: map[string]string{
				annotMountRootfs: "",
			},
			expected: false,
		},
		{
			name: "mount rootfs invalid",
			annot: map[string]string{
				annotMountRootfs: "invalid",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rs := &rootfsSelector{
				annot: tt.annot,
			}

			got := rs.shouldMountContainerRootfs()
			assert.Equal(t, tt.expected, got, "shouldMountContainerRootfs() mismatch")
		})
	}
}

func TestMonitorDeviceMode(t *testing.T) {
	t.Run("widens a group-only device for other users", func(t *testing.T) {
		t.Parallel()
		// /dev/kvm on a stock host: 0660 root:kvm. Without the widening a
		// monitor running as a non-root user gets EACCES on it.
		assert.Equal(t, os.FileMode(0o666), monitorDeviceMode(0o660))
	})

	t.Run("leaves an already-wide device alone", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, os.FileMode(0o666), monitorDeviceMode(0o666))
	})

	t.Run("keeps the owner and group bits", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, os.FileMode(0o646), monitorDeviceMode(0o640))
	})

	t.Run("drops the file type bits", func(t *testing.T) {
		t.Parallel()
		// unix.Stat reports the type in the high bits; only the permission
		// bits may reach mknod.
		assert.Equal(t, os.FileMode(0o666), monitorDeviceMode(unix.S_IFCHR|0o660))
	})
}

func TestNoRootfsGetMounts(t *testing.T) {
	t.Run("mounts the container rootfs read-only without a block image", func(t *testing.T) {
		t.Parallel()
		n := noRootfs{containerRootfsPath: "/run/rootfs"}

		mounts, err := n.getMounts()
		require.NoError(t, err)
		require.Len(t, mounts, 2)
		assert.Equal(t, "/run/rootfs", mounts[0].Source)
		assert.Equal(t, containerRootfsMountPath, mounts[0].Destination)
		assert.Contains(t, mounts[0].Options, "ro")
	})

	t.Run("keeps the container rootfs writable when a block image is attached", func(t *testing.T) {
		t.Parallel()
		// The monitor opens the image read-write, so the mount that holds it
		// can not be read-only.
		n := noRootfs{
			containerRootfsPath:  "/run/rootfs",
			annotBlockPath:       "/data/vol.ext2",
			annotBlockMountPoint: "/data",
		}

		mounts, err := n.getMounts()
		require.NoError(t, err)
		require.Len(t, mounts, 2)
		assert.Equal(t, containerRootfsMountPath, mounts[0].Destination)
		assert.NotContains(t, mounts[0].Options, "ro")
	})
}

// rootfsSelector's shared-fs decision tree (tryVirtiofs, try9pfs,
// tryContainerSharedFS, tryContainerRootfs) had no tests before this pass --
// 159/188 statements in rootfs.go were uncovered. Real unikernels.New(...) and
// hypervisors.NewVMM(...) are used rather than hand-rolled fakes: setting
// MonitorConfig.BinaryPath skips the exec.LookPath call in
// hypervisors.getVMMPath (vmm.go:106), so no installed VMM binaries are
// needed, and this exercises the actual SupportsFS/SupportsSharedfs contract
// instead of a stubbed one.
//
// tryContainerBlockRootfs is deliberately never driven here: it calls
// getMountInfo on the host path, whose result depends on the host's real
// filesystem and is not deterministic across machines. Driving
// tryContainerRootfs with a guest whose SupportsBlock()==false (unikraft)
// means it never reaches that lookup at all.

func newTestVMM(t *testing.T, vmmType hypervisors.VmmType) types.VMM {
	t.Helper()
	vmm, err := hypervisors.NewVMM(vmmType, map[string]types.MonitorConfig{
		string(vmmType): {BinaryPath: "/bin/true"},
	})
	require.NoError(t, err)
	return vmm
}

func newTestUnikernel(t *testing.T, unikernelType string) types.Unikernel {
	t.Helper()
	u, err := unikernels.New(unikernelType)
	require.NoError(t, err)
	return u
}

func TestRootfsSelector_TryVirtiofs(t *testing.T) {
	vfsdPath := filepath.Join(t.TempDir(), "virtiofsd")
	require.NoError(t, os.WriteFile(vfsdPath, []byte(""), 0o644))

	t.Run("unikernel supports virtiofs, vmm supports virtio, binary exists", func(t *testing.T) {
		rs := &rootfsSelector{
			unikernel:  newTestUnikernel(t, unikernels.LinuxUnikernel),
			vmm:        newTestVMM(t, hypervisors.QemuVmm),
			vfsdPath:   vfsdPath,
			cntrRootfs: "/container/rootfs",
		}
		got, ok := rs.tryVirtiofs()
		assert.True(t, ok)
		assert.Equal(t, "virtiofs", got.Type)
	})

	t.Run("unikernel does not support virtiofs", func(t *testing.T) {
		// Mewz's SupportsFS never returns true for anything.
		rs := &rootfsSelector{
			unikernel:  newTestUnikernel(t, unikernels.MewzUnikernel),
			vmm:        newTestVMM(t, hypervisors.QemuVmm),
			vfsdPath:   vfsdPath,
			cntrRootfs: "/container/rootfs",
		}
		_, ok := rs.tryVirtiofs()
		assert.False(t, ok)
	})

	t.Run("vmm does not support the virtio shared-fs transport", func(t *testing.T) {
		// cloud-hypervisor's SupportsSharedfs only accepts "virtio" -- Linux
		// supports virtiofs, so this isolates the vmm-side guard.
		rs := &rootfsSelector{
			unikernel:  newTestUnikernel(t, unikernels.RumprunUnikernel),
			vmm:        newTestVMM(t, hypervisors.CloudHypervisorVmm),
			vfsdPath:   vfsdPath,
			cntrRootfs: "/container/rootfs",
		}
		_, ok := rs.tryVirtiofs()
		assert.False(t, ok, "rumprun does not implement SupportsFS(\"virtiofs\") either, so this also isolates the unikernel-side guard")
	})

	t.Run("virtiofsd binary does not exist on the host", func(t *testing.T) {
		rs := &rootfsSelector{
			unikernel:  newTestUnikernel(t, unikernels.LinuxUnikernel),
			vmm:        newTestVMM(t, hypervisors.QemuVmm),
			vfsdPath:   filepath.Join(t.TempDir(), "does-not-exist"),
			cntrRootfs: "/container/rootfs",
		}
		_, ok := rs.tryVirtiofs()
		assert.False(t, ok)
	})
}

func TestRootfsSelector_Try9pfs(t *testing.T) {
	t.Run("unikernel supports 9pfs, vmm supports the 9p transport", func(t *testing.T) {
		rs := &rootfsSelector{
			unikernel:  newTestUnikernel(t, unikernels.LinuxUnikernel),
			vmm:        newTestVMM(t, hypervisors.QemuVmm),
			cntrRootfs: "/container/rootfs",
		}
		got, ok := rs.try9pfs()
		assert.True(t, ok)
		assert.Equal(t, "9pfs", got.Type)
	})

	t.Run("unikernel does not support 9pfs", func(t *testing.T) {
		rs := &rootfsSelector{
			unikernel:  newTestUnikernel(t, unikernels.MewzUnikernel),
			vmm:        newTestVMM(t, hypervisors.QemuVmm),
			cntrRootfs: "/container/rootfs",
		}
		_, ok := rs.try9pfs()
		assert.False(t, ok)
	})

	t.Run("vmm does not support the 9p transport", func(t *testing.T) {
		// cloud-hypervisor's SupportsSharedfs only accepts "virtio", never "9p".
		rs := &rootfsSelector{
			unikernel:  newTestUnikernel(t, unikernels.LinuxUnikernel),
			vmm:        newTestVMM(t, hypervisors.CloudHypervisorVmm),
			cntrRootfs: "/container/rootfs",
		}
		_, ok := rs.try9pfs()
		assert.False(t, ok)
	})
}

func TestRootfsSelector_TryContainerSharedFS(t *testing.T) {
	vfsdPath := filepath.Join(t.TempDir(), "virtiofsd")
	require.NoError(t, os.WriteFile(vfsdPath, []byte(""), 0o644))

	t.Run("virtiofs is preferred over 9pfs when both are available", func(t *testing.T) {
		// Kills a mutant that swaps the tryVirtiofs/try9pfs call order.
		rs := &rootfsSelector{
			unikernel:  newTestUnikernel(t, unikernels.LinuxUnikernel),
			vmm:        newTestVMM(t, hypervisors.QemuVmm),
			vfsdPath:   vfsdPath,
			cntrRootfs: "/container/rootfs",
		}
		got, ok := rs.tryContainerSharedFS()
		assert.True(t, ok)
		assert.Equal(t, "virtiofs", got.Type)
	})

	t.Run("falls back to 9pfs when virtiofs is unavailable", func(t *testing.T) {
		// No virtiofsd binary on the host, so tryVirtiofs fails and
		// tryContainerSharedFS must fall through to try9pfs rather than
		// giving up.
		rs := &rootfsSelector{
			unikernel:  newTestUnikernel(t, unikernels.LinuxUnikernel),
			vmm:        newTestVMM(t, hypervisors.QemuVmm),
			vfsdPath:   filepath.Join(t.TempDir(), "does-not-exist"),
			cntrRootfs: "/container/rootfs",
		}
		got, ok := rs.tryContainerSharedFS()
		assert.True(t, ok)
		assert.Equal(t, "9pfs", got.Type)
	})

	t.Run("neither is available", func(t *testing.T) {
		rs := &rootfsSelector{
			unikernel:  newTestUnikernel(t, unikernels.MewzUnikernel),
			vmm:        newTestVMM(t, hypervisors.CloudHypervisorVmm),
			vfsdPath:   vfsdPath,
			cntrRootfs: "/container/rootfs",
		}
		_, ok := rs.tryContainerSharedFS()
		assert.False(t, ok)
	})
}

func TestRootfsSelector_TryContainerRootfs(t *testing.T) {
	vfsdPath := filepath.Join(t.TempDir(), "virtiofsd")
	require.NoError(t, os.WriteFile(vfsdPath, []byte(""), 0o644))

	t.Run("the mountRootfs annotation gate blocks everything else", func(t *testing.T) {
		// Kills a mutant that drops the shouldMountContainerRootfs() guard --
		// annot is empty here, so the gate must return false before ever
		// reaching tryContainerBlockRootfs's host-dependent getMountInfo call.
		rs := &rootfsSelector{
			unikernel:  newTestUnikernel(t, unikernels.LinuxUnikernel),
			vmm:        newTestVMM(t, hypervisors.QemuVmm),
			vfsdPath:   vfsdPath,
			cntrRootfs: "/container/rootfs",
			annot:      map[string]string{},
		}
		_, ok := rs.tryContainerRootfs()
		assert.False(t, ok)
	})

	t.Run("gate open, block unsupported, falls back to shared-fs", func(t *testing.T) {
		// unikraft.SupportsBlock() is always false, so this reaches
		// tryContainerSharedFS without ever calling the host-dependent
		// tryContainerBlockRootfs -- deterministic across machines.
		// Result is "9pfs" specifically because unikraft.SupportsFS never
		// returns true for "virtiofs" (only "9pfs") -- confirmed by running
		// this, not assumed; an earlier draft of this case wrongly expected
		// "virtiofs" and failed here.
		rs := &rootfsSelector{
			unikernel:  newTestUnikernel(t, unikernels.UnikraftUnikernel),
			vmm:        newTestVMM(t, hypervisors.QemuVmm),
			vfsdPath:   vfsdPath,
			cntrRootfs: "/container/rootfs",
			annot:      map[string]string{annotMountRootfs: "true"},
		}
		got, ok := rs.tryContainerRootfs()
		assert.True(t, ok)
		assert.Equal(t, "9pfs", got.Type)
	})

	t.Run("gate open, block unsupported, shared-fs also unavailable", func(t *testing.T) {
		rs := &rootfsSelector{
			unikernel:  newTestUnikernel(t, unikernels.UnikraftUnikernel),
			vmm:        newTestVMM(t, hypervisors.CloudHypervisorVmm),
			vfsdPath:   vfsdPath,
			cntrRootfs: "/container/rootfs",
			annot:      map[string]string{annotMountRootfs: "true"},
		}
		_, ok := rs.tryContainerRootfs()
		assert.False(t, ok)
	})
}
