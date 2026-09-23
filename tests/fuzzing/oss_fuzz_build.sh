#!/usr/bin/env bash

# This file is only meant to be run by OSS-Fuzz and will not work if run
# outside of it. compile_native_go_fuzzer() is provided by the OSS-Fuzz
# base-builder-go image. Layout mirrors runc's tests/fuzzing/oss_fuzz_build.sh.
#
# urunc's harnesses are native Go 1.18+ fuzz targets (func FuzzXxx(f *testing.F))
# living beside the code as _test.go files, so compile_native_go_fuzzer is used
# rather than runc's older compile_go_fuzzer + //go:build gofuzz style.

set -o nounset
set -o pipefail
set -o errexit
set -x

go get github.com/AdaLogics/go-fuzz-headers
go get github.com/AdamKorcz/go-118-fuzz-build/testing

UP=github.com/urunc-dev/urunc

# Dictionaries. OSS-Fuzz picks up $OUT/<target>.dict automatically and passes
# it to libFuzzer as -dict=. These matter a great deal for the string-shaped
# targets: measured locally, libFuzzer found the subnetMaskToCIDR defect in
# 435 executions with the dictionary and did not find it at all in 752,743
# executions without one.
cp $SRC/urunc/tests/fuzzing/dicts/*.dict $OUT/ 2>/dev/null || true

# Targets are discovered, not hand-listed. A hand-maintained list here drifted
# badly during Phase 1: it kept registering 12 retired targets and was missing
# 5 live ones -- including both BuildExecCmd differential targets and the
# hook-argv target, i.e. the ones that actually found bugs. containerd's
# contrib/fuzz/oss_fuzz_build.sh auto-discovers the same way.
#
# Fuzzer names are snake_case of the Go name (FuzzIsIPInSubnet ->
# fuzz_is_ip_in_subnet) so that dicts/<name>.dict keeps matching.
#
# cmd/ is skipped on purpose: cmd/urunc is `package main`, and
# go-118-fuzz-build must import the package under test to generate a libFuzzer
# entry point, which Go refuses ("is a program, not an importable package").
# This is why runc keeps its fuzzable logic in libcontainer/* rather than main.
# cmd/urunc currently has no fuzz targets; if any are added they belong in an
# importable package instead.
#
# Unverified: an earlier, now-retired target (FuzzBuildExecCmd) failed with
# "Could not find the function" only in the containerized multi-target build
# while building fine in isolation. pkg/unikontainers/hypervisors now holds
# three targets; confirm they all build before relying on this in CI.
cd "$SRC/urunc"
grep -rl --include='*_test.go' '^func Fuzz.*testing\.F' pkg internal | sort | while read -r file; do
	pkg="$UP/$(dirname "$file")"
	grep -oE '^func Fuzz[A-Za-z0-9_]+\(f \*testing\.F\)' "$file" | sed -E 's/func (Fuzz[A-Za-z0-9_]+).*/\1/' | while read -r fn; do
		name=$(echo "$fn" | sed -E 's/([a-z0-9])([A-Z])/\1_\2/g; s/([A-Z]+)([A-Z][a-z])/\1_\2/g' | tr 'A-Z' 'a-z')
		compile_native_go_fuzzer "$pkg" "$fn" "$name"
	done
done
