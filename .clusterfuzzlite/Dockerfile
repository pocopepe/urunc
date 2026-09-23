# ClusterFuzzLite build environment for urunc.
# Unlike the OSS-Fuzz Dockerfile (oss-fuzz/projects/urunc/Dockerfile), which
# clones the repo, ClusterFuzzLite copies the checkout CI already has, so the
# fuzzers are always built from the commit under test.
FROM gcr.io/oss-fuzz-base/base-builder-go
COPY . $SRC/urunc
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/urunc
