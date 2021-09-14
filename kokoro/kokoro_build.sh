#!/bin/bash

set -ex

cd "${KOKORO_ARTIFACTS_DIR}/git/kernel"
env | sort
uname -a
which gcloud
sudo gcloud auth list
sudo gcloud docker -- pull gcr.io/cloud-kernel-build/cos-kernel-devenv
pwd
echo -n "-cos${KOKORO_BUILD_NUMBER}" > localversion
# Remove '+' sign from the version
touch .scmversion
sudo docker run --rm \
  -u "$(id -u):$(id -g)" \
  -v $(pwd):/src -w /src \
  gcr.io/cloud-kernel-build/cos-kernel-devenv -k

# XXX: replace with `make kernelversion > version.full` in the containers
KERNEL_VERSION="$(ls linux-*.tar.xz | sed s@linux-@@ | sed -E s@-[^-]*.tar.xz@@)"

gsutil cp linux-*.tar.xz "gs://ovt-dev/kernel-builds/${VERSION}/"
