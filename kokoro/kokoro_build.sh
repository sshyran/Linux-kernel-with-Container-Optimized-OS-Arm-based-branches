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
sudo docker run --rm \
  -v $(pwd):/src -w /src gcr.io/cloud-kernel-build/cos-kernel-devenv -k
