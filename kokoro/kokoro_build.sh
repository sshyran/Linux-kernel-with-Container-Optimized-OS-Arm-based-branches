#!/bin/bash

set -ex

cd "${KOKORO_ARTIFACTS_DIR}/git/kernel"
sudo gcloud docker -- pull gcr.io/cloud-kernel-build/cos-kernel-devenv
sudo docker run --rm \
  -v $(pwd):/src -w /src gcr.io/cloud-kernel-build/cos-kernel-devenv -k
