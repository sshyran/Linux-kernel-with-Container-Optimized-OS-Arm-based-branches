#!/bin/bash

set -ex

KERNEL_SRC_DIR="${KOKORO_ARTIFACTS_DIR}/git/kernel"
CONTAINER_NAME="gcr.io/cloud-kernel-build/cos-kernel-devenv"
CONTAINER_CMD="sudo docker run --rm -v ${KERNEL_SRC_DIR}:/src -w /src ${CONTAINER_NAME} "
cd "${KOKORO_ARTIFACTS_DIR}/git/kernel"
env | sort
uname -a
which gcloud
sudo gcloud auth list
sudo gcloud docker -- pull ${CONTAINER_NAME}
pwd
echo ${CONTAINER_CMD}
echo -n "-cos${KOKORO_BUILD_NUMBER}" > localversion
# Remove '+' sign from the version
touch .scmversion
for arch in 'x86' 'arm64'
do
  ${CONTAINER_CMD} -k -A ${arch}

  # Fixup permissions
  sudo chown -R "$(id -u):$(id -g)" .

  KERNEL_VERSION=`${CONTAINER_CMD} kernelrelease | tail -1`

  gsutil cp cos-kernel-${KERNEL_VERSION}-${arch}.txz "gs://ovt-dev/kernel-builds/${KERNEL_VERSION}/"
  #gsutil cp kernel/kheaders_data.tar.xz "gs://ovt-dev/kernel-builds/${KERNEL_VERSION}/linux-headers-${KERNEL_VERSION_ARCH}.tar.xz"
done
