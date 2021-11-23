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
GCS_PATH="gs://ovt-dev/kernel-builds/"
for arch in 'x86' 'arm64'
do
  ${CONTAINER_CMD} -k -H -d -A ${arch}

  # Fixup permissions
  sudo chown -R "$(id -u):$(id -g)" .

  KERNEL_VERSION=`${CONTAINER_CMD} kernelrelease | tail -1`

  gsutil cp cos-kernel-${KERNEL_VERSION}-${arch}.txz "${GCS_PATH}"/"${KERNEL_VERSION}"/
  gsutil cp cos-kernel-headers-${KERNEL_VERSION}-${arch}.tgz "${GCS_PATH}"/"${KERNEL_VERSION}"/
  gsutil cp cos-kernel-debug-${KERNEL_VERSION}-${arch}.txz "${GCS_PATH}"/"${KERNEL_VERSION}"/
done
