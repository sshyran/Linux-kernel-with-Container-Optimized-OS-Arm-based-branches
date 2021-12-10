#!/bin/bash

set -ex

KERNEL_SRC_DIR="${KOKORO_ARTIFACTS_DIR}/git/kernel"
CONTAINER_NAME="gcr.io/cloud-kernel-build/cos-kernel-devenv"
CONTAINER_CMD="sudo docker run --rm -v ${KERNEL_SRC_DIR}:/src -w /src ${CONTAINER_NAME} "
FILE_PREFIX="cos-kernel"
SRC="src"
HEADERS="headers"
DEBUG="debug"
GCS_PATH="gs://ovt-dev/kernel-builds"
BUILD_OUTPUT="build"
GCS_DIR=""
KERNEL_VERSION=""

cd "${KOKORO_ARTIFACTS_DIR}/git/kernel"
env | sort
uname -a
which gcloud
sudo gcloud auth list
sudo gcloud docker -- pull ${CONTAINER_NAME}
pwd

echo ${CONTAINER_CMD}
echo -n "-${KOKORO_BUILD_NUMBER}.${BRANCH}" > localversion

# Remove '+' sign from the version
touch .scmversion
echo ${BRANCH}

echo "Archiving source code"
# Archive source files before building the kernel.
tar --exclude=.git -czf /tmp/${FILE_PREFIX}-${SRC}.tgz .

for arch in 'x86' 'arm64'
do
  ${CONTAINER_CMD} -k -H -d -A ${arch} -O ${BUILD_OUTPUT}_${arch}

  # Fixup permissions
  sudo chown -R "$(id -u):$(id -g)" .

  if [ -z "${KERNEL_VERSION}" ]
  then
    KERNEL_VERSION=`${CONTAINER_CMD} -O ${BUILD_OUTPUT}_${arch} kernelrelease | tail -2 | head -1`
  fi

  GCS_DIR=${GCS_PATH}/${KERNEL_VERSION}

  gsutil cp ${FILE_PREFIX}-${KERNEL_VERSION}-${arch}.txz "${GCS_DIR}"/
  gsutil cp ${FILE_PREFIX}-${HEADERS}-${KERNEL_VERSION}-${arch}.tgz "${GCS_DIR}"/
  gsutil cp ${FILE_PREFIX}-${DEBUG}-${KERNEL_VERSION}-${arch}.txz "${GCS_DIR}"/
done

# Rename the source archive with correct kernel version.
gsutil cp /tmp/${FILE_PREFIX}-${SRC}.tgz "${GCS_DIR}"/${FILE_PREFIX}-${SRC}-${KERNEL_VERSION}.tgz
rm /tmp/${FILE_PREFIX}-${SRC}.tgz
