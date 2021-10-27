#!/bin/bash
# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -ex

KERNEL_SRC_DIR="${KOKORO_ARTIFACTS_DIR}/git/kernel"
DEVENV_CONTAINER_NAME="gcr.io/cloud-kernel-build/cos-kernel-devenv:v20220126"
declare -a CONTAINER_CMD
CONTAINER_CMD=( sudo docker run --rm -v "${KERNEL_SRC_DIR}":/src -w /src "${DEVENV_CONTAINER_NAME}" )
PACKAGE_PREFIX="cos-kernel"
SRC="src"
HEADERS="headers"
DEBUG="debug"
GCS_PATH="gs://cos-kernel-artifacts"
BUILD_OUTPUT="build"
GCS_DIR=""
KERNEL_VERSION=""

cd "${KOKORO_ARTIFACTS_DIR}/git/kernel"
sudo gcloud docker -- pull ${DEVENV_CONTAINER_NAME}

echo "Using devenv container: ${DEVENV_CONTAINER_NAME}"
echo -n "-${KOKORO_BUILD_NUMBER}.${BRANCH}" > localversion
echo "${KOKORO_GIT_COMMIT}" > kernel_commit

# Remove '+' sign from the version
touch .scmversion
echo "COS branch: ${BRANCH}"
echo "Git commit: ${KOKORO_GIT_COMMIT}"

echo "Archiving source code"
# Archive source files before building the kernel.
tar --exclude=.git -czf /tmp/${PACKAGE_PREFIX}-${SRC}.tgz .

for arch in 'x86_64' 'arm64'
do
  # Build kernel, kernel-headers, debug packges in arch-specific directory
  "${CONTAINER_CMD[@]}" -k -H -d -A "${arch}" -C lakitu_defconfig -O "${BUILD_OUTPUT}_${arch}"

  # Fixup permissions
  sudo chown -R "$(id -u):$(id -g)" .

  # Get ther kernel version on the first iteration.
  # The version is the same for all architectures
  if [[ -z "${KERNEL_VERSION}" ]]
  then
    KERNEL_VERSION=$("${CONTAINER_CMD[@]}" -O "${BUILD_OUTPUT}_${arch}" kernelrelease | tail -2 | head -1)
  fi
done

if [[ "${KOKORO_JOB_TYPE}" = CONTINUOUS_INTEGRATION ]]; then
  GCS_DIR="${GCS_PATH}/builds/${KERNEL_VERSION}"
elif [[ "${KOKORO_JOB_TYPE}" = "PRESUBMIT_GERRIT_ON_BORG" ]]; then
  # store presubmit artifacts into dedicated folder
  # so they could be used in further tests/qualification
  GCS_DIR="${GCS_PATH}/presubmit/${KOKORO_BUILD_ID}"
else
  echo "Unknown Kokoro job type: '${KOKORO_JOB_TYPE}'"
  exit 1
fi

# upload artifacts for all supported architectures
for arch in 'x86_64' 'arm64'
do
  gsutil cp "${PACKAGE_PREFIX}-${KERNEL_VERSION}-${arch}.txz" "${GCS_DIR}"/
  gsutil cp "${PACKAGE_PREFIX}-${HEADERS}-${KERNEL_VERSION}-${arch}.tgz" "${GCS_DIR}"/
  gsutil cp "${PACKAGE_PREFIX}-${DEBUG}-${KERNEL_VERSION}-${arch}.txz" "${GCS_DIR}"/
done
gsutil cp kernel_commit "${GCS_DIR}"/

# Rename the source archive with correct kernel version.
gsutil cp "/tmp/${PACKAGE_PREFIX}-${SRC}.tgz" "${GCS_DIR}/${PACKAGE_PREFIX}-${SRC}-${KERNEL_VERSION}.tgz"
rm "/tmp/${PACKAGE_PREFIX}-${SRC}.tgz"
