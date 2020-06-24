#! /usr/bin/env bash
set -x
set -o errexit
set -o nounset
set -o pipefail

KUSTOMIZE=kustomize2

SRCROOT="$( CDPATH='' cd -- "$(dirname "$0")/.." && pwd -P )"
AUTOGENMSG="# This is an auto-generated file. DO NOT EDIT"

cd ${SRCROOT}/manifests/ha/base/redis-ha && ./generate.sh

IMAGE_NAMESPACE="${IMAGE_NAMESPACE:-argoproj}"
IMAGE_TAG="${IMAGE_TAG:-}"
ARGOCD_VERSION_LABEL=v$(cat $SRCROOT/VERSION)

# if the tag has not been declared, and we are on a release branch, use the VERSION file.
if [ "$IMAGE_TAG" = "" ]; then
  branch=$(git rev-parse --abbrev-ref HEAD)
  if [[ $branch = release-* ]]; then
    pwd
    IMAGE_TAG=${ARGOCD_VERSION_LABEL}
  fi
fi
# otherwise, use latest
if [ "$IMAGE_TAG" = "" ]; then
  IMAGE_TAG=latest
fi

cd ${SRCROOT}/manifests/base && $KUSTOMIZE edit set image argoproj/argocd=${IMAGE_NAMESPACE}/argocd:${IMAGE_TAG} && sed "s/ARGOCD_VERSION_TO_BE_REPLACED/${ARGOCD_VERSION_LABEL}/g" version_label_patches.tmpl > version_label_patches.yaml
cd ${SRCROOT}/manifests/ha/base && $KUSTOMIZE edit set image argoproj/argocd=${IMAGE_NAMESPACE}/argocd:${IMAGE_TAG}

echo "${AUTOGENMSG}" > "${SRCROOT}/manifests/install.yaml"
$KUSTOMIZE build "${SRCROOT}/manifests/cluster-install" >> "${SRCROOT}/manifests/install.yaml"

echo "${AUTOGENMSG}" > "${SRCROOT}/manifests/namespace-install.yaml"
$KUSTOMIZE build "${SRCROOT}/manifests/namespace-install" >> "${SRCROOT}/manifests/namespace-install.yaml"

echo "${AUTOGENMSG}" > "${SRCROOT}/manifests/ha/install.yaml"
$KUSTOMIZE build "${SRCROOT}/manifests/ha/cluster-install" >> "${SRCROOT}/manifests/ha/install.yaml"

echo "${AUTOGENMSG}" > "${SRCROOT}/manifests/ha/namespace-install.yaml"
$KUSTOMIZE build "${SRCROOT}/manifests/ha/namespace-install" >> "${SRCROOT}/manifests/ha/namespace-install.yaml"

