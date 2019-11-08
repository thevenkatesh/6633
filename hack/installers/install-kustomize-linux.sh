#!/bin/bash
set -eux -o pipefail

# TODO we use v2 for generating manifests, v3 for production - we should always use v3
KUSTOMIZE_VERSION=${KUSTOMIZE_VERSION:-3.2.1}
DL=$DOWNLOADS/kustomize-${KUSTOMIZE_VERSION}

# Note that kustomize release URIs have changed for v3.2.1. Then again for
# v3.3.0. When upgrading to versions >= v3.3.0 please change the URI format. And
# also note that as of version v3.3.0, assets are in .tar.gz form.
# v3.2.0 = https://github.com/kubernetes-sigs/kustomize/releases/download/v3.2.0/kustomize_3.2.0_linux_amd64
# v3.2.1 = https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/v3.2.1/kustomize_kustomize.v3.2.1_linux_amd64
# v3.3.0 = https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/v3.3.0/kustomize_v3.3.0_linux_amd64.tar.gz
[ -e $DL ] || curl -sLf --retry 3 -o $DL https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/v${KUSTOMIZE_VERSION}/kustomize_kustomize.v${KUSTOMIZE_VERSION}_linux_amd64
cp $DL $BIN/kustomize
chmod +x $BIN/kustomize
kustomize version
