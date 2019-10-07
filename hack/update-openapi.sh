#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

GO111MODULE=on
go get k8s.io/kube-openapiv0.0.0-20190918143330-0270cf2f1c1d

PROJECT_ROOT=$(cd $(dirname "$0")/.. ; pwd)
CODEGEN_PKG=${PROJECT_ROOT}/vendor/k8s.io/kube-openapi
VERSION="v1alpha1"

go run ${CODEGEN_PKG}/cmd/openapi-gen/openapi-gen.go \
  --go-header-file ${PROJECT_ROOT}/hack/custom-boilerplate.go.txt \
  --input-dirs github.com/argoproj/argo-cd/pkg/apis/application/${VERSION} \
  --output-package github.com/argoproj/argo-cd/pkg/apis/application/${VERSION} \
  --report-filename pkg/apis/api-rules/violation_exceptions.list \
  $@

go run ./hack/gen-crd-spec/main.go
