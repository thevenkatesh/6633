controller: [ "$BIN_MODE" = 'true' ] && COMMAND=./dist/argocd || COMMAND='go run ./cmd/main.go' && sh -c "GOCOVERDIR=${ARGOCD_COVERAGE_DIR:-/tmp/argo-e2e/app/coverage} HOSTNAME=testappcontroller-1  FORCE_LOG_COLORS=1 ARGOCD_FAKE_IN_CLUSTER=true ARGOCD_TLS_DATA_PATH=${ARGOCD_TLS_DATA_PATH:-/tmp/argocd-local/tls} ARGOCD_SSH_DATA_PATH=${ARGOCD_SSH_DATA_PATH:-/tmp/argocd-local/ssh} ARGOCD_BINARY_NAME=argocd-application-controller $COMMAND --loglevel debug --redis localhost:${ARGOCD_E2E_REDIS_PORT:-6379} --repo-server localhost:${ARGOCD_E2E_REPOSERVER_PORT:-8081} --otlp-address=${ARGOCD_OTLP_ADDRESS} --application-namespaces=${ARGOCD_APPLICATION_NAMESPACES:-''} --server-side-diff-enabled=${ARGOCD_APPLICATION_CONTROLLER_SERVER_SIDE_DIFF:-'false'}"
api-server: [ "$BIN_MODE" = 'true' ] && COMMAND=./dist/argocd || COMMAND='go run ./cmd/main.go' && sh -c "GOCOVERDIR=${ARGOCD_COVERAGE_DIR:-/tmp/argo-e2e/app/coverage} FORCE_LOG_COLORS=1 ARGOCD_FAKE_IN_CLUSTER=true ARGOCD_TLS_DATA_PATH=${ARGOCD_TLS_DATA_PATH:-/tmp/argocd-local/tls} ARGOCD_SSH_DATA_PATH=${ARGOCD_SSH_DATA_PATH:-/tmp/argocd-local/ssh} ARGOCD_BINARY_NAME=argocd-server $COMMAND --loglevel debug --redis localhost:${ARGOCD_E2E_REDIS_PORT:-6379} --disable-auth=${ARGOCD_E2E_DISABLE_AUTH:-'true'} --insecure --dex-server http://localhost:${ARGOCD_E2E_DEX_PORT:-5556} --repo-server localhost:${ARGOCD_E2E_REPOSERVER_PORT:-8081} --port ${ARGOCD_E2E_APISERVER_PORT:-8080} --otlp-address=${ARGOCD_OTLP_ADDRESS} --application-namespaces=${ARGOCD_APPLICATION_NAMESPACES:-''}"
dex: sh -c "ARGOCD_BINARY_NAME=argocd-dex go run github.com/argoproj/argo-cd/v2/cmd gendexcfg -o `pwd`/dist/dex.yaml && (test -f dist/dex.yaml || { echo 'Failed to generate dex configuration'; exit 1; }) && docker run --rm -p ${ARGOCD_E2E_DEX_PORT:-5556}:${ARGOCD_E2E_DEX_PORT:-5556} -v `pwd`/dist/dex.yaml:/dex.yaml ghcr.io/dexidp/dex:$(grep "image: ghcr.io/dexidp/dex" manifests/base/dex/argocd-dex-server-deployment.yaml | cut -d':' -f3) dex serve /dex.yaml"
redis: bash -c "if [ \"$ARGOCD_REDIS_LOCAL\" = 'true' ]; then redis-server --save '' --appendonly no --port ${ARGOCD_E2E_REDIS_PORT:-6379}; else docker run --rm --name argocd-redis -i -p ${ARGOCD_E2E_REDIS_PORT:-6379}:${ARGOCD_E2E_REDIS_PORT:-6379} docker.io/library/redis:$(grep "image: redis" manifests/base/redis/argocd-redis-deployment.yaml | cut -d':' -f3) --save '' --appendonly no --port ${ARGOCD_E2E_REDIS_PORT:-6379}; fi"
repo-server: [ "$BIN_MODE" = 'true' ] && COMMAND=./dist/argocd || COMMAND='go run ./cmd/main.go' && sh -c "GOCOVERDIR=${ARGOCD_COVERAGE_DIR:-/tmp/argo-e2e/app/coverage} FORCE_LOG_COLORS=1 ARGOCD_FAKE_IN_CLUSTER=true ARGOCD_GNUPGHOME=${ARGOCD_GNUPGHOME:-/tmp/argocd-local/gpg/keys} ARGOCD_PLUGINSOCKFILEPATH=${ARGOCD_PLUGINSOCKFILEPATH:-./test/cmp}  ARGOCD_GPG_DATA_PATH=${ARGOCD_GPG_DATA_PATH:-/tmp/argocd-local/gpg/source} ARGOCD_TLS_DATA_PATH=${ARGOCD_TLS_DATA_PATH:-/tmp/argocd-local/tls} ARGOCD_SSH_DATA_PATH=${ARGOCD_SSH_DATA_PATH:-/tmp/argocd-local/ssh} ARGOCD_BINARY_NAME=argocd-repo-server ARGOCD_GPG_ENABLED=${ARGOCD_GPG_ENABLED:-false} $COMMAND --loglevel debug --port ${ARGOCD_E2E_REPOSERVER_PORT:-8081} --redis localhost:${ARGOCD_E2E_REDIS_PORT:-6379} --otlp-address=${ARGOCD_OTLP_ADDRESS}"
cmp-server: [ "$ARGOCD_E2E_TEST" = 'true' ] && exit 0 || [ "$BIN_MODE" = 'true' ] && COMMAND=./dist/argocd || COMMAND='go run ./cmd/main.go' && sh -c "FORCE_LOG_COLORS=1 ARGOCD_FAKE_IN_CLUSTER=true ARGOCD_BINARY_NAME=argocd-cmp-server ARGOCD_PLUGINSOCKFILEPATH=${ARGOCD_PLUGINSOCKFILEPATH:-./test/cmp} $COMMAND --config-dir-path ./test/cmp --loglevel debug --otlp-address=${ARGOCD_OTLP_ADDRESS}"
ui: sh -c 'cd ui && ${ARGOCD_E2E_YARN_CMD:-yarn} start'
git-server: test/fixture/testrepos/start-git.sh
helm-registry: test/fixture/testrepos/start-helm-registry.sh
dev-mounter: [[ "$ARGOCD_E2E_TEST" != "true" ]] && go run hack/dev-mounter/main.go --configmap argocd-ssh-known-hosts-cm=${ARGOCD_SSH_DATA_PATH:-/tmp/argocd-local/ssh} --configmap argocd-tls-certs-cm=${ARGOCD_TLS_DATA_PATH:-/tmp/argocd-local/tls} --configmap argocd-gpg-keys-cm=${ARGOCD_GPG_DATA_PATH:-/tmp/argocd-local/gpg/source}
applicationset-controller: [ "$BIN_MODE" = 'true' ] && COMMAND=./dist/argocd || COMMAND='go run ./cmd/main.go' && sh -c "GOCOVERDIR=${ARGOCD_COVERAGE_DIR:-/tmp/argo-e2e/app/coverage} FORCE_LOG_COLORS=4 ARGOCD_FAKE_IN_CLUSTER=true ARGOCD_TLS_DATA_PATH=${ARGOCD_TLS_DATA_PATH:-/tmp/argocd-local/tls} ARGOCD_SSH_DATA_PATH=${ARGOCD_SSH_DATA_PATH:-/tmp/argocd-local/ssh} ARGOCD_BINARY_NAME=argocd-applicationset-controller $COMMAND --loglevel debug --metrics-addr localhost:12345 --probe-addr localhost:12346 --argocd-repo-server localhost:${ARGOCD_E2E_REPOSERVER_PORT:-8081}"
notification: [ "$BIN_MODE" = 'true' ] && COMMAND=./dist/argocd || COMMAND='go run ./cmd/main.go' && sh -c "GOCOVERDIR=${ARGOCD_COVERAGE_DIR:-/tmp/argo-e2e/app/coverage} FORCE_LOG_COLORS=4 ARGOCD_FAKE_IN_CLUSTER=true ARGOCD_TLS_DATA_PATH=${ARGOCD_TLS_DATA_PATH:-/tmp/argocd-local/tls} ARGOCD_BINARY_NAME=argocd-notifications $COMMAND --loglevel debug --application-namespaces=${ARGOCD_APPLICATION_NAMESPACES:-''} --self-service-notification-enabled=${ARGOCD_NOTIFICATION_CONTROLLER_SELF_SERVICE_NOTIFICATION_ENABLED:-'false'}"

