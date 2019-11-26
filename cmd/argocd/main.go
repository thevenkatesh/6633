package main

import (
	commands "github.com/argoproj/argo-cd/cmd/argocd/commands"
	"github.com/argoproj/argo-cd/errors"
	"github.com/argoproj/argo-cd/util/tracer"

	// load the gcp plugin (required to authenticate against GKE clusters).
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	// load the oidc plugin (required to authenticate with OpenID Connect).
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
)

func main() {
	closer, err := tracer.Init("argocd")
	errors.CheckError(err)
	defer func() { _ = closer.Close() }()
	err = commands.NewCommand().Execute()
	errors.CheckError(err)
}
