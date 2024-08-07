package admin

import (
	"context"
	"os"
	"testing"

	fakeappclientset "github.com/argoproj/argo-cd/v2/pkg/client/clientset/versioned/fake"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/argoproj/argo-cd/v2/server/rbacpolicy"
	"github.com/argoproj/argo-cd/v2/util/assets"
)

type FakeClientConfig struct {
	clientConfig clientcmd.ClientConfig
}

func NewFakeClientConfig(clientConfig clientcmd.ClientConfig) *FakeClientConfig {
	return &FakeClientConfig{clientConfig: clientConfig}
}

func (f *FakeClientConfig) RawConfig() (clientcmdapi.Config, error) {
	config, err := f.clientConfig.RawConfig()
	return config, err
}

func (f *FakeClientConfig) ClientConfig() (*restclient.Config, error) {
	return f.clientConfig.ClientConfig()
}

func (f *FakeClientConfig) Namespace() (string, bool, error) {
	return f.clientConfig.Namespace()
}

func (f *FakeClientConfig) ConfigAccess() clientcmd.ConfigAccess {
	return nil
}

func Test_validateRBACResourceAction(t *testing.T) {
	type args struct {
		resource string
		action   string
	}
	tests := []struct {
		name  string
		args  args
		valid bool
	}{
		{
			name: "Test valid resource and action",
			args: args{
				resource: rbacpolicy.ResourceApplications,
				action:   rbacpolicy.ActionCreate,
			},
			valid: true,
		},
		{
			name: "Test invalid resource",
			args: args{
				resource: "invalid",
			},
			valid: false,
		},
		{
			name: "Test invalid action",
			args: args{
				resource: rbacpolicy.ResourceApplications,
				action:   "invalid",
			},
			valid: false,
		},
		{
			name: "Test invalid action for resource",
			args: args{
				resource: rbacpolicy.ResourceLogs,
				action:   rbacpolicy.ActionCreate,
			},
			valid: false,
		},
		{
			name: "Test valid action with path",
			args: args{
				resource: rbacpolicy.ResourceApplications,
				action:   rbacpolicy.ActionAction + "/apps/Deployment/restart",
			},
			valid: true,
		},
		{
			name: "Test invalid action with path",
			args: args{
				resource: rbacpolicy.ResourceApplications,
				action:   rbacpolicy.ActionGet + "/apps/Deployment/restart",
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateRBACResourceAction(tt.args.resource, tt.args.action)
			if tt.valid {
				assert.NoError(t, result)
			} else {
				assert.Error(t, result)
			}
		})
	}
}

func Test_PolicyFromCSV(t *testing.T) {
	ctx := context.Background()

	uPol, dRole, matchMode := getPolicy(ctx, "testdata/rbac/policy.csv", nil, "")
	require.NotEmpty(t, uPol)
	require.Empty(t, dRole)
	require.Empty(t, matchMode)
}

func Test_PolicyFromYAML(t *testing.T) {
	ctx := context.Background()

	uPol, dRole, matchMode := getPolicy(ctx, "testdata/rbac/argocd-rbac-cm.yaml", nil, "")
	require.NotEmpty(t, uPol)
	require.Equal(t, "role:unknown", dRole)
	require.Empty(t, matchMode)
	require.True(t, checkPolicy("my-org:team-qa", "update", "project", "foo",
		"", uPol, dRole, matchMode, true))
}

func Test_PolicyFromK8s(t *testing.T) {
	data, err := os.ReadFile("testdata/rbac/policy.csv")
	ctx := context.Background()

	require.NoError(t, err)
	kubeclientset := fake.NewSimpleClientset(&v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "argocd-rbac-cm",
			Namespace: "argocd",
		},
		Data: map[string]string{
			"policy.csv":     string(data),
			"policy.default": "role:unknown",
		},
	})
	uPol, dRole, matchMode := getPolicy(ctx, "", kubeclientset, "argocd")
	require.NotEmpty(t, uPol)
	require.Equal(t, "role:unknown", dRole)
	require.Equal(t, "", matchMode)

	t.Run("get applications", func(t *testing.T) {
		ok := checkPolicy("", "role:user", "get", "applications", "*/*", assets.BuiltinPolicyCSV, uPol, "", dRole, "", true)
		require.True(t, ok)
	})
	t.Run("get clusters", func(t *testing.T) {
		ok := checkPolicy("", "role:user", "get", "clusters", "*", assets.BuiltinPolicyCSV, uPol, "", dRole, "", true)
		require.True(t, ok)
	})
	t.Run("get certificates", func(t *testing.T) {
		ok := checkPolicy("", "role:user", "get", "certificates", "*", assets.BuiltinPolicyCSV, uPol, "", dRole, "", true)
		require.False(t, ok)
	})
	t.Run("get certificates by default role", func(t *testing.T) {
		ok := checkPolicy("", "role:user", "get", "certificates", "*", assets.BuiltinPolicyCSV, uPol, "", "role:readonly", "glob", true)
		require.True(t, ok)
	})
	t.Run("get certificates by default role without builtin policy", func(t *testing.T) {
		ok := checkPolicy("", "role:user", "get", "certificates", "*", "", uPol, "", "role:readonly", "glob", true)
		require.False(t, ok)
	})
	t.Run("use regex match mode instead of glob", func(t *testing.T) {
		ok := checkPolicy("", "role:user", "get", "certificates", ".*", assets.BuiltinPolicyCSV, uPol, "", "role:readonly", "regex", true)
		require.False(t, ok)
	})
	t.Run("get logs", func(t *testing.T) {
		ok := checkPolicy("", "role:test", "get", "logs", "*/*", assets.BuiltinPolicyCSV, uPol, "", dRole, "", true)
		require.True(t, ok)
	})
	t.Run("create exec", func(t *testing.T) {
		ok := checkPolicy("", "role:test", "create", "exec", "*/*", assets.BuiltinPolicyCSV, uPol, "", dRole, "", true)
		require.True(t, ok)
	})
	t.Run("create applicationsets", func(t *testing.T) {
		ok := checkPolicy("", "role:user", "create", "applicationsets", "*/*", assets.BuiltinPolicyCSV, uPol, "", dRole, "", true)
		require.True(t, ok)
	})
	t.Run("delete applicationsets", func(t *testing.T) {
		ok := checkPolicy("", "role:user", "delete", "applicationsets", "*/*", assets.BuiltinPolicyCSV, uPol, "", dRole, "", true)
		require.True(t, ok)
	})
}

func Test_PolicyFromK8sUsingRegex(t *testing.T) {
	ctx := context.Background()

	policy := `
p, role:user, clusters, get, .+, allow
p, role:user, clusters, get, https://kubernetes.*, deny
p, role:user, applications, get, .*, allow
p, role:user, applications, create, .*/.*, allow
p, role:user, applicationsets, create, .*/.*, allow
p, role:user, applicationsets, delete, .*/.*, allow
p, role:user, logs, get, .*/.*, allow
p, role:user, exec, create, .*/.*, allow
`

	kubeclientset := fake.NewSimpleClientset(&v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "argocd-rbac-cm",
			Namespace: "argocd",
		},
		Data: map[string]string{
			"policy.csv":       policy,
			"policy.default":   "role:unknown",
			"policy.matchMode": "regex",
		},
	})
	uPol, dRole, matchMode := getPolicy(ctx, "", kubeclientset, "argocd")
	require.NotEmpty(t, uPol)
	require.Equal(t, "role:unknown", dRole)
	require.Equal(t, "regex", matchMode)

	builtInPolicy := `
p, role:readonly, certificates, get, .*, allow
p, role:, certificates, get, .*, allow`

	t.Run("get applications", func(t *testing.T) {
		ok := checkPolicy("", "role:user", "get", "applications", ".*/.*", builtInPolicy, uPol, "", dRole, "regex", true)
		require.True(t, ok)
	})
	t.Run("get clusters", func(t *testing.T) {
		ok := checkPolicy("", "role:user", "get", "clusters", ".*", builtInPolicy, uPol, "", dRole, "regex", true)
		require.True(t, ok)
	})
	t.Run("get certificates", func(t *testing.T) {
		ok := checkPolicy("", "role:user", "get", "certificates", ".*", builtInPolicy, uPol, "", dRole, "regex", true)
		require.False(t, ok)
	})
	t.Run("get certificates by default role", func(t *testing.T) {
		ok := checkPolicy("", "role:user", "get", "certificates", ".*", builtInPolicy, uPol, "", "role:readonly", "regex", true)
		require.True(t, ok)
	})
	t.Run("get certificates by default role without builtin policy", func(t *testing.T) {
		ok := checkPolicy("", "role:user", "get", "certificates", ".*", "", uPol, "", "role:readonly", "regex", true)
		require.False(t, ok)
	})
	t.Run("use glob match mode instead of regex", func(t *testing.T) {
		ok := checkPolicy("", "role:user", "get", "certificates", ".+", builtInPolicy, uPol, "", dRole, "glob", true)
		require.False(t, ok)
	})
	t.Run("get logs via glob match mode", func(t *testing.T) {
		ok := checkPolicy("", "role:user", "get", "logs", ".*/.*", builtInPolicy, uPol, "", dRole, "glob", true)
		require.True(t, ok)
	})
	t.Run("create exec", func(t *testing.T) {
		ok := checkPolicy("", "role:user", "create", "exec", ".*/.*", builtInPolicy, uPol, "", dRole, "regex", true)
		require.True(t, ok)
	})
	t.Run("create applicationsets", func(t *testing.T) {
		ok := checkPolicy("", "role:user", "create", "applicationsets", ".*/.*", builtInPolicy, uPol, "", dRole, "regex", true)
		require.True(t, ok)
	})
	t.Run("delete applicationsets", func(t *testing.T) {
		ok := checkPolicy("", "role:user", "delete", "applicationsets", ".*/.*", builtInPolicy, uPol, "", dRole, "regex", true)
		require.True(t, ok)
	})
}

func Test_PolicyFromAppProjects(t *testing.T) {
	ctx := context.Background()

	policy := `
g, role:user, proj:foo:test
g, role:user, proj:bar:test
`

	kubeclientset := fake.NewSimpleClientset(&v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "argocd-rbac-cm",
			Namespace: "argocd",
		},
		Data: map[string]string{
			"policy.csv":       policy,
			"policy.default":   "",
			"policy.matchMode": "glob",
		},
	})

	appclients := fakeappclientset.NewSimpleClientset(newProj("foo", "test"))
	projIf := appclients.ArgoprojV1alpha1().AppProjects(namespace)
	uPol, dRole, matchMode := getPolicy(ctx, "", kubeclientset, "argocd")

	require.Equal(t, policy, uPol)
	require.Empty(t, dRole)
	require.Equal(t, "glob", matchMode)

	t.Run("get applications", func(t *testing.T) {
		modification, err := getModification("set", "applications", "*", "allow")
		require.NoError(t, err)
		err = updateProjects(ctx, projIf, "foo", "test", "get", modification, false)
		require.NoError(t, err)

		projectPolicies := getProjectPolicies(ctx, projIf, "*")
		ok := checkPolicy("*", "role:user", "get", "applications", "*/*", assets.BuiltinPolicyCSV, uPol, projectPolicies, dRole, "glob", true)
		require.False(t, ok)

		projectPolicies = getProjectPolicies(ctx, projIf, "foo")

		ok = checkPolicy("foo", "role:user", "get", "applications", "foo/*", assets.BuiltinPolicyCSV, uPol, projectPolicies, dRole, "glob", true)
		require.True(t, ok)
	})

	t.Run("create applications", func(t *testing.T) {
		modification, err := getModification("set", "applications", "*", "allow")
		require.NoError(t, err)
		err = updateProjects(ctx, projIf, "foo", "test", "create", modification, false)
		require.NoError(t, err)

		projectPolicies := getProjectPolicies(ctx, projIf, "*")
		ok := checkPolicy("foo", "role:user", "create", "applications", "*/*", assets.BuiltinPolicyCSV, uPol, projectPolicies, dRole, "glob", true)
		require.False(t, ok)

		projectPolicies = getProjectPolicies(ctx, projIf, "foo")
		ok = checkPolicy("foo", "role:user", "create", "applications", "foo/*", assets.BuiltinPolicyCSV, uPol, projectPolicies, dRole, "glob", true)
		require.True(t, ok)
	})

	t.Run("update applications", func(t *testing.T) {
		modification, err := getModification("set", "applications", "*", "allow")
		require.NoError(t, err)
		err = updateProjects(ctx, projIf, "foo", "test", "update", modification, false)
		require.NoError(t, err)

		projectPolicies := getProjectPolicies(ctx, projIf, "*")
		ok := checkPolicy("foo", "role:user", "update", "applications", "*/*", assets.BuiltinPolicyCSV, uPol, projectPolicies, dRole, "glob", true)
		require.False(t, ok)

		projectPolicies = getProjectPolicies(ctx, projIf, "foo")
		ok = checkPolicy("foo", "role:user", "update", "applications", "foo/*", assets.BuiltinPolicyCSV, uPol, projectPolicies, dRole, "glob", true)
		require.True(t, ok)
	})

	t.Run("delete applications", func(t *testing.T) {
		modification, err := getModification("set", "applications", "*", "allow")
		require.NoError(t, err)
		err = updateProjects(ctx, projIf, "foo", "test", "delete", modification, false)
		require.NoError(t, err)

		projectPolicies := getProjectPolicies(ctx, projIf, "*")
		ok := checkPolicy("foo", "role:user", "delete", "applications", "*/*", assets.BuiltinPolicyCSV, uPol, projectPolicies, dRole, "glob", true)
		require.False(t, ok)

		projectPolicies = getProjectPolicies(ctx, projIf, "foo")
		ok = checkPolicy("foo", "role:user", "delete", "applications", "foo/*", assets.BuiltinPolicyCSV, uPol, projectPolicies, dRole, "glob", true)
		require.True(t, ok)
	})

	t.Run("sync applications", func(t *testing.T) {
		modification, err := getModification("set", "applications", "*", "allow")
		require.NoError(t, err)
		err = updateProjects(ctx, projIf, "foo", "test", "sync", modification, false)
		require.NoError(t, err)

		projectPolicies := getProjectPolicies(ctx, projIf, "*")
		ok := checkPolicy("foo", "role:user", "sync", "applications", "*/*", assets.BuiltinPolicyCSV, uPol, projectPolicies, dRole, "glob", true)
		require.False(t, ok)

		projectPolicies = getProjectPolicies(ctx, projIf, "foo")
		ok = checkPolicy("foo", "role:user", "sync", "applications", "foo/*", assets.BuiltinPolicyCSV, uPol, projectPolicies, dRole, "glob", true)
		require.True(t, ok)
	})

	t.Run("get applicationsets", func(t *testing.T) {
		modification, err := getModification("set", "applicationsets", "*", "allow")
		require.NoError(t, err)
		err = updateProjects(ctx, projIf, "foo", "test", "get", modification, false)
		require.NoError(t, err)

		projectPolicies := getProjectPolicies(ctx, projIf, "*")
		ok := checkPolicy("foo", "role:user", "get", "applicationsets", "*/*", assets.BuiltinPolicyCSV, uPol, projectPolicies, dRole, "glob", true)
		require.False(t, ok)

		projectPolicies = getProjectPolicies(ctx, projIf, "foo")
		ok = checkPolicy("foo", "role:user", "get", "applicationsets", "foo/*", assets.BuiltinPolicyCSV, uPol, projectPolicies, dRole, "glob", true)
		require.True(t, ok)
	})

	t.Run("create applicationsets", func(t *testing.T) {
		modification, err := getModification("set", "applicationsets", "*", "allow")
		require.NoError(t, err)
		err = updateProjects(ctx, projIf, "foo", "test", "create", modification, false)
		require.NoError(t, err)

		projectPolicies := getProjectPolicies(ctx, projIf, "*")
		ok := checkPolicy("foo", "role:user", "create", "applicationsets", "*/*", assets.BuiltinPolicyCSV, uPol, projectPolicies, dRole, "glob", true)
		require.False(t, ok)

		projectPolicies = getProjectPolicies(ctx, projIf, "foo")
		ok = checkPolicy("foo", "role:user", "create", "applicationsets", "foo/*", assets.BuiltinPolicyCSV, uPol, projectPolicies, dRole, "glob", true)
		require.True(t, ok)
	})

	t.Run("update applicationsets", func(t *testing.T) {
		modification, err := getModification("set", "applicationsets", "*", "allow")
		require.NoError(t, err)
		err = updateProjects(ctx, projIf, "foo", "test", "update", modification, false)
		require.NoError(t, err)

		projectPolicies := getProjectPolicies(ctx, projIf, "*")
		ok := checkPolicy("foo", "role:user", "update", "applicationsets", "*/*", assets.BuiltinPolicyCSV, uPol, projectPolicies, dRole, "glob", true)
		require.False(t, ok)

		projectPolicies = getProjectPolicies(ctx, projIf, "foo")
		ok = checkPolicy("foo", "role:user", "update", "applicationsets", "foo/*", assets.BuiltinPolicyCSV, uPol, projectPolicies, dRole, "glob", true)
		require.True(t, ok)
	})

	t.Run("delete applicationsets", func(t *testing.T) {
		modification, err := getModification("set", "applicationsets", "*", "allow")
		require.NoError(t, err)
		err = updateProjects(ctx, projIf, "foo", "test", "delete", modification, false)
		require.NoError(t, err)

		projectPolicies := getProjectPolicies(ctx, projIf, "*")
		ok := checkPolicy("foo", "role:user", "delete", "applicationsets", "*/*", assets.BuiltinPolicyCSV, uPol, projectPolicies, dRole, "glob", true)
		require.False(t, ok)

		projectPolicies = getProjectPolicies(ctx, projIf, "foo")
		ok = checkPolicy("foo", "role:user", "delete", "applicationsets", "foo/*", assets.BuiltinPolicyCSV, uPol, projectPolicies, dRole, "glob", true)
		require.True(t, ok)
	})

	t.Run("get logs", func(t *testing.T) {
		modification, err := getModification("set", "logs", "*", "allow")
		require.NoError(t, err)
		err = updateProjects(ctx, projIf, "foo", "test", "get", modification, false)
		require.NoError(t, err)

		projectPolicies := getProjectPolicies(ctx, projIf, "*")
		ok := checkPolicy("foo", "role:user", "get", "logs", "*/*", assets.BuiltinPolicyCSV, uPol, projectPolicies, dRole, "glob", true)
		require.False(t, ok)

		projectPolicies = getProjectPolicies(ctx, projIf, "foo")
		ok = checkPolicy("foo", "role:user", "get", "logs", "foo/*", assets.BuiltinPolicyCSV, uPol, projectPolicies, dRole, "glob", true)
		require.True(t, ok)
	})

	t.Run("create exec", func(t *testing.T) {
		modification, err := getModification("set", "exec", "*", "allow")
		require.NoError(t, err)
		err = updateProjects(ctx, projIf, "foo", "test", "create", modification, false)
		require.NoError(t, err)

		projectPolicies := getProjectPolicies(ctx, projIf, "*")
		ok := checkPolicy("foo", "role:user", "create", "exec", "*/*", assets.BuiltinPolicyCSV, uPol, projectPolicies, dRole, "glob", true)
		require.False(t, ok)

		projectPolicies = getProjectPolicies(ctx, projIf, "foo")
		ok = checkPolicy("foo", "role:user", "create", "exec", "foo/*", assets.BuiltinPolicyCSV, uPol, projectPolicies, dRole, "glob", true)
		require.True(t, ok)
	})
}

func TestNewRBACCanCommand(t *testing.T) {
	command := NewRBACCanCommand()

	require.NotNil(t, command)
	assert.Equal(t, "can", command.Name())
	assert.Equal(t, "Check RBAC permissions for a role or subject", command.Short)
}

func TestNewRBACValidateCommand(t *testing.T) {
	command := NewRBACValidateCommand()

	require.NotNil(t, command)
	assert.Equal(t, "validate", command.Name())
	assert.Equal(t, "Validate RBAC policy", command.Short)
}
