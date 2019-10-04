package v1alpha1

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAppProject_IsSourcePermitted(t *testing.T) {
	testData := []struct {
		projSources []string
		appSource   string
		isPermitted bool
	}{{
		projSources: []string{"*"}, appSource: "https://github.com/argoproj/test.git", isPermitted: true,
	}, {
		projSources: []string{"https://github.com/argoproj/test.git"}, appSource: "https://github.com/argoproj/test.git", isPermitted: true,
	}, {
		projSources: []string{"ssh://git@GITHUB.com:argoproj/test"}, appSource: "ssh://git@github.com:argoproj/test", isPermitted: true,
	}, {
		projSources: []string{"https://github.com/argoproj/*"}, appSource: "https://github.com/argoproj/argoproj.git", isPermitted: true,
	}, {
		projSources: []string{"https://github.com/test1/test.git", "https://github.com/test2/test.git"}, appSource: "https://github.com/test2/test.git", isPermitted: true,
	}, {
		projSources: []string{"https://github.com/argoproj/test1.git"}, appSource: "https://github.com/argoproj/test2.git", isPermitted: false,
	}, {
		projSources: []string{"https://github.com/argoproj/*.git"}, appSource: "https://github.com/argoproj1/test2.git", isPermitted: false,
	}, {
		projSources: []string{"https://github.com/argoproj/foo"}, appSource: "https://github.com/argoproj/foo1", isPermitted: false,
	}}

	for _, data := range testData {
		proj := AppProject{
			Spec: AppProjectSpec{
				SourceRepos: data.projSources,
			},
		}
		assert.Equal(t, proj.IsSourcePermitted(ApplicationSource{
			RepoURL: data.appSource,
		}), data.isPermitted)
	}
}

func TestAppProject_IsDestinationPermitted(t *testing.T) {
	testData := []struct {
		projDest    []ApplicationDestination
		appDest     ApplicationDestination
		isPermitted bool
	}{{
		projDest: []ApplicationDestination{{
			Server: "https://kubernetes.default.svc", Namespace: "default",
		}},
		appDest:     ApplicationDestination{Server: "https://kubernetes.default.svc", Namespace: "default"},
		isPermitted: true,
	}, {
		projDest: []ApplicationDestination{{
			Server: "https://kubernetes.default.svc", Namespace: "default",
		}},
		appDest:     ApplicationDestination{Server: "https://kubernetes.default.svc", Namespace: "kube-system"},
		isPermitted: false,
	}, {
		projDest: []ApplicationDestination{{
			Server: "https://my-cluster", Namespace: "default",
		}},
		appDest:     ApplicationDestination{Server: "https://kubernetes.default.svc", Namespace: "default"},
		isPermitted: false,
	}, {
		projDest: []ApplicationDestination{{
			Server: "https://kubernetes.default.svc", Namespace: "*",
		}},
		appDest:     ApplicationDestination{Server: "https://kubernetes.default.svc", Namespace: "kube-system"},
		isPermitted: true,
	}, {
		projDest: []ApplicationDestination{{
			Server: "https://*.default.svc", Namespace: "default",
		}},
		appDest:     ApplicationDestination{Server: "https://kubernetes.default.svc", Namespace: "default"},
		isPermitted: true,
	}, {
		projDest: []ApplicationDestination{{
			Server: "https://team1-*", Namespace: "default",
		}},
		appDest:     ApplicationDestination{Server: "https://test2-dev-cluster", Namespace: "default"},
		isPermitted: false,
	}, {
		projDest: []ApplicationDestination{{
			Server: "https://kubernetes.default.svc", Namespace: "test-*",
		}},
		appDest:     ApplicationDestination{Server: "https://kubernetes.default.svc", Namespace: "test-foo"},
		isPermitted: true,
	}, {
		projDest: []ApplicationDestination{{
			Server: "https://kubernetes.default.svc", Namespace: "test-*",
		}},
		appDest:     ApplicationDestination{Server: "https://kubernetes.default.svc", Namespace: "test"},
		isPermitted: false,
	}, {
		projDest: []ApplicationDestination{{
			Server: "*", Namespace: "*",
		}},
		appDest:     ApplicationDestination{Server: "https://kubernetes.default.svc", Namespace: "test"},
		isPermitted: true,
	}}

	for _, data := range testData {
		proj := AppProject{
			Spec: AppProjectSpec{
				Destinations: data.projDest,
			},
		}
		assert.Equal(t, proj.IsDestinationPermitted(data.appDest), data.isPermitted)
	}
}

func TestAppProject_GetRoleByName(t *testing.T) {
	t.Run("NotExists", func(t *testing.T) {
		p := &AppProject{}
		role, i, err := p.GetRoleByName("test-role")
		assert.Error(t, err)
		assert.Equal(t, -1, i)
		assert.Nil(t, role)
	})
	t.Run("NotExists", func(t *testing.T) {
		p := AppProject{Spec: AppProjectSpec{Roles: []ProjectRole{{Name: "test-role"}}}}
		role, i, err := p.GetRoleByName("test-role")
		assert.NoError(t, err)
		assert.Equal(t, 0, i)
		assert.Equal(t, &ProjectRole{Name: "test-role"}, role)
	})
}

func TestAppProject_AddGroupToRole(t *testing.T) {
	t.Run("NoRole", func(t *testing.T) {
		p := &AppProject{}
		got, err := p.AddGroupToRole("test-role", "test-group")
		assert.Error(t, err)
		assert.False(t, got)
	})
	t.Run("NoGroup", func(t *testing.T) {
		p := &AppProject{Spec: AppProjectSpec{Roles: []ProjectRole{{Name: "test-role", Groups: []string{}}}}}
		got, err := p.AddGroupToRole("test-role", "test-group")
		assert.NoError(t, err)
		assert.True(t, got)
		assert.Len(t, p.Spec.Roles[0].Groups, 1)
	})
	t.Run("Exists", func(t *testing.T) {
		p := &AppProject{Spec: AppProjectSpec{Roles: []ProjectRole{{Name: "test-role", Groups: []string{"test-group"}}}}}
		got, err := p.AddGroupToRole("test-role", "test-group")
		assert.NoError(t, err)
		assert.False(t, got)
	})
}

func TestAppProject_RemoveGroupFromRole(t *testing.T) {
	t.Run("NoRole", func(t *testing.T) {
		p := &AppProject{}
		got, err := p.RemoveGroupFromRole("test-role", "test-group")
		assert.Error(t, err)
		assert.False(t, got)
	})
	t.Run("NoGroup", func(t *testing.T) {
		p := &AppProject{Spec: AppProjectSpec{Roles: []ProjectRole{{Name: "test-role", Groups: []string{}}}}}
		got, err := p.RemoveGroupFromRole("test-role", "test-group")
		assert.NoError(t, err)
		assert.False(t, got)
	})
	t.Run("Exists", func(t *testing.T) {
		p := &AppProject{Spec: AppProjectSpec{Roles: []ProjectRole{{Name: "test-role", Groups: []string{"test-group"}}}}}
		got, err := p.RemoveGroupFromRole("test-role", "test-group")
		assert.NoError(t, err)
		assert.True(t, got)
		assert.Len(t, p.Spec.Roles[0].Groups, 0)
	})
}

func newTestProject() *AppProject {
	p := AppProject{
		ObjectMeta: v1.ObjectMeta{Name: "my-proj"},
		Spec:       AppProjectSpec{Roles: []ProjectRole{{Name: "my-role"}}},
	}
	return &p
}

// TestValidateRoleName tests for an invalid role name
func TestAppProject_ValidateRoleName(t *testing.T) {
	p := newTestProject()
	err := p.ValidateProject()
	assert.NoError(t, err)
	badRoleNames := []string{
		"",
		" ",
		"my role",
		"my, role",
		"my,role",
		"my\nrole",
		"my\rrole",
		"my:role",
		"my-role-",
		"-my-role",
	}
	for _, badName := range badRoleNames {
		p.Spec.Roles[0].Name = badName
		err = p.ValidateProject()
		assert.Error(t, err)
	}
	goodRoleNames := []string{
		"MY-ROLE",
		"1MY-ROLE1",
	}
	for _, goodName := range goodRoleNames {
		p.Spec.Roles[0].Name = goodName
		err = p.ValidateProject()
		assert.NoError(t, err)
	}
}

// TestValidateGroupName tests for an invalid group name
func TestAppProject_ValidateGroupName(t *testing.T) {
	p := newTestProject()
	err := p.ValidateProject()
	assert.NoError(t, err)
	p.Spec.Roles[0].Groups = []string{"mygroup"}
	err = p.ValidateProject()
	assert.NoError(t, err)
	badGroupNames := []string{
		"",
		" ",
		"my, group",
		"my,group",
		"my\ngroup",
		"my\rgroup",
	}
	for _, badName := range badGroupNames {
		p.Spec.Roles[0].Groups = []string{badName}
		err = p.ValidateProject()
		assert.Error(t, err)
	}
	goodGroupNames := []string{
		"my:group",
	}
	for _, goodName := range goodGroupNames {
		p.Spec.Roles[0].Groups = []string{goodName}
		err = p.ValidateProject()
		assert.NoError(t, err)
	}
}

// TestInvalidPolicyRules checks various errors in policy rules
func TestAppProject_InvalidPolicyRules(t *testing.T) {
	p := newTestProject()
	err := p.ValidateProject()
	assert.NoError(t, err)
	type badPolicy struct {
		policy string
		errmsg string
	}
	badPolicies := []badPolicy{
		// should have spaces
		{"p,proj:my-proj:my-role,applications,get,my-proj/*,allow", "syntax"},
		// incorrect form
		{"g, proj:my-proj:my-role, applications, get, my-proj/*, allow", "must be of the form: 'p, sub, res, act, obj, eft'"},
		{"p, not, enough, parts", "must be of the form: 'p, sub, res, act, obj, eft'"},
		{"p, has, too, many, parts, to, split", "must be of the form: 'p, sub, res, act, obj, eft'"},
		// invalid subject
		{"p, , applications, get, my-proj/*, allow", "policy subject must be: 'proj:my-proj:my-role'"},
		{"p, proj:my-proj, applications, get, my-proj/*, allow", "policy subject must be: 'proj:my-proj:my-role'"},
		{"p, proj:my-proj:, applications, get, my-proj/*, allow", "policy subject must be: 'proj:my-proj:my-role'"},
		{"p, ::, applications, get, my-proj/*, allow", "policy subject must be: 'proj:my-proj:my-role'"},
		{"p, proj:different-my-proj:my-role, applications, get, my-proj/*, allow", "policy subject must be: 'proj:my-proj:my-role'"},
		// invalid resource
		{"p, proj:my-proj:my-role, , get, my-proj/*, allow", "resource must be: 'applications'"},
		{"p, proj:my-proj:my-role, applicationz, get, my-proj/*, allow", "resource must be: 'applications'"},
		{"p, proj:my-proj:my-role, projects, get, my-proj, allow", "resource must be: 'applications'"},
		// invalid action
		{"p, proj:my-proj:my-role, applications, , my-proj/*, allow", "invalid action"},
		{"p, proj:my-proj:my-role, applications, foo, my-proj/*, allow", "invalid action"},
		// invalid object
		{"p, proj:my-proj:my-role, applications, get, my-proj/, allow", "object must be of form"},
		{"p, proj:my-proj:my-role, applications, get, /, allow", "object must be of form"},
		{"p, proj:my-proj:my-role, applications, get, different-my-proj/*, allow", "object must be of form"},
		// invalid effect
		{"p, proj:my-proj:my-role, applications, get, my-proj/*, ", "effect must be: 'allow' or 'deny'"},
		{"p, proj:my-proj:my-role, applications, get, my-proj/*, foo", "effect must be: 'allow' or 'deny'"},
	}
	for _, bad := range badPolicies {
		p.Spec.Roles[0].Policies = []string{bad.policy}
		err = p.ValidateProject()
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), bad.errmsg)
		}
	}
}

// TestValidPolicyRules checks valid policy rules
func TestAppProject_ValidPolicyRules(t *testing.T) {
	p := newTestProject()
	err := p.ValidateProject()
	assert.NoError(t, err)
	goodPolicies := []string{
		"p, proj:my-proj:my-role, applications, get, my-proj/*, allow",
		"p, proj:my-proj:my-role, applications, get, my-proj/*, deny",
		"p, proj:my-proj:my-role, applications, get, my-proj/foo, allow",
		"p, proj:my-proj:my-role, applications, get, my-proj/*-foo, allow",
		"p, proj:my-proj:my-role, applications, get, my-proj/foo-*, allow",
		"p, proj:my-proj:my-role, applications, get, my-proj/*-*, allow",
		"p, proj:my-proj:my-role, applications, *, my-proj/foo, allow",
		"p, proj:my-proj:my-role, applications, create, my-proj/foo, allow",
		"p, proj:my-proj:my-role, applications, update, my-proj/foo, allow",
		"p, proj:my-proj:my-role, applications, sync, my-proj/foo, allow",
		"p, proj:my-proj:my-role, applications, delete, my-proj/foo, allow",
	}
	for _, good := range goodPolicies {
		p.Spec.Roles[0].Policies = []string{good}
		err = p.ValidateProject()
		assert.NoError(t, err)
	}
}

func TestExplicitType(t *testing.T) {
	src := ApplicationSource{
		Ksonnet: &ApplicationSourceKsonnet{
			Environment: "foo",
		},
		Kustomize: &ApplicationSourceKustomize{
			NamePrefix: "foo",
		},
		Helm: &ApplicationSourceHelm{
			ValueFiles: []string{"foo"},
		},
	}
	explicitType, err := src.ExplicitType()
	assert.NotNil(t, err)
	assert.Nil(t, explicitType)
	src = ApplicationSource{
		Helm: &ApplicationSourceHelm{
			ValueFiles: []string{"foo"},
		},
	}

	explicitType, err = src.ExplicitType()
	assert.Nil(t, err)
	assert.Equal(t, *explicitType, ApplicationSourceTypeHelm)
}

func TestExplicitTypeWithDirectory(t *testing.T) {
	src := ApplicationSource{
		Ksonnet: &ApplicationSourceKsonnet{
			Environment: "foo",
		},
		Directory: &ApplicationSourceDirectory{},
	}
	_, err := src.ExplicitType()
	assert.NotNil(t, err, "cannot add directory with any other types")
}

func TestAppSourceEquality(t *testing.T) {
	left := &ApplicationSource{
		Directory: &ApplicationSourceDirectory{
			Recurse: true,
		},
	}
	right := left.DeepCopy()
	assert.True(t, left.Equals(*right))
	right.Directory.Recurse = false
	assert.False(t, left.Equals(*right))
}

func TestAppDestinationEquality(t *testing.T) {
	left := &ApplicationDestination{
		Server:    "https://kubernetes.default.svc",
		Namespace: "default",
	}
	right := left.DeepCopy()
	assert.True(t, left.Equals(*right))
	right.Namespace = "kube-system"
	assert.False(t, left.Equals(*right))
}

func TestAppProjectSpec_DestinationClusters(t *testing.T) {
	tests := []struct {
		name         string
		destinations []ApplicationDestination
		want         []string
	}{
		{
			name:         "Empty",
			destinations: []ApplicationDestination{},
			want:         []string{},
		},
		{
			name:         "SingleValue",
			destinations: []ApplicationDestination{{Server: "foo"}},
			want:         []string{"foo"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := AppProjectSpec{Destinations: tt.destinations}
			if got := d.DestinationClusters(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AppProjectSpec.DestinationClusters() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRepository_CopyCredentialsFrom(t *testing.T) {
	tests := []struct {
		name   string
		repo   *Repository
		source *Repository
		want   Repository
	}{
		{"Username", &Repository{Username: "foo"}, &Repository{}, Repository{Username: "foo"}},
		{"Password", &Repository{Password: "foo"}, &Repository{}, Repository{Password: "foo"}},
		{"SSHPrivateKey", &Repository{SSHPrivateKey: "foo"}, &Repository{}, Repository{SSHPrivateKey: "foo"}},
		{"InsecureHostKey", &Repository{InsecureIgnoreHostKey: true}, &Repository{}, Repository{InsecureIgnoreHostKey: true}},
		{"Insecure", &Repository{Insecure: true}, &Repository{}, Repository{Insecure: true}},
		{"EnableLFS", &Repository{EnableLFS: true}, &Repository{}, Repository{EnableLFS: true}},
		{"TLSClientCertData", &Repository{TLSClientCertData: "foo"}, &Repository{}, Repository{TLSClientCertData: "foo"}},
		{"TLSClientCertKey", &Repository{TLSClientCertKey: "foo"}, &Repository{}, Repository{TLSClientCertKey: "foo"}},
		{"SourceNil", &Repository{}, nil, Repository{}},

		{"SourceUsername", &Repository{}, &Repository{Username: "foo"}, Repository{Username: "foo"}},
		{"SourcePassword", &Repository{}, &Repository{Password: "foo"}, Repository{Password: "foo"}},
		{"SourceSSHPrivateKey", &Repository{}, &Repository{SSHPrivateKey: "foo"}, Repository{SSHPrivateKey: "foo"}},
		{"SourceInsecureHostKey", &Repository{}, &Repository{InsecureIgnoreHostKey: true}, Repository{InsecureIgnoreHostKey: true}},
		{"SourceInsecure", &Repository{}, &Repository{Insecure: true}, Repository{Insecure: true}},
		{"SourceEnableLFS", &Repository{}, &Repository{EnableLFS: true}, Repository{EnableLFS: true}},
		{"SourceTLSClientCertData", &Repository{}, &Repository{TLSClientCertData: "foo"}, Repository{TLSClientCertData: "foo"}},
		{"SourceTLSClientCertKey", &Repository{}, &Repository{TLSClientCertKey: "foo"}, Repository{TLSClientCertKey: "foo"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.repo.DeepCopy()
			r.CopyCredentialsFrom(tt.source)
			assert.Equal(t, tt.want, *r)
		})
	}
}

func TestNewHookType(t *testing.T) {
	t.Run("Garbage", func(t *testing.T) {
		_, ok := NewHookType("Garbage")
		assert.False(t, ok)
	})
	t.Run("PreSync", func(t *testing.T) {
		hookType, ok := NewHookType("PreSync")
		assert.True(t, ok)
		assert.Equal(t, HookTypePreSync, hookType)
	})
	t.Run("Sync", func(t *testing.T) {
		hookType, ok := NewHookType("Sync")
		assert.True(t, ok)
		assert.Equal(t, HookTypeSync, hookType)
	})
	t.Run("PostSync", func(t *testing.T) {
		hookType, ok := NewHookType("PostSync")
		assert.True(t, ok)
		assert.Equal(t, HookTypePostSync, hookType)
	})
}

func TestNewHookDeletePolicy(t *testing.T) {
	t.Run("Garbage", func(t *testing.T) {
		_, ok := NewHookDeletePolicy("Garbage")
		assert.False(t, ok)
	})
	t.Run("HookSucceeded", func(t *testing.T) {
		p, ok := NewHookDeletePolicy("HookSucceeded")
		assert.True(t, ok)
		assert.Equal(t, HookDeletePolicyHookSucceeded, p)
	})
	t.Run("HookFailed", func(t *testing.T) {
		p, ok := NewHookDeletePolicy("HookFailed")
		assert.True(t, ok)
		assert.Equal(t, HookDeletePolicyHookFailed, p)
	})
	t.Run("BeforeHookCreation", func(t *testing.T) {
		p, ok := NewHookDeletePolicy("BeforeHookCreation")
		assert.True(t, ok)
		assert.Equal(t, HookDeletePolicyBeforeHookCreation, p)
	})
}

func TestSyncStrategy_Force(t *testing.T) {
	type fields struct {
		Apply *SyncStrategyApply
		Hook  *SyncStrategyHook
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{"TestZero", fields{}, false},
		{"TestApply", fields{Apply: &SyncStrategyApply{}}, false},
		{"TestForceApply", fields{Apply: &SyncStrategyApply{Force: true}}, true},
		{"TestHook", fields{Hook: &SyncStrategyHook{}}, false},
		{"TestForceHook", fields{Hook: &SyncStrategyHook{SyncStrategyApply{Force: true}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &SyncStrategy{
				Apply: tt.fields.Apply,
				Hook:  tt.fields.Hook,
			}
			if got := m.Force(); got != tt.want {
				t.Errorf("SyncStrategy.Force() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSyncOperation_IsApplyStrategy(t *testing.T) {
	type fields struct {
		SyncStrategy *SyncStrategy
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{"TestZero", fields{}, false},
		{"TestSyncStrategy", fields{SyncStrategy: &SyncStrategy{}}, false},
		{"TestApplySyncStrategy", fields{SyncStrategy: &SyncStrategy{Apply: &SyncStrategyApply{}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &SyncOperation{
				SyncStrategy: tt.fields.SyncStrategy,
			}
			if got := o.IsApplyStrategy(); got != tt.want {
				t.Errorf("SyncOperation.IsApplyStrategy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResourceResults_Filter(t *testing.T) {
	type args struct {
		predicate func(r *ResourceResult) bool
	}
	tests := []struct {
		name string
		r    ResourceResults
		args args
		want ResourceResults
	}{
		{"Nil", nil, args{predicate: func(r *ResourceResult) bool { return true }}, ResourceResults{}},
		{"Empty", ResourceResults{}, args{predicate: func(r *ResourceResult) bool { return true }}, ResourceResults{}},
		{"All", ResourceResults{{}}, args{predicate: func(r *ResourceResult) bool { return true }}, ResourceResults{{}}},
		{"None", ResourceResults{{}}, args{predicate: func(r *ResourceResult) bool { return false }}, ResourceResults{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.r.Filter(tt.args.predicate); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ResourceResults.Filter() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResourceResults_Find(t *testing.T) {
	type args struct {
		group     string
		kind      string
		namespace string
		name      string
		phase     SyncPhase
	}
	foo := &ResourceResult{Group: "foo"}
	results := ResourceResults{
		&ResourceResult{Group: "bar"},
		foo,
	}
	tests := []struct {
		name  string
		r     ResourceResults
		args  args
		want  int
		want1 *ResourceResult
	}{
		{"TestNil", nil, args{}, 0, nil},
		{"TestNotFound", results, args{}, 0, nil},
		{"TestFound", results, args{group: "foo"}, 1, foo},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := tt.r.Find(tt.args.group, tt.args.kind, tt.args.namespace, tt.args.name, tt.args.phase)
			if got != tt.want {
				t.Errorf("ResourceResults.Find() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("ResourceResults.Find() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestResourceResults_PruningRequired(t *testing.T) {
	needsPruning := &ResourceResult{Status: ResultCodePruneSkipped}
	tests := []struct {
		name    string
		r       ResourceResults
		wantNum int
	}{
		{"TestNil", ResourceResults{}, 0},
		{"TestOne", ResourceResults{needsPruning}, 1},
		{"TestTwo", ResourceResults{needsPruning, needsPruning}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotNum := tt.r.PruningRequired(); gotNum != tt.wantNum {
				t.Errorf("ResourceResults.PruningRequired() = %v, want %v", gotNum, tt.wantNum)
			}
		})
	}
}

func TestApplicationSource_IsZero(t *testing.T) {
	tests := []struct {
		name   string
		source *ApplicationSource
		want   bool
	}{
		{"Nil", nil, true},
		{"Empty", &ApplicationSource{}, true},
		{"RepoURL", &ApplicationSource{RepoURL: "foo"}, false},
		{"Path", &ApplicationSource{Path: "foo"}, false},
		{"TargetRevision", &ApplicationSource{TargetRevision: "foo"}, false},
		{"Helm", &ApplicationSource{Helm: &ApplicationSourceHelm{ReleaseName: "foo"}}, false},
		{"Kustomize", &ApplicationSource{Kustomize: &ApplicationSourceKustomize{Images: KustomizeImages{""}}}, false},
		{"Helm", &ApplicationSource{Ksonnet: &ApplicationSourceKsonnet{Environment: "foo"}}, false},
		{"Directory", &ApplicationSource{Directory: &ApplicationSourceDirectory{Recurse: true}}, false},
		{"Plugin", &ApplicationSource{Plugin: &ApplicationSourcePlugin{Name: "foo"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.source.IsZero())
		})
	}
}

func TestApplicationSourceHelm_AddParameter(t *testing.T) {
	src := ApplicationSourceHelm{}
	t.Run("Add", func(t *testing.T) {
		src.AddParameter(HelmParameter{Value: "bar"})
		assert.ElementsMatch(t, []HelmParameter{{Value: "bar"}}, src.Parameters)

	})
	t.Run("Replace", func(t *testing.T) {
		src.AddParameter(HelmParameter{Value: "baz"})
		assert.ElementsMatch(t, []HelmParameter{{Value: "baz"}}, src.Parameters)
	})
}

func TestNewHelmParameter(t *testing.T) {
	t.Run("Invalid", func(t *testing.T) {
		_, err := NewHelmParameter("garbage", false)
		assert.EqualError(t, err, "Expected helm parameter of the form: param=value. Received: garbage")
	})
	t.Run("NonString", func(t *testing.T) {
		p, err := NewHelmParameter("foo=bar", false)
		assert.NoError(t, err)
		assert.Equal(t, &HelmParameter{Name: "foo", Value: "bar"}, p)
	})
	t.Run("String", func(t *testing.T) {
		p, err := NewHelmParameter("foo=bar", true)
		assert.NoError(t, err)
		assert.Equal(t, &HelmParameter{Name: "foo", Value: "bar", ForceString: true}, p)
	})
}

func TestApplicationSourceHelm_IsZero(t *testing.T) {
	tests := []struct {
		name   string
		source *ApplicationSourceHelm
		want   bool
	}{
		{"Nil", nil, true},
		{"Empty", &ApplicationSourceHelm{}, true},
		{"ValueFiles", &ApplicationSourceHelm{ValueFiles: []string{""}}, false},
		{"Parameters", &ApplicationSourceHelm{Parameters: []HelmParameter{{}}}, false},
		{"ReleaseName", &ApplicationSourceHelm{ReleaseName: "foa"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.source.IsZero())
		})
	}
}

func TestApplicationSourceKustomize_IsZero(t *testing.T) {
	tests := []struct {
		name   string
		source *ApplicationSourceKustomize
		want   bool
	}{
		{"Nil", nil, true},
		{"Empty", &ApplicationSourceKustomize{}, true},
		{"NamePrefix", &ApplicationSourceKustomize{NamePrefix: "foo"}, false},
		{"Images", &ApplicationSourceKustomize{Images: []KustomizeImage{""}}, false},
		{"CommonLabels", &ApplicationSourceKustomize{CommonLabels: map[string]string{"": ""}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.source.IsZero())
		})
	}
}

func TestApplicationSourceJsonnet_IsZero(t *testing.T) {
	tests := []struct {
		name   string
		source *ApplicationSourceJsonnet
		want   bool
	}{
		{"Nil", nil, true},
		{"Empty", &ApplicationSourceJsonnet{}, true},
		{"ExtVars", &ApplicationSourceJsonnet{ExtVars: []JsonnetVar{{}}}, false},
		{"TLAs", &ApplicationSourceJsonnet{TLAs: []JsonnetVar{{}}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.source.IsZero())
		})
	}
}

func TestApplicationSourceKsonnet_IsZero(t *testing.T) {
	tests := []struct {
		name   string
		source *ApplicationSourceKsonnet
		want   bool
	}{
		{"Nil", nil, true},
		{"Empty", &ApplicationSourceKsonnet{}, true},
		{"Environment", &ApplicationSourceKsonnet{Environment: "foo"}, false},
		{"Parameters", &ApplicationSourceKsonnet{Parameters: []KsonnetParameter{{}}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.source.IsZero())
		})
	}
}

func TestApplicationSourceDirectory_IsZero(t *testing.T) {
	tests := []struct {
		name   string
		source *ApplicationSourceDirectory
		want   bool
	}{
		{"Nil", nil, true},
		{"Empty", &ApplicationSourceDirectory{}, true},
		{"Recurse", &ApplicationSourceDirectory{Recurse: true}, false},
		{"Jsonnet", &ApplicationSourceDirectory{Jsonnet: ApplicationSourceJsonnet{ExtVars: []JsonnetVar{{}}}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.source.IsZero())
		})
	}
}

func TestApplicationSourcePlugin_IsZero(t *testing.T) {

	tests := []struct {
		name   string
		source *ApplicationSourcePlugin
		want   bool
	}{
		{"Nil", nil, true},
		{"Empty", &ApplicationSourcePlugin{}, true},
		{"Name", &ApplicationSourcePlugin{Name: "foo"}, false},
		{"Env", &ApplicationSourcePlugin{Env: Env{{}}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.source.IsZero())
		})
	}
}

func TestEnvEntry_IsZero(t *testing.T) {
	tests := []struct {
		name string
		env  *EnvEntry
		want bool
	}{
		{"Nil", nil, true},
		{"Empty", &EnvEntry{}, true},
		{"Name", &EnvEntry{Name: "FOO"}, false},
		{"Value", &EnvEntry{Value: "foo"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.env.IsZero())
		})
	}
}

func TestEnv_IsZero(t *testing.T) {
	tests := []struct {
		name string
		e    Env
		want bool
	}{
		{"Empty", Env{}, true},
		{"One", Env{{}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.e.IsZero())
		})
	}
}

func TestEnv_Environ(t *testing.T) {
	tests := []struct {
		name string
		e    Env
		want []string
	}{
		{"Nil", nil, nil},
		{"Env", Env{{}}, nil},
		{"One", Env{{"FOO", "bar"}}, []string{"FOO=bar"}},
		{"Two", Env{{"FOO", "bar"}, {"FOO", "bar"}}, []string{"FOO=bar", "FOO=bar"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.e.Environ())
		})
	}
}

func TestKustomizeImage_Match(t *testing.T) {
	// no pefix
	assert.False(t, KustomizeImage("foo=1").Match("bar=1"))
	// mismatched delimiter
	assert.False(t, KustomizeImage("foo=1").Match("bar:1"))
	assert.False(t, KustomizeImage("foo:1").Match("bar=1"))
	// matches
	assert.True(t, KustomizeImage("foo=1").Match("foo=2"))
	assert.True(t, KustomizeImage("foo:1").Match("foo:2"))
	assert.True(t, KustomizeImage("foo@1").Match("foo@2"))
}

func TestApplicationSourceKustomize_MergeImage(t *testing.T) {
	t.Run("Add", func(t *testing.T) {
		k := ApplicationSourceKustomize{Images: KustomizeImages{}}
		k.MergeImage("foo=1")
		assert.Equal(t, KustomizeImages{"foo=1"}, k.Images)
	})
	t.Run("Replace", func(t *testing.T) {
		k := ApplicationSourceKustomize{Images: KustomizeImages{"foo=1"}}
		k.MergeImage("foo=2")
		assert.Equal(t, KustomizeImages{"foo=2"}, k.Images)
	})
}

func TestProjectMaintenance_AddWindow(t *testing.T) {
	proj := newTestProjectWithMaintenance(true)
	tests := []struct {
		name string
		p    *AppProject
		s    string
		d    string
		a    []string
		n    []string
		c    []string
		want string
	}{
		{"MissingConfig", proj, "", "", []string{}, []string{}, []string{}, "error"},
		{"BadSchedule", proj, "* * *", "1h", []string{"app1"}, []string{}, []string{}, "error"},
		{"BadDuration", proj, "* * * * *", "11", []string{"app1"}, []string{}, []string{}, "error"},
		{"WorkingApplication", proj, "1 * * * *", "1h", []string{"app1"}, []string{}, []string{}, "noError"},
		{"WorkingNamespace", proj, "2 * * * *", "1h", []string{}, []string{"prod"}, []string{}, "noError"},
		{"WorkingCluster", proj, "3 * * * *", "1h", []string{}, []string{}, []string{"cluster"}, "noError"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.p.Spec.Maintenance.AddWindow(tt.s, tt.d, tt.a, tt.n, tt.c)
			switch tt.want {
			case "error":
				assert.Error(t, tt.p.ValidateProject())
				assert.NoError(t, tt.p.Spec.Maintenance.DeleteWindow(tt.s, tt.d))
			case "noError":
				assert.NoError(t, tt.p.ValidateProject())
				assert.NoError(t, tt.p.Spec.Maintenance.DeleteWindow(tt.s, tt.d))
			}
		})

	}
}

func TestProjectMaintenance_DeleteWindow(t *testing.T) {
	proj := newTestProjectWithMaintenance(true)
	window1 := &ProjectMaintenanceWindow{Schedule: "* * * * *", Duration: "1h"}
	proj.Spec.Maintenance.Windows = append(proj.Spec.Maintenance.Windows, window1)
	window2 := &ProjectMaintenanceWindow{Schedule: "1 * * * *", Duration: "2h"}
	proj.Spec.Maintenance.Windows = append(proj.Spec.Maintenance.Windows, window2)
	t.Run("CannotFind", func(t *testing.T) {
		err := proj.Spec.Maintenance.DeleteWindow("* * * *", "1h")
		assert.Error(t, err)
		assert.Equal(t, len(proj.Spec.Maintenance.Windows), 2)
	})
	t.Run("Delete", func(t *testing.T) {
		err := proj.Spec.Maintenance.DeleteWindow("* * * * *", "1h")
		assert.NoError(t, err)
		assert.Equal(t, len(proj.Spec.Maintenance.Windows), 1)
	})
}

func TestProjectMaintenance_HasWindows(t *testing.T) {
	t.Run("True", func(t *testing.T) {
		proj := newTestProjectWithMaintenance(true)
		window := &ProjectMaintenanceWindow{Schedule: "* * * * *", Duration: "1h"}
		proj.Spec.Maintenance.Windows = append(proj.Spec.Maintenance.Windows, window)
		assert.True(t, proj.Spec.Maintenance.HasWindows())
	})
	t.Run("False", func(t *testing.T) {
		proj := newTestProjectWithMaintenance(true)
		assert.False(t, proj.Spec.Maintenance.HasWindows())
	})
}

func TestProjectMaintenance_ActiveWindows(t *testing.T) {
	proj := newTestProjectWithMaintenance(false)
	window := &ProjectMaintenanceWindow{Schedule: "* * * * *", Duration: "1h"}
	proj.Spec.Maintenance.Windows = append(proj.Spec.Maintenance.Windows, window)
	t.Run("SingleActive", func(t *testing.T) {
		windows := proj.Spec.Maintenance.ActiveWindows()
		assert.Equal(t, 1, len(windows))
	})
	t.Run("MultipleActive", func(t *testing.T) {
		window2 := &ProjectMaintenanceWindow{Schedule: "* * * * *", Duration: "2h"}
		proj.Spec.Maintenance.Windows = append(proj.Spec.Maintenance.Windows, window2)
		assert.Equal(t, 2, len(proj.Spec.Maintenance.ActiveWindows()))
	})
	t.Run("None", func(t *testing.T) {
		proj.Spec.Maintenance.Windows = ProjectMaintenanceWindows{}
		assert.Equal(t, 0, len(proj.Spec.Maintenance.ActiveWindows()))
	})

}

func TestProjectMaintenanceWindows_Match(t *testing.T) {
	proj := newTestProjectWithMaintenance(false)
	window := &ProjectMaintenanceWindow{Schedule: "* * * * *", Duration: "1h"}
	proj.Spec.Maintenance.Windows = append(proj.Spec.Maintenance.Windows, window)
	app := newTestApp()
	t.Run("MatchNamespace", func(t *testing.T) {
		proj.Spec.Maintenance.Windows[0].Namespaces = []string{"default"}
		match, windows := proj.Spec.Maintenance.Windows.Match(app)
		assert.True(t, match)
		assert.Equal(t, 1, len(windows))
		proj.Spec.Maintenance.Windows[0].Namespaces = nil
	})
	t.Run("MatchCluster", func(t *testing.T) {
		proj.Spec.Maintenance.Windows[0].Clusters = []string{"cluster1"}
		match, windows := proj.Spec.Maintenance.Windows.Match(app)
		assert.True(t, match)
		assert.Equal(t, 1, len(windows))
		proj.Spec.Maintenance.Windows[0].Clusters = nil
	})
	t.Run("MatchAppName", func(t *testing.T) {
		proj.Spec.Maintenance.Windows[0].Applications = []string{"test-app"}
		match, windows := proj.Spec.Maintenance.Windows.Match(app)
		assert.True(t, match)
		assert.Equal(t, 1, len(windows))
		proj.Spec.Maintenance.Windows[0].Applications = nil
	})
	t.Run("MatchWildcardAppName", func(t *testing.T) {
		proj.Spec.Maintenance.Windows[0].Applications = []string{"test-*"}
		match, windows := proj.Spec.Maintenance.Windows.Match(app)
		assert.True(t, match)
		assert.Equal(t, 1, len(windows))
		proj.Spec.Maintenance.Windows[0].Applications = nil
	})
	t.Run("NoMatch", func(t *testing.T) {
		match, windows := proj.Spec.Maintenance.Windows.Match(app)
		assert.False(t, match)
		assert.Equal(t, 0, len(windows))
	})
}

func TestProjectMaintenanceWindows_Active_Match(t *testing.T) {
	proj := newTestProjectWithMaintenance(false)
	window := &ProjectMaintenanceWindow{Schedule: "* * * * *", Duration: "1h"}
	proj.Spec.Maintenance.Windows = append(proj.Spec.Maintenance.Windows, window)
	app := newTestApp()
	t.Run("MatchNamespace", func(t *testing.T) {
		proj.Spec.Maintenance.Windows[0].Namespaces = []string{"default"}
		active := proj.Spec.Maintenance.ActiveWindows()
		match, windows := active.Match(app)
		assert.True(t, match)
		assert.Equal(t, 1, len(windows))
		proj.Spec.Maintenance.Windows[0].Namespaces = nil
	})
}

func TestProjectMaintenance_IsEnabled(t *testing.T) {
	t.Run("True", func(t *testing.T) {
		proj := newTestProjectWithMaintenance(true)
		assert.True(t, proj.Spec.Maintenance.IsEnabled())
	})
	t.Run("False", func(t *testing.T) {
		proj := newTestProjectWithMaintenance(false)
		proj.Spec.Maintenance.Enabled = false
		assert.False(t, proj.Spec.Maintenance.IsEnabled())
	})
}

func TestProjectMaintenanceWindow_Update(t *testing.T) {
	e := ProjectMaintenanceWindow{Schedule: "* * * * *", Duration: "1h", Applications: []string{"app1"}}
	t.Run("AddApplication", func(t *testing.T) {
		err := e.Update([]string{"app1", "app2"}, []string{}, []string{})
		assert.NoError(t, err)
		assert.Equal(t, []string{"app1", "app2"}, e.Applications)
	})
	t.Run("AddNamespace", func(t *testing.T) {
		err := e.Update([]string{}, []string{"namespace1"}, []string{})
		assert.NoError(t, err)
		assert.Equal(t, []string{"namespace1"}, e.Namespaces)
	})
	t.Run("AddCluster", func(t *testing.T) {
		err := e.Update([]string{}, []string{}, []string{"cluster1"})
		assert.NoError(t, err)
		assert.Equal(t, []string{"cluster1"}, e.Clusters)
	})
	t.Run("MissingConfig", func(t *testing.T) {
		err := e.Update([]string{}, []string{}, []string{})
		assert.EqualError(t, err, "cannot update window: require one of application, namespace or cluster")
	})
}

func newTestProjectWithMaintenance(w bool) *AppProject {
	p := &AppProject{
		ObjectMeta: v1.ObjectMeta{Name: "my-proj"},
		Spec:       AppProjectSpec{Maintenance: &ProjectMaintenance{Enabled: true}}}
	if w {
		p.Spec.Maintenance.Windows = ProjectMaintenanceWindows{}
	}
	return p
}

func newTestApp() *Application {
	a := &Application{
		ObjectMeta: v1.ObjectMeta{Name: "test-app"},
		Spec: ApplicationSpec{
			Destination: ApplicationDestination{
				Namespace: "default",
				Server:    "cluster1",
			},
		},
	}
	return a
}

func TestAppProjectSpec_AddMaintenance(t *testing.T) {
	proj := newTestProject()
	t.Run("AddMaintenance", func(t *testing.T) {
		proj.Spec.AddMaintenance()
		assert.NotNil(t, proj.Spec.Maintenance)
	})
}

func TestProjectMaintenanceWindow_Active(t *testing.T) {
	window := &ProjectMaintenanceWindow{Schedule: "* * * * *", Duration: "1h"}
	t.Run("ActiveWindow", func(t *testing.T) {
		window.Active()
		assert.True(t, window.Active())
	})
}

func TestRevisionHistories_Trunc(t *testing.T) {
	// always match - but limit is >= size, -> unchanged
	assert.Len(t, RevisionHistories{{Revision: "my-revision"}, {}}.Trunc(func(h RevisionHistory) bool { return true }, 2), 2)
	// match one element, no need to trunc -> unchanged
	assert.Len(t, RevisionHistories{{Revision: "my-revision"}, {}}.Trunc(func(h RevisionHistory) bool { return h.Revision == "my-revision" }, 1), 2)
	// match first element, need to trunc
	assert.Equal(t, RevisionHistories{{}, {}}, RevisionHistories{{Revision: "my-revision"}, {}, {}}.Trunc(func(h RevisionHistory) bool { return h.Revision == "my-revision" }, 1))
	// never match, but limit < size -> change to limit
	assert.Len(t, RevisionHistories{{}, {}}.Trunc(func(h RevisionHistory) bool { return false }, 1), 1)
}

func TestRevisionHistories_Map(t *testing.T) {
	assert.Equal(t, RevisionHistories{{Revision: "my-revision"}}, RevisionHistories{{}}.Map(func(h RevisionHistory) RevisionHistory {
		return RevisionHistory{Revision: "my-revision"}
	}))
}

func TestRevisionHistoryStatus_IsZero(t *testing.T) {
	assert.False(t, RevisionHistoryStatus{}.IsZero())
}

func TestApplicationSpec_GetRevisionHistoryLimit(t *testing.T) {
	// default
	assert.Equal(t, 10, ApplicationSpec{}.GetRevisionHistoryLimit())
	// configured
	n := int64(11)
	assert.Equal(t, 11, ApplicationSpec{RevisionHistoryLimit: &n}.GetRevisionHistoryLimit())
}
