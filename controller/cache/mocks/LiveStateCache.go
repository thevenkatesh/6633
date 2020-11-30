// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import (
	context "context"

	cache "github.com/argoproj/gitops-engine/pkg/cache"

	kube "github.com/argoproj/gitops-engine/pkg/utils/kube"

	mock "github.com/stretchr/testify/mock"

	schema "k8s.io/apimachinery/pkg/runtime/schema"

	unstructured "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/argoproj/argo-cd/pkg/apis/application/v1alpha1"
)

// LiveStateCache is an autogenerated mock type for the LiveStateCache type
type LiveStateCache struct {
	mock.Mock
}

// GetClusterCache provides a mock function with given fields: server
func (_m *LiveStateCache) GetClusterCache(server string, name string) (cache.ClusterCache, error) {
	ret := _m.Called(server, name)

	var r0 cache.ClusterCache
	if rf, ok := ret.Get(0).(func(string, string) cache.ClusterCache); ok {
		r0 = rf(server, name)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(cache.ClusterCache)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string) error); ok {
		r1 = rf(server, name)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetClustersInfo provides a mock function with given fields:
func (_m *LiveStateCache) GetClustersInfo() []cache.ClusterInfo {
	ret := _m.Called()

	var r0 []cache.ClusterInfo
	if rf, ok := ret.Get(0).(func() []cache.ClusterInfo); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]cache.ClusterInfo)
		}
	}

	return r0
}

// GetManagedLiveObjs provides a mock function with given fields: a, targetObjs
func (_m *LiveStateCache) GetManagedLiveObjs(a *v1alpha1.Application, targetObjs []*unstructured.Unstructured) (map[kube.ResourceKey]*unstructured.Unstructured, error) {
	ret := _m.Called(a, targetObjs)

	var r0 map[kube.ResourceKey]*unstructured.Unstructured
	if rf, ok := ret.Get(0).(func(*v1alpha1.Application, []*unstructured.Unstructured) map[kube.ResourceKey]*unstructured.Unstructured); ok {
		r0 = rf(a, targetObjs)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[kube.ResourceKey]*unstructured.Unstructured)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*v1alpha1.Application, []*unstructured.Unstructured) error); ok {
		r1 = rf(a, targetObjs)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetNamespaceTopLevelResources provides a mock function with given fields: server, namespace
func (_m *LiveStateCache) GetNamespaceTopLevelResources(server string, name string, namespace string) (map[kube.ResourceKey]v1alpha1.ResourceNode, error) {
	ret := _m.Called(server, name, namespace)

	var r0 map[kube.ResourceKey]v1alpha1.ResourceNode
	if rf, ok := ret.Get(0).(func(string, string, string) map[kube.ResourceKey]v1alpha1.ResourceNode); ok {
		r0 = rf(server, name, namespace)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[kube.ResourceKey]v1alpha1.ResourceNode)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string, string) error); ok {
		r1 = rf(server, name, namespace)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetVersionsInfo provides a mock function with given fields: serverURL
func (_m *LiveStateCache) GetVersionsInfo(serverURL string, name string) (string, []v1.APIGroup, error) {
	ret := _m.Called(serverURL, name)

	var r0 string
	if rf, ok := ret.Get(0).(func(string, string) string); ok {
		r0 = rf(serverURL, name)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 []v1.APIGroup
	if rf, ok := ret.Get(1).(func(string, string) []v1.APIGroup); ok {
		r1 = rf(serverURL, name)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).([]v1.APIGroup)
		}
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(string, string) error); ok {
		r2 = rf(serverURL, name)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// Init provides a mock function with given fields:
func (_m *LiveStateCache) Init() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// IsNamespaced provides a mock function with given fields: server, gk
func (_m *LiveStateCache) IsNamespaced(server string, name string, gk schema.GroupKind) (bool, error) {
	ret := _m.Called(server, name, gk)

	var r0 bool
	if rf, ok := ret.Get(0).(func(string, string, schema.GroupKind) bool); ok {
		r0 = rf(server, name, gk)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string, schema.GroupKind) error); ok {
		r1 = rf(server, name, gk)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IterateHierarchy provides a mock function with given fields: server, key, action
func (_m *LiveStateCache) IterateHierarchy(server string, name string, key kube.ResourceKey, action func(v1alpha1.ResourceNode, string)) error {
	ret := _m.Called(server, key, action)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, kube.ResourceKey, func(v1alpha1.ResourceNode, string)) error); ok {
		r0 = rf(server, key, action)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Run provides a mock function with given fields: ctx
func (_m *LiveStateCache) Run(ctx context.Context) error {
	ret := _m.Called(ctx)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context) error); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
