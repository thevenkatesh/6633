package kube

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os/exec"
	"regexp"
	"strings"

	argoexec "github.com/argoproj/pkg/exec"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	kubeerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/utils/pointer"

	"github.com/argoproj/argo-cd/util"
	"github.com/argoproj/argo-cd/util/diff"
	executil "github.com/argoproj/argo-cd/util/exec"
	"github.com/argoproj/argo-cd/util/tracing"
)

type Kubectl interface {
	ApplyResource(config *rest.Config, obj *unstructured.Unstructured, namespace string, dryRun, force, validate bool) (string, error)
	ConvertToVersion(obj *unstructured.Unstructured, group, version string) (*unstructured.Unstructured, error)
	DeleteResource(config *rest.Config, gvk schema.GroupVersionKind, name string, namespace string, forceDelete bool) error
	GetResource(config *rest.Config, gvk schema.GroupVersionKind, name string, namespace string) (*unstructured.Unstructured, error)
	PatchResource(config *rest.Config, gvk schema.GroupVersionKind, name string, namespace string, patchType types.PatchType, patchBytes []byte) (*unstructured.Unstructured, error)
	GetAPIResources(config *rest.Config, resourceFilter ResourceFilter) ([]APIResourceInfo, error)
	GetServerVersion(config *rest.Config) (string, error)
	SetOnKubectlRun(onKubectlRun func(command string) (util.Closer, error))
}

type KubectlCmd struct {
	OnKubectlRun func(command string) (util.Closer, error)
}

type APIResourceInfo struct {
	GroupKind schema.GroupKind
	Meta      metav1.APIResource
	Interface dynamic.ResourceInterface
}

type filterFunc func(apiResource *metav1.APIResource) bool

func filterAPIResources(config *rest.Config, resourceFilter ResourceFilter, filter filterFunc, namespace string) ([]APIResourceInfo, error) {
	dynamicIf, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	disco, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return nil, err
	}

	serverResources, err := disco.ServerPreferredResources()
	if err != nil {
		if len(serverResources) == 0 {
			return nil, err
		}
		log.Warnf("Partial success when performing preferred resource discovery: %v", err)
	}
	apiResIfs := make([]APIResourceInfo, 0)
	for _, apiResourcesList := range serverResources {
		gv, err := schema.ParseGroupVersion(apiResourcesList.GroupVersion)
		if err != nil {
			gv = schema.GroupVersion{}
		}
		for _, apiResource := range apiResourcesList.APIResources {

			if resourceFilter.IsExcludedResource(gv.Group, apiResource.Kind, config.Host) {
				continue
			}

			if filter(&apiResource) {
				resource := ToGroupVersionResource(apiResourcesList.GroupVersion, &apiResource)
				resourceIf := ToResourceInterface(dynamicIf, &apiResource, resource, namespace)
				gv, err := schema.ParseGroupVersion(apiResourcesList.GroupVersion)
				if err != nil {
					return nil, err
				}
				apiResIf := APIResourceInfo{
					GroupKind: schema.GroupKind{Group: gv.Group, Kind: apiResource.Kind},
					Meta:      apiResource,
					Interface: resourceIf,
				}
				apiResIfs = append(apiResIfs, apiResIf)
			}
		}
	}
	return apiResIfs, nil
}

// isSupportedVerb returns whether or not a APIResource supports a specific verb
func isSupportedVerb(apiResource *metav1.APIResource, verb string) bool {
	for _, v := range apiResource.Verbs {
		if v == verb {
			return true
		}
	}
	return false
}

func (k *KubectlCmd) GetAPIResources(config *rest.Config, resourceFilter ResourceFilter) ([]APIResourceInfo, error) {
	span := tracing.StartSpan("GetAPIResources")
	defer span.Finish()
	apiResIfs, err := filterAPIResources(config, resourceFilter, func(apiResource *metav1.APIResource) bool {
		return isSupportedVerb(apiResource, listVerb) && isSupportedVerb(apiResource, watchVerb)
	}, "")
	if err != nil {
		return nil, err
	}
	return apiResIfs, err
}

// GetResource returns resource
func (k *KubectlCmd) GetResource(config *rest.Config, gvk schema.GroupVersionKind, name string, namespace string) (*unstructured.Unstructured, error) {
	span := tracing.StartSpan("GetResource")
	span.SetBaggageItem("kind", gvk.Kind)
	span.SetBaggageItem("name", name)
	defer span.Finish()
	dynamicIf, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	disco, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return nil, err
	}
	apiResource, err := ServerResourceForGroupVersionKind(disco, gvk)
	if err != nil {
		return nil, err
	}
	resource := gvk.GroupVersion().WithResource(apiResource.Name)
	resourceIf := ToResourceInterface(dynamicIf, apiResource, resource, namespace)
	return resourceIf.Get(name, metav1.GetOptions{})
}

func getResourceIf(config *rest.Config, gvk schema.GroupVersionKind, namespace string) (dynamic.ResourceInterface, error) {
	dynamicIf, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	disco, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return nil, err
	}
	apiResource, err := ServerResourceForGroupVersionKind(disco, gvk)
	if err != nil {
		return nil, err
	}
	return ToResourceInterface(dynamicIf, apiResource, gvk.GroupVersion().
		WithResource(apiResource.Name), namespace), nil
}

// PatchResource patches resource
func (k *KubectlCmd) PatchResource(config *rest.Config, gvk schema.GroupVersionKind, name string, namespace string, patchType types.PatchType, patchBytes []byte) (*unstructured.Unstructured, error) {
	span := tracing.StartSpan("PatchResource")
	span.SetBaggageItem("kind", gvk.Kind)
	span.SetBaggageItem("name", name)
	defer span.Finish()
	resourceIf, err := getResourceIf(config, gvk, namespace)
	if err != nil {
		return nil, err
	}
	return resourceIf.Patch(name, patchType, patchBytes, metav1.PatchOptions{})
}

// DeleteResource deletes resource
func (k *KubectlCmd) DeleteResource(config *rest.Config, gvk schema.GroupVersionKind, name string, namespace string, forceDelete bool) error {
	span := tracing.StartSpan("DeleteResource")
	span.SetBaggageItem("kind", gvk.Kind)
	span.SetBaggageItem("name", name)
	defer span.Finish()
	resourceIf, err := getResourceIf(config, gvk, namespace)
	if err != nil {
		return err
	}
	propagationPolicy := metav1.DeletePropagationForeground
	deleteOptions := &metav1.DeleteOptions{PropagationPolicy: &propagationPolicy}
	if forceDelete {
		propagationPolicy = metav1.DeletePropagationBackground
		zeroGracePeriod := int64(0)
		deleteOptions.GracePeriodSeconds = &zeroGracePeriod
	}
	return resourceIf.Delete(name, deleteOptions)
}

// ApplyResource performs an apply of a unstructured resource
func (k *KubectlCmd) ApplyResource(config *rest.Config, obj *unstructured.Unstructured, namespace string, dryRun, force, validate bool) (string, error) {
	span := tracing.StartSpan("ApplyResource")
	span.SetBaggageItem("kind", obj.GetKind())
	span.SetBaggageItem("name", obj.GetName())
	defer span.Finish()
	log.Infof("Applying resource %s/%s in cluster: %s, namespace: %s", obj.GetKind(), obj.GetName(), config.Host, namespace)

	resourceIf, err := getResourceIf(config, obj.GroupVersionKind(), namespace)
	if err != nil {
		return "", err
	}
	objBytes, err := yaml.Marshal(obj)
	if err != nil {
		return "", err
	}

	_, err = resourceIf.Get(obj.GetName(), metav1.GetOptions{})

	// TODO validate!

	if kubeerrors.IsNotFound(err) {
		options := metav1.CreateOptions{}
		if dryRun {
			options.DryRun = append(options.DryRun, "All")
		}
		out, err := resourceIf.Create(obj, options)
		if err != nil {
			return "", err
		}
		outBytes, err := yaml.Marshal(out)
		if err != nil {
			return "", err
		}
		return string(outBytes), nil
	} else {
		options := metav1.PatchOptions{}
		if dryRun {
			options.DryRun = append(options.DryRun, "All")
		}
		if force {
			options.Force = pointer.BoolPtr(force)
		}
		out, err := resourceIf.Patch(obj.GetName(), types.StrategicMergePatchType, objBytes, options)
		if err != nil {
			return "", err
		}
		outBytes, err := yaml.Marshal(out)
		if err != nil {
			return "", err
		}
		return string(outBytes), nil
	}
}

func convertKubectlError(err error) error {
	errorStr := err.Error()
	if cmdErr, ok := err.(*argoexec.CmdError); ok {
		parts := []string{fmt.Sprintf("kubectl failed %s", cmdErr.Cause.Error())}
		if cmdErr.Stderr != "" {
			parts = append(parts, cleanKubectlOutput(cmdErr.Stderr))
		}
		errorStr = strings.Join(parts, ": ")
	}
	return fmt.Errorf(errorStr)
}

func (k *KubectlCmd) processKubectlRun(args []string) (util.Closer, error) {
	if k.OnKubectlRun != nil {
		cmd := "unknown"
		if len(args) > 0 {
			cmd = args[0]
		}
		return k.OnKubectlRun(cmd)
	}
	return util.NewCloser(func() error {
		return nil
		// do nothing
	}), nil
}

func (k *KubectlCmd) runKubectl(kubeconfigPath string, namespace string, args []string, manifestBytes []byte, dryRun bool) (string, error) {
	closer, err := k.processKubectlRun(args)
	if err != nil {
		return "", err
	}
	defer util.Close(closer)

	cmdArgs := append([]string{"--kubeconfig", kubeconfigPath, "-f", "-"}, args...)
	if namespace != "" {
		cmdArgs = append(cmdArgs, "-n", namespace)
	}
	if dryRun {
		cmdArgs = append(cmdArgs, "--dry-run")
	}
	cmd := exec.Command("kubectl", cmdArgs...)
	if log.IsLevelEnabled(log.DebugLevel) {
		var obj unstructured.Unstructured
		err := json.Unmarshal(manifestBytes, &obj)
		if err != nil {
			return "", err
		}
		redacted, _, err := diff.HideSecretData(&obj, nil)
		if err != nil {
			return "", err
		}
		redactedBytes, err := json.Marshal(redacted)
		if err != nil {
			return "", err
		}
		log.Debug(string(redactedBytes))
	}
	cmd.Stdin = bytes.NewReader(manifestBytes)
	out, err := executil.Run(cmd)
	if err != nil {
		return "", convertKubectlError(err)
	}
	return out, nil
}

func Version() (string, error) {
	span := tracing.StartSpan("Version")
	defer span.Finish()
	cmd := exec.Command("kubectl", "version", "--client")
	out, err := executil.Run(cmd)
	if err != nil {
		return "", fmt.Errorf("could not get kubectl version: %s", err)
	}
	re := regexp.MustCompile(`GitVersion:"([a-zA-Z0-9\.]+)"`)
	matches := re.FindStringSubmatch(out)
	if len(matches) != 2 {
		return "", errors.New("could not get kubectl version")
	}
	version := matches[1]
	if version[0] != 'v' {
		version = "v" + version
	}
	return strings.TrimSpace(version), nil
}

// ConvertToVersion converts an unstructured object into the specified group/version
func (k *KubectlCmd) ConvertToVersion(obj *unstructured.Unstructured, group string, version string) (*unstructured.Unstructured, error) {
	span := tracing.StartSpan("ConvertToVersion")
	from := obj.GroupVersionKind().GroupVersion()
	span.SetBaggageItem("from", from.String())
	span.SetBaggageItem("to", schema.GroupVersion{Group: group, Version: version}.String())
	defer span.Finish()
	if from.Group == group && from.Version == version {
		return obj.DeepCopy(), nil
	}
	return convertToVersionWithScheme(obj, group, version)
}

func (k *KubectlCmd) GetServerVersion(config *rest.Config) (string, error) {
	span := tracing.StartSpan("GetServerVersion")
	defer span.Finish()
	client, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return "", err
	}
	v, err := client.ServerVersion()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%s", v.Major, v.Minor), nil
}

func (k *KubectlCmd) SetOnKubectlRun(onKubectlRun func(command string) (util.Closer, error)) {
	k.OnKubectlRun = onKubectlRun
}
