package cache

import (
	"fmt"
	"regexp"

	"github.com/argoproj/gitops-engine/pkg/utils/kube"
	"github.com/argoproj/gitops-engine/pkg/utils/text"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	k8snode "k8s.io/kubernetes/pkg/util/node"

	"github.com/argoproj/argo-cd/pkg/apis/application/v1alpha1"
	"github.com/argoproj/argo-cd/util/resource"
)

func populateNodeInfo(un *unstructured.Unstructured, res *ResourceInfo) {
	gvk := un.GroupVersionKind()
	revision := resource.GetRevision(un)
	if revision > 0 {
		res.Info = append(res.Info, v1alpha1.InfoItem{Name: "Revision", Value: fmt.Sprintf("Rev:%v", revision)})
	}

	switch gvk.Group {
	case "":
		switch gvk.Kind {
		case kube.PodKind:
			populatePodInfo(un, res)
			return
		case kube.ServiceKind:
			populateServiceInfo(un, res)
			return
		}
	case "extensions", "networking.k8s.io":
		switch gvk.Kind {
		case kube.IngressKind:
			populateIngressInfo(un, res)
			return
		}
	case "getambassador.io":
		switch gvk.Kind {
		case "Mapping":
			populateAmbassador(un, res)
			return
		}
	}
}

func getIngress(un *unstructured.Unstructured) []v1.LoadBalancerIngress {
	// check for external-dns hostname
	hostname, ok, err := unstructured.NestedString(un.Object, "metadata", "annotations", "external-dns.alpha.kubernetes.io/hostname")
	if !ok || err != nil || hostname == "" {
		ingress, ok, err := unstructured.NestedSlice(un.Object, "status", "loadBalancer", "ingress")
		if !ok || err != nil {
			return nil
		}
		res := make([]v1.LoadBalancerIngress, 0)
		for _, item := range ingress {
			if lbIngress, ok := item.(map[string]interface{}); ok {
				if hostname := lbIngress["hostname"]; hostname != nil {
					res = append(res, v1.LoadBalancerIngress{Hostname: fmt.Sprintf("%s", hostname)})
				} else if ip := lbIngress["ip"]; ip != nil {
					res = append(res, v1.LoadBalancerIngress{IP: fmt.Sprintf("%s", ip)})
				}
			}
		}
		return res
	}
	return []v1.LoadBalancerIngress{{Hostname: hostname}}
}

func populateServiceInfo(un *unstructured.Unstructured, res *ResourceInfo) {
	targetLabels, _, _ := unstructured.NestedStringMap(un.Object, "spec", "selector")
	ingress := make([]v1.LoadBalancerIngress, 0)
	res.NetworkingInfo = &v1alpha1.ResourceNetworkingInfo{TargetLabels: targetLabels}
	if serviceType, ok, err := unstructured.NestedString(un.Object, "spec", "type"); ok && err == nil && serviceType == string(v1.ServiceTypeLoadBalancer) {
		ingress = getIngress(un)
		host := text.FirstNonEmpty(ingress[0].Hostname, ingress[0].IP)

		urls := make([]string, 0)
		// process exposed ports (only 80/http or 443/https)
		if ports, ok, err := unstructured.NestedSlice(un.Object, "spec", "ports"); ok && err == nil {
			fmt.Println("In service ", un.GetName(), " in namespace ", un.GetNamespace())
			for i := range ports {
				fmt.Printf("PortSpec %+v", ports[i])
				portSpec, ok := ports[i].(map[string]interface{})
				if !ok {
					continue
				}

				stringPort := ""
				switch typedPort := portSpec["port"].(type) {
				case int64:
					stringPort = fmt.Sprintf("%d", typedPort)
				case float64:
					stringPort = fmt.Sprintf("%d", int64(typedPort))
				case string:
					stringPort = typedPort
				default:
					stringPort = fmt.Sprintf("%v", portSpec["port"])
				}
				switch stringPort {
				case "80":
					urls = append(urls, fmt.Sprintf("http://%s", host))
				case "443":
					urls = append(urls, fmt.Sprintf("https://%s", host))
				default:
					urls = append(urls, fmt.Sprintf("http://%s:%s", host, stringPort))
				}

				// port name (http or https)
				//if portSpec["name"] == "http" || portSpec["name"] == "https" {
				//	urls = append(urls, fmt.Sprintf("%s://%s:%s", portSpec["name"], host, stringPort))
				//}
			}
		}
		res.NetworkingInfo.Ingress = ingress
		res.NetworkingInfo.ExternalURLs = urls
	}
}

func populateAmbassador(un *unstructured.Unstructured, res *ResourceInfo) {
	if spec, ok, err := unstructured.NestedMap(un.Object, "spec"); ok && err == nil {
		// https://www.getambassador.io/docs/latest/topics/using/intro-mappings/#services
		var mappingExp = regexp.MustCompile(`((?P<scheme>[a-z]+)(://))?(?P<service>[a-zA-Z\-]+)(.(?P<namespace>[a-zA-Z\-]+))?(:(?P<port>[0-9]+))?`)
		match := mappingExp.FindStringSubmatch(fmt.Sprintf("%s", spec["service"]))
		result := make(map[string]string)
		for i, name := range mappingExp.SubexpNames() {
			if i != 0 && name != "" && match[i] != "" {
				result[name] = match[i]
			}
		}

		// default to object namespace
		namespace, ok := result["namespace"]
		if !ok {
			namespace = un.GetNamespace()
		}

		// full ExternalURLs is not known at this time. Will be updated on render
		networkInfo := &v1alpha1.ResourceNetworkingInfo{TargetRefs: []v1alpha1.ResourceRef{
			{Group: "",
				Kind:      kube.ServiceKind,
				Namespace: namespace,
				Name:      result["service"]}}, ExternalURLs: []string{spec["prefix"].(string)}}

		res.NetworkingInfo = networkInfo
	}
}

func populateIngressInfo(un *unstructured.Unstructured, res *ResourceInfo) {
	ingress := getIngress(un)
	targetsMap := make(map[v1alpha1.ResourceRef]bool)
	if backend, ok, err := unstructured.NestedMap(un.Object, "spec", "backend"); ok && err == nil {
		targetsMap[v1alpha1.ResourceRef{
			Group:     "",
			Kind:      kube.ServiceKind,
			Namespace: un.GetNamespace(),
			Name:      fmt.Sprintf("%s", backend["serviceName"]),
		}] = true
	}
	urlsSet := make(map[string]bool)
	if rules, ok, err := unstructured.NestedSlice(un.Object, "spec", "rules"); ok && err == nil {
		for i := range rules {
			rule, ok := rules[i].(map[string]interface{})
			if !ok {
				continue
			}
			host := rule["host"]
			if host == nil || host == "" {
				for i := range ingress {
					host = text.FirstNonEmpty(ingress[i].Hostname, ingress[i].IP)
					if host != "" {
						break
					}
				}
			}
			paths, ok, err := unstructured.NestedSlice(rule, "http", "paths")
			if !ok || err != nil {
				continue
			}
			for i := range paths {
				path, ok := paths[i].(map[string]interface{})
				if !ok {
					continue
				}

				if serviceName, ok, err := unstructured.NestedString(path, "backend", "serviceName"); ok && err == nil {
					targetsMap[v1alpha1.ResourceRef{
						Group:     "",
						Kind:      kube.ServiceKind,
						Namespace: un.GetNamespace(),
						Name:      serviceName,
					}] = true
				}

				if port, ok, err := unstructured.NestedFieldNoCopy(path, "backend", "servicePort"); ok && err == nil && host != "" && host != nil {
					stringPort := ""
					switch typedPod := port.(type) {
					case int64:
						stringPort = fmt.Sprintf("%d", typedPod)
					case float64:
						stringPort = fmt.Sprintf("%d", int64(typedPod))
					case string:
						stringPort = typedPod
					default:
						stringPort = fmt.Sprintf("%v", port)
					}

					var externalURL string
					switch stringPort {
					case "80", "http":
						externalURL = fmt.Sprintf("http://%s", host)
					case "443", "https":
						externalURL = fmt.Sprintf("https://%s", host)
					default:
						externalURL = fmt.Sprintf("http://%s:%s", host, stringPort)
					}

					subPath := ""
					if nestedPath, ok, err := unstructured.NestedString(path, "path"); ok && err == nil {
						subPath = nestedPath
					}

					externalURL += subPath
					urlsSet[externalURL] = true
				}
			}
		}
	}
	targets := make([]v1alpha1.ResourceRef, 0)
	for target := range targetsMap {
		targets = append(targets, target)
	}
	urls := make([]string, 0)
	for url := range urlsSet {
		urls = append(urls, url)
	}
	res.NetworkingInfo = &v1alpha1.ResourceNetworkingInfo{TargetRefs: targets, Ingress: ingress, ExternalURLs: urls}
}

func populatePodInfo(un *unstructured.Unstructured, res *ResourceInfo) {
	pod := v1.Pod{}
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(un.Object, &pod)
	if err != nil {
		return
	}
	restarts := 0
	totalContainers := len(pod.Spec.Containers)
	readyContainers := 0

	reason := string(pod.Status.Phase)
	if pod.Status.Reason != "" {
		reason = pod.Status.Reason
	}

	imagesSet := make(map[string]bool)
	for _, container := range pod.Spec.InitContainers {
		imagesSet[container.Image] = true
	}
	for _, container := range pod.Spec.Containers {
		imagesSet[container.Image] = true
	}

	res.Images = nil
	for image := range imagesSet {
		res.Images = append(res.Images, image)
	}

	initializing := false
	for i := range pod.Status.InitContainerStatuses {
		container := pod.Status.InitContainerStatuses[i]
		restarts += int(container.RestartCount)
		switch {
		case container.State.Terminated != nil && container.State.Terminated.ExitCode == 0:
			continue
		case container.State.Terminated != nil:
			// initialization is failed
			if len(container.State.Terminated.Reason) == 0 {
				if container.State.Terminated.Signal != 0 {
					reason = fmt.Sprintf("Init:Signal:%d", container.State.Terminated.Signal)
				} else {
					reason = fmt.Sprintf("Init:ExitCode:%d", container.State.Terminated.ExitCode)
				}
			} else {
				reason = "Init:" + container.State.Terminated.Reason
			}
			initializing = true
		case container.State.Waiting != nil && len(container.State.Waiting.Reason) > 0 && container.State.Waiting.Reason != "PodInitializing":
			reason = "Init:" + container.State.Waiting.Reason
			initializing = true
		default:
			reason = fmt.Sprintf("Init:%d/%d", i, len(pod.Spec.InitContainers))
			initializing = true
		}
		break
	}
	if !initializing {
		restarts = 0
		hasRunning := false
		for i := len(pod.Status.ContainerStatuses) - 1; i >= 0; i-- {
			container := pod.Status.ContainerStatuses[i]

			restarts += int(container.RestartCount)
			if container.State.Waiting != nil && container.State.Waiting.Reason != "" {
				reason = container.State.Waiting.Reason
			} else if container.State.Terminated != nil && container.State.Terminated.Reason != "" {
				reason = container.State.Terminated.Reason
			} else if container.State.Terminated != nil && container.State.Terminated.Reason == "" {
				if container.State.Terminated.Signal != 0 {
					reason = fmt.Sprintf("Signal:%d", container.State.Terminated.Signal)
				} else {
					reason = fmt.Sprintf("ExitCode:%d", container.State.Terminated.ExitCode)
				}
			} else if container.Ready && container.State.Running != nil {
				hasRunning = true
				readyContainers++
			}
		}

		// change pod status back to "Running" if there is at least one container still reporting as "Running" status
		if reason == "Completed" && hasRunning {
			reason = "Running"
		}
	}

	if pod.DeletionTimestamp != nil && pod.Status.Reason == k8snode.NodeUnreachablePodReason {
		reason = "Unknown"
	} else if pod.DeletionTimestamp != nil {
		reason = "Terminating"
	}

	if reason != "" {
		res.Info = append(res.Info, v1alpha1.InfoItem{Name: "Status Reason", Value: reason})
	}
	res.Info = append(res.Info, v1alpha1.InfoItem{Name: "Containers", Value: fmt.Sprintf("%d/%d", readyContainers, totalContainers)})
	res.NetworkingInfo = &v1alpha1.ResourceNetworkingInfo{Labels: un.GetLabels()}
}
