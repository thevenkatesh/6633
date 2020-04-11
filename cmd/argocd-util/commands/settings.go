package commands

import (
	"bytes"
	"context"
	syserrors "errors"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"sort"
	"strings"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/ghodss/yaml"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/argoproj/argo-cd/common"
	"github.com/argoproj/argo-cd/errors"
	"github.com/argoproj/argo-cd/pkg/apis/application/v1alpha1"
	"github.com/argoproj/argo-cd/util/argo/normalizers"
	"github.com/argoproj/argo-cd/util/cli"
	"github.com/argoproj/argo-cd/util/diff"
	"github.com/argoproj/argo-cd/util/health"
	"github.com/argoproj/argo-cd/util/lua"
	"github.com/argoproj/argo-cd/util/settings"
)

type settingsOpts struct {
	argocdCMPath        string
	argocdSecretPath    string
	loadClusterSettings bool
	clientConfig        clientcmd.ClientConfig
}

func collectLogs(callback func()) string {
	log.SetLevel(log.DebugLevel)
	out := bytes.Buffer{}
	log.SetOutput(&out)
	defer log.SetLevel(log.FatalLevel)
	callback()
	return out.String()
}

func setSettingsMeta(obj v1.Object) {
	obj.SetNamespace("default")
	labels := obj.GetLabels()
	if labels == nil {
		labels = make(map[string]string)
	}
	labels["app.kubernetes.io/part-of"] = "argocd"
	obj.SetLabels(labels)
}

func (opts *settingsOpts) createSettingsManager() (*settings.SettingsManager, error) {
	var argocdCM *corev1.ConfigMap
	if opts.argocdCMPath == "" && !opts.loadClusterSettings {
		return nil, syserrors.New("either --argocd-cm-path must be provided or --load-cluster-settings must be set to true")
	} else if opts.argocdCMPath == "" {
		realClientset, ns, err := opts.getK8sClient()
		if err != nil {
			return nil, err
		}

		argocdCM, err = realClientset.CoreV1().ConfigMaps(ns).Get(common.ArgoCDConfigMapName, v1.GetOptions{})
		if err != nil {
			return nil, err
		}
	} else {
		data, err := ioutil.ReadFile(opts.argocdCMPath)
		if err != nil {
			return nil, err
		}
		err = yaml.Unmarshal(data, &argocdCM)
		if err != nil {
			return nil, err
		}
	}
	setSettingsMeta(argocdCM)

	var argocdSecret *corev1.Secret
	if opts.argocdSecretPath != "" {
		data, err := ioutil.ReadFile(opts.argocdSecretPath)
		if err != nil {
			return nil, err
		}
		err = yaml.Unmarshal(data, &argocdSecret)
		if err != nil {
			return nil, err
		}
		setSettingsMeta(argocdSecret)
	} else if opts.loadClusterSettings {
		realClientset, ns, err := opts.getK8sClient()
		if err != nil {
			return nil, err
		}
		argocdSecret, err = realClientset.CoreV1().Secrets(ns).Get(common.ArgoCDSecretName, v1.GetOptions{})
		if err != nil {
			return nil, err
		}
	} else {
		argocdSecret = &corev1.Secret{
			ObjectMeta: v1.ObjectMeta{
				Name: common.ArgoCDSecretName,
			},
			Data: map[string][]byte{
				"admin.password":   []byte("test"),
				"server.secretkey": []byte("test"),
			},
		}
	}
	setSettingsMeta(argocdSecret)
	clientset := fake.NewSimpleClientset(argocdSecret, argocdCM)

	manager := settings.NewSettingsManager(context.Background(), clientset, "default")
	errors.CheckError(manager.ResyncInformers())

	return manager, nil
}

func (opts *settingsOpts) getK8sClient() (*kubernetes.Clientset, string, error) {
	namespace, _, err := opts.clientConfig.Namespace()
	if err != nil {
		return nil, "", err
	}

	restConfig, err := opts.clientConfig.ClientConfig()
	if err != nil {
		return nil, "", err
	}

	realClientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, "", err
	}
	return realClientset, namespace, nil
}

func NewSettingsCommand() *cobra.Command {
	var (
		opts settingsOpts
	)

	var command = &cobra.Command{
		Use: "settings",
		Run: func(c *cobra.Command, args []string) {
			c.HelpFunc()(c, args)
		},
	}
	log.SetLevel(log.FatalLevel)

	command.AddCommand(NewValidateSettingsCommand(&opts))
	command.AddCommand(NewResourceOverridesCommand(&opts))

	opts.clientConfig = cli.AddKubectlFlagsToCmd(command)
	command.PersistentFlags().StringVar(&opts.argocdCMPath, "argocd-cm-path", "", "Path to local argocd-cm.yaml file")
	command.PersistentFlags().StringVar(&opts.argocdSecretPath, "argocd-secret-path", "", "Path to local argocd-secret.yaml file")
	command.PersistentFlags().BoolVar(&opts.loadClusterSettings, "load-cluster-settings", false,
		"Indicates that config map and secret should be loaded from cluster unless local file path is provided")
	return command
}

type settingValidator func(manager *settings.SettingsManager) (string, error)

func joinValidators(validators ...settingValidator) settingValidator {
	return func(manager *settings.SettingsManager) (string, error) {
		var errorStrs []string
		var summaries []string
		for i := range validators {
			summary, err := validators[i](manager)
			if err != nil {
				errorStrs = append(errorStrs, err.Error())
			}
			if summary != "" {
				summaries = append(summaries, summary)
			}
		}
		if len(errorStrs) > 0 {
			return "", fmt.Errorf("%s", strings.Join(errorStrs, "\n"))
		}
		return strings.Join(summaries, "\n"), nil
	}
}

var validatorsByGroup = map[string]settingValidator{
	"general": joinValidators(func(manager *settings.SettingsManager) (string, error) {
		general, err := manager.GetSettings()
		if err != nil {
			return "", err
		}
		var summary string
		ssoConfigured := general.IsSSOConfigured()
		if ssoConfigured && general.URL == "" {
			summary = "sso configured ('url' field is missing)"
		} else if ssoConfigured && general.URL != "" {
			summary = "sso configured"
		} else {
			summary = "sso is not configured"
		}
		return summary, nil
	}, func(manager *settings.SettingsManager) (string, error) {
		_, err := manager.GetAppInstanceLabelKey()
		return "", err
	}, func(manager *settings.SettingsManager) (string, error) {
		_, err := manager.GetHelp()
		return "", err
	}, func(manager *settings.SettingsManager) (string, error) {
		_, err := manager.GetGoogleAnalytics()
		return "", err
	}),
	"plugins": func(manager *settings.SettingsManager) (string, error) {
		plugins, err := manager.GetConfigManagementPlugins()
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d plugins", len(plugins)), nil
	},
	"kustomize": func(manager *settings.SettingsManager) (string, error) {
		opts, err := manager.GetKustomizeBuildOptions()
		if opts == "" {
			opts = "default options"
		}
		return opts, err
	},
	"repositories": joinValidators(func(manager *settings.SettingsManager) (string, error) {
		repos, err := manager.GetRepositories()
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d repositories", len(repos)), nil
	}, func(manager *settings.SettingsManager) (string, error) {
		creds, err := manager.GetRepositoryCredentials()
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d repository credentials", len(creds)), nil
	}),
	"accounts": func(manager *settings.SettingsManager) (string, error) {
		accounts, err := manager.GetAccounts()
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d accounts", len(accounts)), nil
	},
	"resource-overrides": func(manager *settings.SettingsManager) (string, error) {
		overrides, err := manager.GetResourceOverrides()
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d resource overrides", len(overrides)), nil
	},
}

func NewValidateSettingsCommand(opts *settingsOpts) *cobra.Command {
	var (
		groups []string
	)

	var allGroups []string
	for k := range validatorsByGroup {
		allGroups = append(allGroups, k)
	}
	sort.Slice(allGroups, func(i, j int) bool {
		return allGroups[i] < allGroups[j]
	})

	var command = &cobra.Command{
		Use:  "validate",
		Long: "Validates settings specified in 'argocd-cm' ConfigMap and 'argocd-secret' Secret",
		Example: `
#Validates all settings in the specified YAML file
argocd-util settings validate --argocd-cm-path ./argocd-cm.yaml

#Validates accounts and plugins settings in Kubernetes cluster of current kubeconfig context
argocd-util settings validate --group accounts --group plugins --load-cluster-settings`,
		Run: func(c *cobra.Command, args []string) {
			settingsManager, err := opts.createSettingsManager()
			errors.CheckError(err)

			if len(groups) == 0 {
				groups = allGroups
			}
			for i, group := range groups {
				validator := validatorsByGroup[group]

				logs := collectLogs(func() {
					summary, err := validator(settingsManager)

					if err != nil {
						_, _ = fmt.Fprintf(os.Stdout, "❌ %s\n", group)
						_, _ = fmt.Fprintf(os.Stdout, "%s\n", err.Error())
					} else {
						_, _ = fmt.Fprintf(os.Stdout, "✅ %s\n", group)
						if summary != "" {
							_, _ = fmt.Fprintf(os.Stdout, "%s\n", summary)
						}
					}
				})
				if logs != "" {
					_, _ = fmt.Fprintf(os.Stdout, "%s\n", logs)
				}
				if i != len(groups)-1 {
					_, _ = fmt.Fprintf(os.Stdout, "\n")
				}
			}
		},
	}

	command.Flags().StringArrayVar(&groups, "group", nil, fmt.Sprintf(
		"Optional list of setting groups that have to be validated ( one of: %s)", strings.Join(allGroups, ", ")))

	return command
}

func NewResourceOverridesCommand(opts *settingsOpts) *cobra.Command {
	var command = &cobra.Command{
		Use: "resource-overrides",
		Run: func(c *cobra.Command, args []string) {
			c.HelpFunc()(c, args)
		},
	}
	command.AddCommand(NewResourceIgnoreDifferencesCommand(opts))
	command.AddCommand(NewResourceActionCommand(opts))
	command.AddCommand(NewResourceHealthCommand(opts))
	return command
}

func executeResourceOverrideCommand(opts *settingsOpts, args []string, callback func(res unstructured.Unstructured, override v1alpha1.ResourceOverride, overrides map[string]v1alpha1.ResourceOverride)) {
	data, err := ioutil.ReadFile(args[0])
	errors.CheckError(err)

	res := unstructured.Unstructured{}
	errors.CheckError(yaml.Unmarshal(data, &res))

	settingsManager, err := opts.createSettingsManager()
	errors.CheckError(err)

	overrides, err := settingsManager.GetResourceOverrides()
	errors.CheckError(err)
	gvk := res.GroupVersionKind()
	override, hasOverride := overrides[fmt.Sprintf("%s/%s", gvk.Group, gvk.Kind)]
	if !hasOverride {
		_, _ = fmt.Printf("No overrides configured for '%s/%s'\n", gvk.Group, gvk.Kind)
		return
	}
	callback(res, override, overrides)
}

func NewResourceIgnoreDifferencesCommand(opts *settingsOpts) *cobra.Command {
	var command = &cobra.Command{
		Use:  "ignore-differences RESOURCE_YAML_PATH",
		Long: "Renders ignored fields using the 'ignoreDifferences' setting specified in the 'resource.customizations' field of 'argocd-cm' ConfigMap",
		Example: `
argocd-util settings resource-overrides ignore-differences ./deploy.yaml --argocd-cm-path ./argocd-cm.yaml`,
		Run: func(c *cobra.Command, args []string) {
			if len(args) < 1 {
				c.HelpFunc()(c, args)
				os.Exit(1)
			}

			executeResourceOverrideCommand(opts, args, func(res unstructured.Unstructured, override v1alpha1.ResourceOverride, overrides map[string]v1alpha1.ResourceOverride) {
				gvk := res.GroupVersionKind()
				if override.IgnoreDifferences == "" {
					_, _ = fmt.Printf("Ignore differences are not configured for '%s/%s'\n", gvk.Group, gvk.Kind)
					return
				}

				normalizer, err := normalizers.NewIgnoreNormalizer(nil, overrides)
				errors.CheckError(err)

				normalizedRes := res.DeepCopy()
				logs := collectLogs(func() {
					errors.CheckError(normalizer.Normalize(normalizedRes))
				})
				if logs != "" {
					_, _ = fmt.Println(logs)
				}

				if reflect.DeepEqual(&res, normalizedRes) {
					_, _ = fmt.Printf("No fields are ignored by ignoreDifferences settings: \n%s\n", override.IgnoreDifferences)
					return
				}

				_, _ = fmt.Printf("Following fields are ignored:\n\n")
				_ = diff.PrintDiff(res.GetName(), &res, normalizedRes)
			})
		},
	}
	return command
}

func NewResourceHealthCommand(opts *settingsOpts) *cobra.Command {
	var command = &cobra.Command{
		Use:  "health RESOURCE_YAML_PATH",
		Long: "Assess resource health using the lua script configured in the 'resource.customizations' field of 'argocd-cm' ConfigMap",
		Example: `
argocd-util settings resource-overrides health ./deploy.yaml --argocd-cm-path ./argocd-cm.yaml`,
		Run: func(c *cobra.Command, args []string) {
			if len(args) < 1 {
				c.HelpFunc()(c, args)
				os.Exit(1)
			}

			executeResourceOverrideCommand(opts, args, func(res unstructured.Unstructured, override v1alpha1.ResourceOverride, overrides map[string]v1alpha1.ResourceOverride) {
				gvk := res.GroupVersionKind()
				if override.HealthLua == "" {
					_, _ = fmt.Printf("Health script is not configured for '%s/%s'\n", gvk.Group, gvk.Kind)
					return
				}

				resHealth, err := health.GetResourceHealth(&res, overrides)
				errors.CheckError(err)

				_, _ = fmt.Printf("STATUS: %s\n", resHealth.Status)
				_, _ = fmt.Printf("MESSAGE: %s\n", resHealth.Message)
			})
		},
	}
	return command
}

func NewResourceActionCommand(opts *settingsOpts) *cobra.Command {
	var command = &cobra.Command{
		Use:  "action RESOURCE_YAML_PATH ACTION",
		Long: "Executes resource action using the lua script configured in the 'resource.customizations' field of 'argocd-cm' ConfigMap and outputs updated fields",
		Example: `
argocd-util settings resource-overrides action /tmp/deploy.yaml restart --argocd-cm-path ./argocd-cm.yaml`,
		Run: func(c *cobra.Command, args []string) {
			if len(args) < 2 {
				c.HelpFunc()(c, args)
				os.Exit(1)
			}
			action := args[1]

			executeResourceOverrideCommand(opts, args, func(res unstructured.Unstructured, override v1alpha1.ResourceOverride, overrides map[string]v1alpha1.ResourceOverride) {
				gvk := res.GroupVersionKind()
				if override.Actions == "" {
					_, _ = fmt.Printf("Actions are not configured for '%s/%s'\n", gvk.Group, gvk.Kind)
					return
				}

				luaVM := lua.VM{ResourceOverrides: overrides}
				action, err := luaVM.GetResourceAction(&res, action)
				errors.CheckError(err)

				modifiedRes, err := luaVM.ExecuteResourceAction(&res, action.ActionLua)
				errors.CheckError(err)

				if reflect.DeepEqual(&res, modifiedRes) {
					_, _ = fmt.Printf("No fields had been changed by action: \n%s\n", action.Name)
					return
				}

				_, _ = fmt.Printf("Following fields have been changed:\n\n")
				_ = diff.PrintDiff(res.GetName(), &res, modifiedRes)
			})
		},
	}
	return command
}
