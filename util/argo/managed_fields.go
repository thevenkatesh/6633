package argo

import (
	"bytes"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/structured-merge-diff/v4/fieldpath"
	"sigs.k8s.io/structured-merge-diff/v4/typed"
)

// Normalize will compare the live and config states. If config mutates a field that belongs to one of
// the trustedManagers it will remove that field from both live and config objects.
func Normalize(live, config *unstructured.Unstructured, trustedManagers []string) error {
	comparison, err := Compare(live, config)
	if err != nil {
		return err
	}

	for _, mf := range live.GetManagedFields() {
		if trustedManager(mf.Manager, trustedManagers) {
			err := normalize(live, config, mf, comparison.Modified)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// normalize will check if the modified set has fields that are present in the managed fields entry. If so,
// it will remove the fields from the live and config objects so it is ignored in diffs.
func normalize(live, config *unstructured.Unstructured, mf v1.ManagedFieldsEntry, modified *fieldpath.Set) error {
	liveSet := &fieldpath.Set{}
	err := liveSet.FromJSON(bytes.NewReader(mf.FieldsV1.Raw))
	if err != nil {
		return err
	}

	intersect := liveSet.Intersection(modified)
	if !intersect.Empty() {
		intersect.Iterate(func(p fieldpath.Path) {
			fields := PathToNestedFields(p)
			unstructured.RemoveNestedField(config.Object, fields...)
			unstructured.RemoveNestedField(live.Object, fields...)
		})
	}
	return nil
}

// Compare will compare the live and the config state and returned a typed.Comparison
// as a result.
func Compare(live, config *unstructured.Unstructured) (*typed.Comparison, error) {
	typedLive, err := typed.DeducedParseableType.FromUnstructured(live.Object)
	if err != nil {
		return nil, err
	}
	typedConfig, err := typed.DeducedParseableType.FromUnstructured(config.Object)
	if err != nil {
		return nil, err
	}
	return typedLive.Compare(typedConfig)
}

// PathToNestedFields will convert a path into a slice of field names so it
// can be used in unstructured nested fields operations.
func PathToNestedFields(path fieldpath.Path) []string {
	fields := []string{}
	for _, element := range path {
		if element.FieldName != nil {
			fields = append(fields, *element.FieldName)
		}
	}
	return fields
}

// trustedManager will return true if trustedManagers contains curManager.
// Returns false otherwise.
func trustedManager(curManager string, trustedManagers []string) bool {
	for _, m := range trustedManagers {
		if m == curManager {
			return true
		}
	}
	return false
}
