package security

import (
	"fmt"
	"path/filepath"
	"strings"
)

func EnforceToCurrentRoot(currentRoot, requestedPath string) (string, error) {
	requestedDir, requestedFile := parsePath(requestedPath)
	if !isRequestedDirUnderCurrentRoot(currentRoot, requestedDir) {
		return "", fmt.Errorf("requested path %s should be on or under current directory %s", requestedPath, currentRoot)
	}
	return requestedDir + string(filepath.Separator) + requestedFile, nil
}

func isRequestedDirUnderCurrentRoot(currentRoot, requestedDir string) bool {
	if currentRoot == string(filepath.Separator) {
		return true
	} else if currentRoot == requestedDir {
		return true
	}
	return strings.HasPrefix(requestedDir, currentRoot+string(filepath.Separator))
}

func parsePath(path string) (string, string) {
	directory := filepath.Dir(path)
	if directory == path {
		return directory, ""
	}
	return directory, filepath.Base(path)
}
