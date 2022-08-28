package core

import (
	"encoding/json"
	"github.com/sirupsen/logrus"
	"vulnerablePackages/pkg/definition"
)

type npmProjectFile struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Dependencies map[string]string `json:"dependencies"`
}

const npmEcosystem = "NPM"

// extractNPMPackages extracts the packages which are being used as dependencies in package.json file.
// It receives the raw file as bytearray and returns the packages.
func extractNPMPackages(fileContent []byte) ([]pkg, error) {
	var projectFile npmProjectFile
	err := json.Unmarshal(fileContent, &projectFile)
	if err != nil || !projectFile.isValid() {
		logrus.WithError(err).Error("extract npm packages - fileContent is invalid")
		return nil, definition.ErrInvalidProjectFile
	}
	return projectFile.getPackages()
}

func (n *npmProjectFile) isValid() bool {
	return n.Name != "" && n.Version != ""
}

func (n *npmProjectFile) getPackages() ([]pkg, error) {
	packages := make([]pkg, 0)
	for name, version := range n.Dependencies {
		if name == "" || version == "" {
			logrus.Errorf("extract npm packages - invalid dependency %s : %s", name, version)
			return nil, definition.ErrInvalidProjectFile
		}
		packages = append(packages, pkg{
			ecosystem: npmEcosystem,
			name:      name,
			version:   version,
		})
	}
	return packages, nil
}
