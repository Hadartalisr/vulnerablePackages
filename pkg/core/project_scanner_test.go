package core

import (
	"encoding/json"
	"testing"
	"vulnerablePackages/pkg/definition"
)

var npmVulnerabilities = []definition.Vulnerability{
	{
		Name:                "express",
		Version:             ">= 4.0.0, < 4.5.0",
		Severity:            "MODERATE",
		FirstPatchedVersion: "4.5.0",
	},
	{
		Name:                "express",
		Version:             "> 4.0.0, <= 4.6.0",
		Severity:            "CRITICAL",
		FirstPatchedVersion: "4.6.0",
	},
	{
		Name:                "deep-override",
		Version:             "= 1.0.1",
		Severity:            "CRITICAL",
		FirstPatchedVersion: "1.0.2",
	},
	{
		Name:                "deep-override",
		Version:             "<= 2.0.1",
		Severity:            "MODERATE",
		FirstPatchedVersion: "2.0.1",
	},
}

type vulDataSourceMock struct{}

func (v *vulDataSourceMock) GetByPackage(ecosystem, name string) ([]definition.Vulnerability, error) {
	vulnerabilities := make([]definition.Vulnerability, 0)
	if ecosystem == "NPM" {
		for _, v := range npmVulnerabilities {
			if v.Name == name {
				vulnerabilities = append(vulnerabilities, v)
			}
		}
	}
	return vulnerabilities, nil
}

func (v *vulDataSourceMock) Close() error {
	return nil
}

func toBytes[T any](t T) ([]byte, error) {
	return json.Marshal(t)
}

func TestGetByPackage(t *testing.T) {
	var vulnerabilitiesDataSourceMock definition.IVulnerabilitiesDataSource
	vulnerabilitiesDataSourceMock = &vulDataSourceMock{}
	projectScanner, err := NewProjectScanner(&vulnerabilitiesDataSourceMock)
	if err != nil {
		t.Error(err)
	}

	t.Run("test mock setup", func(t *testing.T) {
		res, err := vulnerabilitiesDataSourceMock.GetByPackage("NPM", "express")
		if err != nil {
			t.Error("error should not exist")
		}
		if len(res) != 2 {
			t.Error("result should have 2 vulnerabilities")
		}
	})

	t.Run("should send ErrInvalidProjectFile for empty package.json file", func(t *testing.T) {
		b, err := toBytes(npmProjectFile{})
		_, err = projectScanner.Scan("npm", b)
		if err != definition.ErrInvalidProjectFile {
			t.Error(err)
		}
	})

	t.Run("should send ErrUnsupportedEcosystem for unsupported ecosystem", func(t *testing.T) {
		b, err := toBytes(npmProjectFile{
			Name: "my-malicious-code",
		})
		_, err = projectScanner.Scan("futuristic-ecosystem", b)
		if err != definition.ErrUnsupportedEcosystem {
			t.Error(err)
		}
	})

	t.Run("should not have vulnerabilities for project without dependencies", func(t *testing.T) {
		b, err := toBytes(npmProjectFile{
			Name:    "my-malicious-code",
			Version: "1.0.0",
		})
		res, err := projectScanner.Scan("npm", b)
		if err != nil {
			t.Error(err)
		}
		println(res)
	})

	t.Run("should not have vulnerabilities for project without vulnerable dependencies", func(t *testing.T) {
		dependencies := make(map[string]string)
		dependencies["express"] = "3.0.3"
		b, err := toBytes(npmProjectFile{
			Name:         "my-malicious-code",
			Version:      "1.0.0",
			Dependencies: dependencies,
		})
		res, err := projectScanner.Scan("npm", b)
		if err != nil {
			t.Error(err)
		}
		if len(res) != 0 {
			t.Error("should not have vulnerabilities")
		}
	})

	t.Run("should not have vulnerabilities for project with vulnerable dependencies", func(t *testing.T) {
		dependencies := make(map[string]string)
		dependencies["express"] = "4.2.0"
		dependencies["super-dependency"] = "6.6.6"
		b, err := toBytes(npmProjectFile{
			Name:         "amazing-project",
			Version:      "1.0.0",
			Dependencies: dependencies,
		})
		res, err := projectScanner.Scan("npm", b)
		if err != nil {
			t.Error(err)
		}
		if len(res) != 2 {
			t.Error("should have vulnerabilities")
		}
	})

	t.Run("should have vulnerabilities for all the project vulnerable dependencies", func(t *testing.T) {
		dependencies := make(map[string]string)
		dependencies["express"] = "4.2.0"
		dependencies["super-dependency"] = "6.6.6"
		dependencies["deep-override"] = "1.0.1"
		b, err := toBytes(npmProjectFile{
			Name:         "super-vulnerable-project",
			Version:      "1.0.0",
			Dependencies: dependencies,
		})
		res, err := projectScanner.Scan("npm", b)
		if err != nil {
			t.Error(err)
		}
		if len(res) != 4 {
			t.Error("should have vulnerabilities")
		}
	})

}

func TestCache(t *testing.T) {
	var vulnerabilitiesDataSourceMock definition.IVulnerabilitiesDataSource
	vulnerabilitiesDataSourceMock = &vulDataSourceMock{}
	projectScanner, err := NewProjectScanner(&vulnerabilitiesDataSourceMock)
	if err != nil {
		t.Error(err)
	}
	ecosystem := "ecosystem"
	anotherEcosystem := "super-ecosystem"
	name := "package-name"

	t.Run("should return ErrNotFoundInCache if package don't exist", func(t *testing.T) {
		_, err := projectScanner.getCachedPackageVulnerabilities(ecosystem, name)
		if err != ErrNotFoundInCache {
			t.Error("ErrNotFoundInCache should occur")
		}
	})

	t.Run("should return value if vulnerabilities where added", func(t *testing.T) {
		projectScanner.cachePackageVulnerabilities(ecosystem, name, npmVulnerabilities)
		vul, err := projectScanner.getCachedPackageVulnerabilities(ecosystem, name)
		if err != nil {
			t.Error("error should not exist")
		}
		if len(vul) != 4 {
			t.Error("should return all package's cached vulnerabilities")
		}
	})

	t.Run("should return vulnerabilities of the relevant package", func(t *testing.T) {
		_, err := projectScanner.getCachedPackageVulnerabilities(anotherEcosystem, name)
		if err != ErrNotFoundInCache {
			t.Error("ErrNotFoundInCache should occur")
		}
		projectScanner.cachePackageVulnerabilities(anotherEcosystem, name, npmVulnerabilities[:2])
		vul, err := projectScanner.getCachedPackageVulnerabilities(anotherEcosystem, name)
		if err != nil {
			t.Error("error should not exist")
		}
		if len(vul) != 2 {
			t.Error("should return the package's vulnerabilities")
		}
	})

}
