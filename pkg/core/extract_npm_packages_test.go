package core

import (
	"testing"
	"vulnerablePackages/pkg/definition"
)

func TestNPMPackagesExtractor(t *testing.T) {

	t.Run("should extract valid package.json file", func(t *testing.T) {
		file := "{\n\"name\": \"My Application\",\n\"version\": \"1.0.0\"," +
			"\n\"dependencies\": {\n\"deep-override\": \"1.0.1\",\n\"express\": \"4.17.1\"\n}\n}"
		packages, err := extractNPMPackages([]byte(file))
		if err != nil {
			t.Error("errors should not exists ", err)
		}
		if len(packages) != 2 {
			t.Error("2 packages should be extracted")
		}
	})

	t.Run("should return ErrInvalidProjectFile is package.json is invalid json", func(t *testing.T) {
		file := "\n\"name\": \"My Application\",\n\"version\": \"1.0.0\"," +
			"\n\"dependencies\": {\n\"deep-override\": \"1.0.1\",\n\"express\": \"4.17.1\"\n}\n}"
		_, err := extractNPMPackages([]byte(file))
		if err != definition.ErrInvalidProjectFile {
			t.Error("error should be ErrInvalidProjectFile ", err)
		}
	})

	t.Run("should return ErrInvalidProjectFile if package.json dont have Name field", func(t *testing.T) {
		file := "{\n\"version\": \"1.0.0\"," +
			"\n\"dependencies\": {\n\"deep-override\": \"1.0.1\",\n\"express\": \"4.17.1\"\n}\n}"
		_, err := extractNPMPackages([]byte(file))
		if err != definition.ErrInvalidProjectFile {
			t.Error("error should be ErrInvalidProjectFile ", err)
		}
	})

	t.Run("should return ErrInvalidProjectFile if a dependency doesnt contain version", func(t *testing.T) {
		file := "{\n\"name\": \"My Application\",\n\"version\": \"1.0.0\"," +
			"\n\"dependencies\": {\n\"deep-override\": \"1.0.1\",\n\"express\": \"\"\n}\n}"
		_, err := extractNPMPackages([]byte(file))
		if err != definition.ErrInvalidProjectFile {
			t.Error("error should be ErrInvalidProjectFile ", err)
		}
	})

}
