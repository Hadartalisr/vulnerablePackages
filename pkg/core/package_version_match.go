package core

import (
	"errors"
	goVersion "github.com/hashicorp/go-version"
	"github.com/sirupsen/logrus"
)

// = 0.2.0 denotes a single vulnerable version.
//<= 1.0.8 denotes a version range up to and including the specified version
//< 0.1.11 denotes a version range up to, but excluding, the specified version
//>= 4.3.0, < 4.3.5 denotes a version range with a known minimum and maximum version.
//>= 0.0.1 denotes a version range with a known minimum, but no known maximum.

var (
	ErrInvalidVersionParams = errors.New("invalid version params")
)

func isMatch(versionRange, version string) (bool, error) {
	if versionRange == "" || version == "" {
		return invalidParams(versionRange, version)
	}
	v, err := goVersion.NewVersion(version)
	if err != nil {
		logrus.WithError(err)
		return invalidParams(versionRange, version)
	}
	constraints, err := goVersion.NewConstraint(versionRange)
	if err != nil {
		logrus.WithError(err)
		return invalidParams(versionRange, version)
	}
	return constraints.Check(v), nil
}

func invalidParams(versionRange, version string) (bool, error) {
	logrus.WithError(ErrInvalidVersionParams).
		Errorf("versionRange - %s ; version - %s", versionRange, version)
	return false, ErrInvalidVersionParams
}
