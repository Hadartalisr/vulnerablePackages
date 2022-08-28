package provider

import (
	"github.com/shurcooL/githubv4"
	"vulnerablePackages/pkg/definition"
)

// docs can be found in https://docs.github.com/en/graphql/reference/queries#securityvulnerabilities
// package (String) - A package name to filter vulnerabilities by.
// there is no anu ability to send an array of packages.
// there is no any version filtering parameter.

// PageInfo is a GitHub type used in paginated responses
type PageInfo struct {
	StartCursor githubv4.String
	EndCursor   githubv4.String
	HasNextPage bool
}

type QueryVulnerabilities struct {
	SecurityVulnerabilities struct {
		Nodes    []SecurityVulnerability
		PageInfo PageInfo
	} `graphql:"securityVulnerabilities(after: $cursor,  ecosystem: $ecosystem, package: $package, first: $batchSize)"`
}

// SecurityVulnerability has all the security information
type SecurityVulnerability struct {
	Package                SecurityAdvisoryPackage
	FirstPatchedVersion    SecurityAdvisoryPackageVersion
	VulnerableVersionRange string
	Severity               string
}

// SecurityAdvisoryPackageVersion is a struct with an identifier to identify the package
type SecurityAdvisoryPackageVersion struct {
	Identifier string
}

// SecurityAdvisoryPackage is an object to share the name of the package that is impacted
type SecurityAdvisoryPackage struct {
	Name      string
	Ecosystem string
}

func (s *SecurityVulnerability) toVulnerability() definition.Vulnerability {
	return definition.Vulnerability{
		Name:                s.Package.Name,
		Version:             s.VulnerableVersionRange,
		Severity:            s.Severity,
		FirstPatchedVersion: s.FirstPatchedVersion.Identifier,
	}
}
