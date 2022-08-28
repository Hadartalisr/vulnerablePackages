package core

import (
	"errors"
	golangLRU "github.com/bserdar/golang-lru"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"golang.org/x/sync/errgroup"
	"sync"
	"vulnerablePackages/pkg/definition"
)

type pkg struct {
	name            string
	ecosystem       string
	version         string
	vulnerabilities []definition.Vulnerability
}

type ProjectScanner struct {
	// packagesExtractors is a map from the ecosystem
	// to the corresponding function which extracts the packages from its raw project definition file
	packagesExtractors map[string]func(fileContent []byte) ([]pkg, error)
	vulDataSource      *definition.IVulnerabilitiesDataSource
	vulCache           *golangLRU.Cache
}

func NewProjectScanner(vulDataSource *definition.IVulnerabilitiesDataSource) (*ProjectScanner, error) {
	if vulDataSource == nil {
		return nil, errors.New("can not init projectScanner - vulnerabilitiesDataSource is nil")
	}
	vulCache, err := NewCache()
	if err != nil {
		logrus.WithError(err).Error()
		return nil, err
	}
	return &ProjectScanner{
		packagesExtractors: getPackagesExtractors(),
		vulDataSource:      vulDataSource,
		vulCache:           vulCache,
	}, nil
}

func getPackagesExtractors() map[string]func(fileContent []byte) ([]pkg, error) {
	packagesExtractors := make(map[string]func(fileContent []byte) ([]pkg, error))
	packagesExtractors["npm"] = extractNPMPackages
	return packagesExtractors
}

func (p *ProjectScanner) Scan(ecosystem string, fileContent []byte) ([]definition.Vulnerability, error) {
	extract, ok := p.packagesExtractors[ecosystem]
	if !ok {
		return nil, definition.ErrUnsupportedEcosystem
	}
	packages, err := extract(fileContent)
	if err != nil {
		return nil, err
	}
	return p.getVulnerabilities(packages)
}

func (p *ProjectScanner) Close() error {
	return nil
}

func (p *ProjectScanner) getVulnerabilities(packages []pkg) ([]definition.Vulnerability, error) {
	lock := sync.Mutex{}
	vulnerabilities := make([]definition.Vulnerability, 0)
	group, _ := errgroup.WithContext(context.Background())
	for i := 0; i < len(packages); i++ {
		pkg := packages[i]
		group.Go(func() error {
			// get package vulnerabilities
			pkgVulnerabilities, err := p.getPackageVulnerabilities(&pkg)
			if err != nil {
				return err
			}
			// add them to the slice of vulnerabilities
			lock.Lock()
			defer lock.Unlock()
			vulnerabilities = append(vulnerabilities, pkgVulnerabilities...)
			return nil
		})
	}
	err := group.Wait()
	if err != nil {
		return nil, err
	}
	return vulnerabilities, nil
}

func (p *ProjectScanner) getPackageVulnerabilities(pkg *pkg) ([]definition.Vulnerability, error) {
	cachedInfo, err := p.getCachedPackageVulnerabilities(pkg.ecosystem, pkg.name)
	if err == nil {
		return p.filterVulnerabilitiesByVersion(cachedInfo, pkg.version)
	}

	vulnerabilities, err := (*p.vulDataSource).GetByPackage(pkg.ecosystem, pkg.name)
	if err != nil {
		return nil, err
	}

	go p.cachePackageVulnerabilities(pkg.ecosystem, pkg.name, vulnerabilities)

	return p.filterVulnerabilitiesByVersion(vulnerabilities, pkg.version)
}

// filterVulnerabilitiesByVersion returns the vulnerabilities whom relevant to the package version in the project
// the function override the version range of the vulnerability by the actual package version in the project.
func (p *ProjectScanner) filterVulnerabilitiesByVersion(vulnerabilities []definition.Vulnerability, version string) ([]definition.Vulnerability, error) {
	filteredVulnerabilities := make([]definition.Vulnerability, 0)
	for _, vulnerability := range vulnerabilities {
		match, err := isMatch(vulnerability.Version, version)
		if err != nil {
			return nil, err
		}
		if match {
			vulnerability.Version = version
			filteredVulnerabilities = append(filteredVulnerabilities, vulnerability)
		}
	}
	return filteredVulnerabilities, nil
}
