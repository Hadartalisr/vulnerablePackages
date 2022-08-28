package core

import (
	"crypto/sha256"
	"errors"
	"fmt"
	golangLRU "github.com/bserdar/golang-lru"
	"vulnerablePackages/pkg/config"
	"vulnerablePackages/pkg/definition"
)

var (
	ErrNotFoundInCache = errors.New("not found in cache")
)

func NewCache() (*golangLRU.Cache, error) {
	return golangLRU.NewWithTTL(config.Static.VulnerabilitiesCachingSize, config.Static.VulnerabilitiesCachingTTL)
}

func (p *ProjectScanner) getCachedPackageVulnerabilities(ecosystem, name string) ([]definition.Vulnerability, error) {
	if !config.Static.IsVulnerabilitiesCachingEnabled {
		return nil, ErrNotFoundInCache
	}
	val, ok := p.vulCache.Get(getPackageKey(ecosystem, name))
	if !ok {
		return nil, ErrNotFoundInCache
	}
	return val.([]definition.Vulnerability), nil
}

func (p *ProjectScanner) cachePackageVulnerabilities(ecosystem, name string, vulnerabilities []definition.Vulnerability) {
	if !config.Static.IsVulnerabilitiesCachingEnabled {
		return
	}
	p.vulCache.Add(getPackageKey(ecosystem, name), vulnerabilities, len(vulnerabilities))
}

// getPackageKey returns the key of the package in cache
func getPackageKey(ecosystem, name string) string {
	h := sha256.New()
	h.Write([]byte(ecosystem + name))
	return fmt.Sprintf("%x", h.Sum(nil))
}
