package config

import (
	"github.com/caarlos0/env"
	"github.com/sirupsen/logrus"
	"time"
)

var Static = struct {
	HTTPServerPort string `env:"HTTP_SERVER_PORT" envDefault:":8080"`

	GitHubGraphQLAPIURL            string        `env:"GITHUB_GRAPHQL_API_URL" envDefault:"https://api.github.com/graphql"`
	GitHubVulnerabilitiesBatchSize int           `env:"GITHUB_VULNERABILITIES_BATCH_SIZE" envDefault:"20"`
	GitHubAccessToken              string        `env:"GITHUB_ACCESS_TOKEN"`
	GitHubRequestTimeout           time.Duration `env:"GITHUB_REQUEST_TIMEOUT" envDefault:"3s"`

	IsVulnerabilitiesCachingEnabled bool          `end:"IS_VULNERABILITIES_CACHING_ENABLED" envDefault:"1"`
	VulnerabilitiesCachingTTL       time.Duration `end:"VULNERABILITIES_CACHING_TTL" envDefault:"300s"`
	VulnerabilitiesCachingSize      int           `end:"VULNERABILITIES_CACHING_SIZE" envDefault:"300"`
}{}

func init() {
	err := env.Parse(&Static)
	if err != nil {
		logrus.WithError(err).Fatal("Could not load static configuration")
	}
}
