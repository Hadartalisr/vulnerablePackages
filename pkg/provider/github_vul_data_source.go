package provider

import (
	"github.com/hasura/go-graphql-client"
	"github.com/shurcooL/githubv4"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"net/http"
	"vulnerablePackages/pkg/config"
	"vulnerablePackages/pkg/definition"
)

type GitHubVulnerabilitiesDataSource struct {
	httpClient    *http.Client
	graphqlClient *graphql.Client
}

func NewGitHubVulnerabilitiesDataSource() (*GitHubVulnerabilitiesDataSource, error) {
	httpClient := NewGitHubHTTPClient()
	graphqlClient := graphql.NewClient(config.Static.GitHubGraphQLAPIURL, httpClient)
	gitHubVulnerabilitiesDataSource := GitHubVulnerabilitiesDataSource{
		httpClient:    httpClient,
		graphqlClient: graphqlClient,
	}
	gitHubVulnerabilitiesDataSource.testConnection()
	return &gitHubVulnerabilitiesDataSource, nil
}

func NewGitHubHTTPClient() *http.Client {
	return oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: config.Static.GitHubAccessToken,
		TokenType:   "Bearer",
	}))
}

func (g *GitHubVulnerabilitiesDataSource) Close() error {
	g.httpClient.CloseIdleConnections()
	return nil
}

func (g *GitHubVulnerabilitiesDataSource) GetByPackage(ecosystem, name string) ([]definition.Vulnerability, error) {
	if ecosystem == "" || name == "" {
		return nil, definition.ErrInvalidPkg
	}
	variables := map[string]interface{}{
		"cursor":    (*githubv4.String)(nil),
		"package":   graphql.String(name),
		"ecosystem": githubv4.SecurityAdvisoryEcosystem(ecosystem),
		"batchSize": graphql.Int(config.Static.GitHubVulnerabilitiesBatchSize),
	}
	vulnerabilities := make([]definition.Vulnerability, 0)
	for {
		q := &QueryVulnerabilities{}
		ctx, _ := context.WithTimeout(context.Background(), config.Static.GitHubRequestTimeout)
		if err := g.graphqlClient.Query(ctx, q, variables); err != nil {
			logrus.WithError(err).Error()
			return nil, err
		}
		for _, securityVulnerability := range q.SecurityVulnerabilities.Nodes {
			vulnerabilities = append(vulnerabilities, securityVulnerability.toVulnerability())
		}
		if !q.SecurityVulnerabilities.PageInfo.HasNextPage {
			break
		}
		variables["cursor"] = q.SecurityVulnerabilities.PageInfo.EndCursor
	}
	return vulnerabilities, nil
}

func (g *GitHubVulnerabilitiesDataSource) testConnection() {
	_, err := g.GetByPackage("NPM", "express")
	if err != nil {
		logrus.Fatal("github connection test has failed")
	}
}
