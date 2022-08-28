package main

import (
	"net/http"
	"vulnerablePackages/pkg/core"
	"vulnerablePackages/pkg/definition"
	"vulnerablePackages/pkg/provider"
	"vulnerablePackages/pkg/server"
	"vulnerablePackages/pkg/utils/lifecycle"
)

func main() {
	lifecycle.Start()

	vulDateSource := initVulnerabilitiesDataSource()
	projectScanner := initProjectScanner(&vulDateSource)
	startHTTPServer(&projectScanner)

	lifecycle.WaitForShutDown()
}

func initVulnerabilitiesDataSource() definition.IVulnerabilitiesDataSource {
	return lifecycle.CreateResource("VulnerabilitiesDataSource", provider.NewGitHubVulnerabilitiesDataSource)
}

func initProjectScanner(vulDateSource *definition.IVulnerabilitiesDataSource) definition.IProjectScanner {
	return lifecycle.CreateResource("ProjectScanner",
		func() (definition.IProjectScanner, error) {
			return core.NewProjectScanner(vulDateSource)
		})
}

func startHTTPServer(projectScanner *definition.IProjectScanner) {
	lifecycle.CreateResource("HTTPServer",
		func() (*http.Server, error) {
			return server.StartHTTP(projectScanner)
		})
}
