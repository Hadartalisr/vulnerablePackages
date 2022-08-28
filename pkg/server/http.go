package server

import (
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"net/http"
	"vulnerablePackages/pkg/config"
	"vulnerablePackages/pkg/definition"
)

func StartHTTP(projectScanner *definition.IProjectScanner) (*http.Server, error) {
	router := mux.NewRouter()
	initHttpV1Handler(projectScanner)
	registerV1Routes(router)
	httpServer := &http.Server{
		Addr:    config.Static.HTTPServerPort,
		Handler: router,
	}
	go listenAndServe(httpServer)
	return httpServer, nil
}

func listenAndServe(server *http.Server) {
	logrus.Infof("Starting http server on addr %v", config.Static.HTTPServerPort)
	err := server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		logrus.WithError(err).Fatal("failed to start http server")
	}
}

func registerV1Routes(router *mux.Router) {
	router.Methods(http.MethodPost).Path("/api/v1/scan").HandlerFunc(httpV1Handler.Scan)
}
