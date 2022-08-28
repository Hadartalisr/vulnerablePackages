package server

import (
	"github.com/sirupsen/logrus"
	"net/http"
	"vulnerablePackages/pkg/definition"
)

type httpV1HandlerStruct struct {
	projectScanner *definition.IProjectScanner
}

type HttpV1ScanPayload struct {
	Ecosystem   string `json:"ecosystem"`
	FileContent []byte `json:"fileContent"`
}

type HttpV1ScanResponse struct {
	VulnerablePackages []definition.Vulnerability `json:"vulnerablePackages"`
}

var httpV1Handler httpV1HandlerStruct

func initHttpV1Handler(projectScanner *definition.IProjectScanner) {
	if projectScanner == nil {
		logrus.Fatal("can not init httpV1Handler - projectScanner is nil")
	}
	httpV1Handler = httpV1HandlerStruct{
		projectScanner: projectScanner,
	}
}

func (h *httpV1HandlerStruct) Scan(writer http.ResponseWriter, r *http.Request) {
	payload, err := h.readScanPayload(r)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	vulnerabilities, err := (*h.projectScanner).Scan(payload.Ecosystem, payload.FileContent)
	if err != nil {
		h.handleScanError(err, writer)
		return
	}
	h.writeScanResponse(vulnerabilities, writer)
}

func (h *httpV1HandlerStruct) readScanPayload(r *http.Request) (*HttpV1ScanPayload, error) {
	var payload HttpV1ScanPayload
	if !ParseJSONBody(r, &payload) {
		logrus.WithError(ErrRequestBodyNotParsable).Info("could not parse json body")
		return nil, ErrRequestBodyNotParsable
	}
	if payload.Ecosystem == "" || len(payload.FileContent) == 0 {
		logrus.WithError(ErrRequestBodyNotParsable).Info("payload dont have required fields")
		return nil, ErrRequestBodyNotParsable
	}
	return &payload, nil
}

func (h *httpV1HandlerStruct) writeScanResponse(vulnerabilities []definition.Vulnerability, writer http.ResponseWriter) {
	if len(vulnerabilities) == 0 {
		writer.WriteHeader(http.StatusOK)
		return
	}
	response := HttpV1ScanResponse{
		VulnerablePackages: vulnerabilities,
	}
	WriteJSONResponse(writer, http.StatusOK, response)
}

func (h *httpV1HandlerStruct) handleScanError(err error, writer http.ResponseWriter) {
	if err == definition.ErrUnsupportedEcosystem {
		logrus.WithError(definition.ErrUnsupportedEcosystem).Info()
		writer.WriteHeader(http.StatusNotImplemented)
		return
	}
	if err == ErrBadRequestBody {
		logrus.WithError(err).Info()
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	logrus.WithError(err).Error()
	writer.WriteHeader(http.StatusInternalServerError)
	return
}
