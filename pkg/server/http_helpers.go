package server

import (
	"encoding/json"
	"errors"
	"github.com/sirupsen/logrus"
	"net/http"
)

const (
	ContentTypeHeader             = "Content-Type"
	ContentTypeAppJSONHeaderValue = "application/json"
)

var (
	ErrBadRequestBody         = errors.New("bad request body")
	ErrRequestBodyNotParsable = errors.New("request body is not parsable")
)

func WriteJSONResponse(w http.ResponseWriter, status int, body interface{}) {
	raw, err := json.Marshal(body)
	if err != nil {
		logrus.WithError(err).Error("could not marshal http response body")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set(ContentTypeHeader, ContentTypeAppJSONHeaderValue)
	WriteBytesResponse(w, status, raw)
}

func WriteBytesResponse(w http.ResponseWriter, status int, body []byte) {
	w.WriteHeader(status)
	_, err := w.Write(body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		logrus.WithError(err).Error("could not write http response body")
	}
}

func ParseJSONBody(req *http.Request, dst interface{}) bool {
	err := json.NewDecoder(req.Body).Decode(dst)
	if err == nil {
		return true
	}
	return false
}
