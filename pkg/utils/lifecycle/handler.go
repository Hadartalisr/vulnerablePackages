package lifecycle

import (
	"github.com/sirupsen/logrus"
)

type Handler struct {
	HandleInfoMessage           func(msg string)
	HandleResourceCreationError func(title string, err error)
	HandleResourceClosingError  func(title string, err error)
}

func DefaultLifeCycleHandler() *Handler {
	return &Handler{
		HandleInfoMessage:           DefaultHandleInfoMessage,
		HandleResourceCreationError: DefaultHandleResourceCreationError,
		HandleResourceClosingError:  DefaultHandleResourceClosingError,
	}
}

func DefaultHandleInfoMessage(msg string) {
	logrus.Infof(msg)
}

func DefaultHandleResourceCreationError(title string, err error) {
	logrus.RegisterExitHandler(Terminate)
	logrus.WithError(err).Fatalf("Error occured while creating %s", title)
}

func DefaultHandleResourceClosingError(title string, err error) {
	logrus.WithError(err).Errorf("Error occured while closing %s", title)
}
