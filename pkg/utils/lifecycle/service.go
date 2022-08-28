package lifecycle

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

var (
	lifecycle        *service
	lifecycleHandler *Handler
)

type service struct {
	mtx               *sync.Mutex
	closers           []*closer
	terminatedChannel chan bool
}

func Start() {
	lifecycle = &service{
		mtx:               new(sync.Mutex),
		closers:           nil,
		terminatedChannel: make(chan bool, 1),
	}
	lifecycleHandler = DefaultLifeCycleHandler()
	stopChannel := make(chan os.Signal)
	signal.Notify(stopChannel, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-stopChannel
		lifecycle.terminate(sig)
	}()
	lifecycleHandler.HandleInfoMessage("Service started")
}

func WaitForShutDown() {
	lifecycleHandler.HandleInfoMessage("Waiting for shutdown")
	<-lifecycle.terminatedChannel
}

func CreateResource[T io.Closer](title string, constructor func() (T, error)) T {
	lifecycleHandler.HandleInfoMessage(fmt.Sprintf("Creating Resource %s", title))
	resource, err := constructor()
	if err != nil {
		lifecycleHandler.HandleResourceCreationError(title, err)
		var resultT T
		return resultT
	}
	lifecycleHandler.HandleInfoMessage(fmt.Sprintf("Created Resource %s successfully", title))
	RegisterCloserFunc(title, resource.Close)
	return resource
}

func RegisterCloserFunc(title string, closerFunc CloserFunc) {
	lifecycle.mtx.Lock()
	lifecycle.closers = append(lifecycle.closers, &closer{closerFunc: closerFunc, title: title})
	lifecycle.mtx.Unlock()
}

func Terminate() {
	lifecycle.terminate(syscall.SIGKILL)
}

func (s *service) terminate(sig os.Signal) {
	lifecycleHandler.HandleInfoMessage(fmt.Sprintf("Terminating service (handling signal - %v)", sig))
	s.mtx.Lock()
	for i := len(s.closers) - 1; i >= 0; i-- {
		closer := s.closers[i]
		lifecycleHandler.HandleInfoMessage(fmt.Sprintf("closing %s", closer.title))
		err := closer.closerFunc()
		if err != nil {
			lifecycleHandler.HandleResourceClosingError(closer.title, err)
		}
		lifecycleHandler.HandleInfoMessage(fmt.Sprintf("closed %s", closer.title))
	}
	s.mtx.Unlock()
	lifecycleHandler.HandleInfoMessage("Service termination finished")
	s.terminatedChannel <- true
}
