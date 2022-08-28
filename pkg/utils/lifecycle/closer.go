package lifecycle

type CloserFunc func() error

type closer struct {
	title      string
	closerFunc CloserFunc
}
