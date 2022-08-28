package definition

import "errors"

type IProjectScanner interface {
	Scan(ecosystem string, fileContent []byte) ([]Vulnerability, error)
	Close() error
}

var (
	ErrUnsupportedEcosystem = errors.New("unsupported ecosystem")
	ErrInvalidProjectFile   = errors.New("invalid project file")
)
