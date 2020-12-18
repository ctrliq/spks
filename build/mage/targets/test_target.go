package targets

import (
	"github.com/ctrliq/gobuild"
	"github.com/magefile/mage/mg"
)

type Test mg.Namespace

// Integration runs integration and unit tests using `go test`.
func (Test) Integration() error {
	return gobuild.RunIntegration("./pkg/...", "./internal/...")
}

// Unit runs unit tests using `go test`.
func (Test) Unit() error {
	return gobuild.RunUnitTest("./pkg/...", "./internal/...")
}
