package targets

import (
	"os"

	"github.com/ctrl-cmd/gobuild"
	"github.com/magefile/mage/mg"
)

type Test mg.Namespace

// Integration runs integration and unit tests using `go test`.
func (Test) Integration() error {
	// re-enable CGO required by -race flag
	os.Setenv("CGO_ENABLED", "1")
	return gobuild.RunIntegration("./pkg/...", "./internal/...")
}

// Unit runs unit tests using `go test`.
func (Test) Unit() error {
	// re-enable CGO required by -race flag
	os.Setenv("CGO_ENABLED", "1")
	return gobuild.RunUnitTest("./pkg/...", "./internal/...")
}
