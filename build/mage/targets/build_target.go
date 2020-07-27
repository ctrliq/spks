package targets

import (
	"os"
	"strings"

	"github.com/ctrl-cmd/gobuild"
)

// ldFlags returns linker flags passed to Go command.
func ldFlags() string {
	flags := []string{
		"-X main.version=" + getVersion(),
		"-s -w",
	}
	return strings.Join(flags, " ")
}

// Install installs pks server using `go install`.
func Install() error {
	// for static build
	os.Setenv("CGO_ENABLED", "0")
	if os.Getenv("BUILD_GOARCH") != "" {
		os.Setenv("GOARCH", os.Getenv("BUILD_GOARCH"))
	}
	return gobuild.RunInstall("-ldflags", ldFlags(), "./cmd/spks/")
}

// Build builds pks binary using `go build`.
func Build() error {
	// for static build
	os.Setenv("CGO_ENABLED", "0")
	if os.Getenv("BUILD_GOARCH") != "" {
		os.Setenv("GOARCH", os.Getenv("BUILD_GOARCH"))
	}
	return gobuild.RunBuild("-o", "./build/spks", "-ldflags", ldFlags(), "./cmd/spks/")
}

func init() {

}
