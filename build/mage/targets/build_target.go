package targets

import (
	"strings"

	"github.com/ctrl-cmd/gobuild"
)

// ldFlags returns linker flags passed to Go command.
func ldFlags() string {
	flags := []string{"-X main.version=" + getVersion()}
	return strings.Join(flags, " ")
}

// Install installs pks server using `go install`.
func Install() error {
	return gobuild.RunInstall("-ldflags", ldFlags(), "./cmd/pks/")
}

// Build builds pks binary using `go build`.
func Build() error {
	return gobuild.RunBuild("-ldflags", ldFlags(), "./cmd/pks/")
}
