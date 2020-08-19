package targets

import (
	"os"
	"strings"

	"github.com/ctrl-cmd/gobuild"
)

func ArchFromDockerPlatform(platform string) string {
	switch platform {
	case "linux/amd64":
		return "amd64"
	case "linux/386":
		return "386"
	case "linux/arm/v6":
		return "arm"
	case "linux/arm/v7":
		return "arm"
	case "linux/arm64":
		return "arm64"
	case "linux/ppc64le":
		return "ppc64le"
	case "linux/s390x":
		return "s390x"
	}
	return ""
}

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
	if os.Getenv("TARGETPLATFORM") != "" {
		os.Setenv("GOARCH", ArchFromDockerPlatform(os.Getenv("TARGETPLATFORM")))
	}
	return gobuild.RunInstall("-ldflags", ldFlags(), "./cmd/spks/")
}

// Build builds pks binary using `go build`.
func Build() error {
	// for static build
	os.Setenv("CGO_ENABLED", "0")
	if os.Getenv("TARGETPLATFORM") != "" {
		os.Setenv("GOARCH", ArchFromDockerPlatform(os.Getenv("TARGETPLATFORM")))
	}
	return gobuild.RunBuild("-o", "./build/spks", "-ldflags", ldFlags(), "./cmd/spks/")
}

func init() {

}
