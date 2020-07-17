package targets

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ctrl-cmd/gobuild"
)

const packageName = "spks"

func getPackageFile(name, ext string) string {
	if ext != "" {
		return fmt.Sprintf("%s-%s.%s", packageName, getVersion(), ext)
	}
	return fmt.Sprintf("%s-%s", packageName, getVersion())
}

func getReleaseDir() string {
	dir := filepath.Join("release", getVersion())
	if err := os.MkdirAll(dir, 0750); err != nil {
		return ""
	}
	return dir
}

func getVersion() string {
	// Attempt to get git details.
	d, err := gobuild.GitDescribe()
	if err == nil {
		v, err := d.GetSemver()
		if err == nil {
			return v.String()
		}
	}
	return "devel"
}
