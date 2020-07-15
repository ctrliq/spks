package targets

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/ctrl-cmd/gobuild"
	"github.com/magefile/mage/mg"
)

type Package mg.Namespace

const (
	nfpmConf = "./build/packaging/nfpm.yaml"
)

// Tgz creates a release tar gzipped archive.
func (Package) Tgz() error {
	releaseDir := getReleaseDir()

	archive, err := gobuild.NewGitArchive(getPackageFile(packageName, ""))
	if err != nil {
		return err
	}
	path := filepath.Join(releaseDir, getPackageFile(packageName, "tgz"))
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return archive.Create(gobuild.TgzArchive, f)
}

// Zip creates a release zip archive.
func (Package) Zip() error {
	releaseDir := getReleaseDir()

	archive, err := gobuild.NewGitArchive(getPackageFile(packageName, ""))
	if err != nil {
		return err
	}
	path := filepath.Join(releaseDir, getPackageFile(packageName, "zip"))

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return archive.Create(gobuild.ZipArchive, f)
}

// Deb builds a deb package.
func (Package) Deb() error {
	releaseDir := getReleaseDir()

	mg.Deps(Build)

	config, err := os.Open(nfpmConf)
	if err != nil {
		return err
	}
	p, err := gobuild.NewPackage(config, gobuild.DEB, getVersion(), runtime.GOARCH)
	if err != nil {
		return err
	}

	f, err := os.Create(filepath.Join(releaseDir, p.Info.Target))
	if err != nil {
		return err
	}
	defer f.Close()

	return p.Create(f)
}

// RPM builds a RPM package.
func (Package) RPM() error {
	releaseDir := getReleaseDir()

	mg.Deps(Build)

	config, err := os.Open(nfpmConf)
	if err != nil {
		return err
	}
	p, err := gobuild.NewPackage(config, gobuild.RPM, getVersion(), runtime.GOARCH)
	if err != nil {
		return err
	}

	f, err := os.Create(filepath.Join(releaseDir, p.Info.Target))
	if err != nil {
		return err
	}
	defer f.Close()

	return p.Create(f)
}
