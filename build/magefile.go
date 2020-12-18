// +build mage

package main

import (
	"log"
	"os"
	"path/filepath"
	"runtime"

	// mage:import
	_ "github.com/ctrliq/spks/build/mage/targets"
)

func init() {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		log.Fatalf("Could not determine build directory location")
	}
	os.Chdir(filepath.Join(filepath.Dir(filename), ".."))
}
