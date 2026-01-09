package web

import (
	"embed"
	"io/fs"
	"os"
)

//go:embed *.html *.txt
var FS embed.FS

const Prefix = "web"

func Asset(name string) ([]byte, error) {
	return fs.ReadFile(FS, name)
}

func AssetDir(name string) ([]string, error) {
	entries, err := fs.ReadDir(FS, name)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}

func AssetNames() []string {
	var names []string
	fs.WalkDir(FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			names = append(names, path)
		}
		return nil
	})
	return names
}

func AssetInfo(name string) (os.FileInfo, error) {
	return fs.Stat(FS, name)
}
