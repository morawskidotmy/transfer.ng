package web

import (
	"embed"
	"io/fs"
)

// FS contains the embedded web assets (HTML templates, text templates, and icons).
//
//go:embed *.html *.txt *.ico
var FS embed.FS

// Prefix is the URL path prefix for embedded web assets.
const Prefix = "web"

// Asset reads and returns the content of the named embedded file.
func Asset(name string) ([]byte, error) {
	return fs.ReadFile(FS, name)
}

// AssetNames returns the sorted list of all embedded file paths.
func AssetNames() []string {
	var names []string
	_ = fs.WalkDir(FS, ".", func(path string, d fs.DirEntry, err error) error {
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
