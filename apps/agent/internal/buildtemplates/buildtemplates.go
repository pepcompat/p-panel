// Package buildtemplates holds the agent-embedded Dockerfile templates for
// image.build with `template` (docs/AGENT_PROTOCOL.md "Builds (P4b)"). The
// agent writes the chosen template into the build context as Dockerfile.ppanel;
// templates are never fetched from the Center or the repository.
package buildtemplates

import (
	"embed"
	"fmt"
	"sort"
)

//go:embed nextjs/Dockerfile nestjs/Dockerfile laravel/Dockerfile
var files embed.FS

// FileName is the Dockerfile name used inside the build context.
const FileName = "Dockerfile.ppanel"

// Names mirrors DOCKERFILE_TEMPLATES in packages/shared-contracts.
var Names = []string{"nextjs", "nestjs", "laravel"}

// Get returns the embedded Dockerfile for name.
func Get(name string) ([]byte, error) {
	i := sort.SearchStrings(sorted, name)
	if i >= len(sorted) || sorted[i] != name {
		return nil, fmt.Errorf("unknown Dockerfile template %q", name)
	}
	return files.ReadFile(name + "/Dockerfile")
}

// Valid reports whether name is a known template.
func Valid(name string) bool {
	_, err := Get(name)
	return err == nil
}

var sorted = func() []string {
	s := append([]string(nil), Names...)
	sort.Strings(s)
	return s
}()
