package surituner

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

var ifaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

func validateIfaceArg(iface string) error {
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return fmt.Errorf("--iface is required")
	}
	if !ifaceNamePattern.MatchString(iface) {
		return fmt.Errorf("invalid --iface %q: only letters, digits, '.', '_', ':', '-' are allowed", iface)
	}
	return nil
}

func validatePathArg(flagName string, path string, requireAbs bool) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	if strings.ContainsAny(path, "\x00\r\n") {
		return fmt.Errorf("invalid %s: path contains control characters", flagName)
	}
	if requireAbs && !filepath.IsAbs(path) {
		return fmt.Errorf("invalid %s: absolute path is required", flagName)
	}
	return nil
}

func validateStateSelector(path string) error {
	path = strings.TrimSpace(path)
	if path == "" || path == "latest" {
		return nil
	}
	return validatePathArg("--state", path, true)
}
