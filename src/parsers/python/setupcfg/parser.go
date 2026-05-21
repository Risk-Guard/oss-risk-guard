package setupcfg

import (
	"strings"

	"gopkg.in/ini.v1"
)

type NameResult struct {
	Name          *string
	IsDynamic     bool
	DynamicReason string
}

func (nr NameResult) GetName() *string         { return nr.Name }
func (nr NameResult) GetIsDynamic() bool       { return nr.IsDynamic }
func (nr NameResult) GetDynamicReason() string { return nr.DynamicReason }

func ParseName(content string) NameResult {
	cfg, err := ini.LoadSources(ini.LoadOptions{
		AllowPythonMultilineValues: true,
		SkipUnrecognizableLines:    true,
	}, []byte(content))
	if err != nil {
		return NameResult{}
	}

	metadata := cfg.Section("metadata")
	if metadata == nil {
		return NameResult{}
	}

	nameKey := metadata.Key("name")
	if nameKey == nil {
		return NameResult{}
	}

	name := strings.TrimSpace(nameKey.String())
	if name == "" {
		return NameResult{}
	}

	if strings.HasPrefix(name, "attr:") || strings.HasPrefix(name, "file:") {
		return NameResult{
			IsDynamic:     true,
			DynamicReason: "name uses dynamic directive: " + name,
		}
	}

	return NameResult{Name: &name}
}
