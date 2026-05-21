package models

import "sort"

type PackageInfo struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Private   bool   `json:"private,omitempty"`
}

func SortPackages(pkgs []PackageInfo) {
	sort.Slice(pkgs, func(a, b int) bool {
		if pkgs[a].Ecosystem != pkgs[b].Ecosystem {
			return pkgs[a].Ecosystem < pkgs[b].Ecosystem
		}
		if pkgs[a].Name != pkgs[b].Name {
			return pkgs[a].Name < pkgs[b].Name
		}
		return pkgs[a].Version < pkgs[b].Version
	})
}
