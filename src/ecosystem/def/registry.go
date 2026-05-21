package def

import (
	"fmt"
	"sort"
)

var ecosystems = make(map[string]Ecosystem)

func Names() []string {
	all := All()
	result := make([]string, 0, len(all))
	for _, eco := range all {
		result = append(result, eco.Name())
	}
	sort.Strings(result)
	return result
}

func RegisterEcosystem(eco Ecosystem) {
	name := eco.Name()
	if name == "" {
		panic("ecosystem must have a name")
	}
	if _, exists := ecosystems[name]; exists {
		panic(fmt.Sprintf("ecosystem %q already registered", name))
	}
	ecosystems[name] = eco
}

func Get(name string) (Ecosystem, error) {
	if eco, ok := ecosystems[name]; ok {
		return eco, nil
	}
	return nil, fmt.Errorf("unsupported ecosystem: %q (supported: %v)", name, Names())
}

func All() []Ecosystem {
	result := make([]Ecosystem, 0, len(ecosystems))
	for _, eco := range ecosystems {
		result = append(result, eco)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name() < result[j].Name()
	})
	return result
}
