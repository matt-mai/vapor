package contents

import "gopkg.in/yaml.v3"

// UnmarshalYAML accepts a bare package name beside the full mapping, so an unpinned
// package is one line: `- openssl`. The name and version checks run later, on the
// decoded request, so both forms reach validation alike.
func (r *PackageRequest) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		r.Name = node.Value
		return nil
	}
	type plain PackageRequest
	return node.Decode((*plain)(r))
}
