package configutil

import (
	"bytes"
	"fmt"
	"io"
	"slices"

	"gopkg.in/yaml.v3"
)

// UnmarshalYAMLWithEnvStrictSections preserves legacy field decoding outside
// the named security blocks. Such blocks must be explicit mappings, never null,
// aliases or merged defaults. Their types use DecodeStrictYAML for known fields.
// Security configuration accepts exactly one document, including when disabled.
func UnmarshalYAMLWithEnvStrictSections(data []byte, out any, sections ...string) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var root, extra yaml.Node
	if err := decoder.Decode(&root); err == io.EOF {
		return nil
	} else if err != nil {
		return fmt.Errorf("invalid configuration YAML")
	}
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("configuration requires exactly one YAML document")
	}
	if len(root.Content) != 1 {
		return fmt.Errorf("invalid configuration document")
	}
	if !acyclicYAML(&root, make(map[*yaml.Node]uint8)) {
		return fmt.Errorf("configuration contains cyclic aliases")
	}
	mapping := root.Content[0]
	for i := 0; mapping.Kind == yaml.MappingNode && i < len(mapping.Content); i += 2 {
		key, value := mapping.Content[i], mapping.Content[i+1]
		if slices.Contains(sections, key.Value) {
			if value.Kind != yaml.MappingNode || !plainYAML(value) {
				return fmt.Errorf("security configuration requires explicit unaliased mappings")
			}
		}
		if key.Tag == "!!merge" && containsYAMLKey(&root, sections, make(map[*yaml.Node]bool)) {
			return fmt.Errorf("security configuration cannot inherit root defaults")
		}
	}
	expandEnvYAMLNode(&root, make(map[*yaml.Node]bool))
	if err := root.Decode(out); err != nil {
		// Decoder errors may include configured values; never echo them from
		// security configuration, including malformed URL/path declarations.
		return fmt.Errorf("invalid configuration fields")
	}
	return nil
}

// DecodeStrictYAML is for new security-config types' UnmarshalYAML methods.
// Pass an alias of the destination type to avoid recursively calling the method.
func DecodeStrictYAML(node *yaml.Node, out any) error {
	if node == nil || node.Kind != yaml.MappingNode || !plainYAML(node) {
		return fmt.Errorf("security configuration requires an explicit mapping")
	}
	data, err := yaml.Marshal(node)
	if err != nil {
		return fmt.Errorf("invalid security configuration")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("invalid security configuration fields")
	}
	return nil
}

func plainYAML(node *yaml.Node) bool {
	if node.Kind == yaml.AliasNode || node.Anchor != "" || node.Tag == "!!merge" || node.Tag == "!!null" {
		return false
	}
	for _, child := range node.Content {
		if !plainYAML(child) {
			return false
		}
	}
	return true
}

func containsYAMLKey(node *yaml.Node, keys []string, seen map[*yaml.Node]bool) bool {
	if node == nil || seen[node] {
		return false
	}
	seen[node] = true
	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			if slices.Contains(keys, node.Content[i].Value) {
				return true
			}
		}
	}
	if containsYAMLKey(node.Alias, keys, seen) {
		return true
	}
	for _, child := range node.Content {
		if containsYAMLKey(child, keys, seen) {
			return true
		}
	}
	return false
}

func acyclicYAML(node *yaml.Node, states map[*yaml.Node]uint8) bool {
	if node == nil || states[node] == 2 {
		return true
	}
	if states[node] == 1 {
		return false
	}
	states[node] = 1
	if !acyclicYAML(node.Alias, states) {
		return false
	}
	for _, child := range node.Content {
		if !acyclicYAML(child, states) {
			return false
		}
	}
	states[node] = 2
	return true
}

// UnmarshalYAMLWithEnv parses YAML into a node tree, expands environment
// variable references in scalar values, then decodes into out.
//
// Expansion happens before typed decoding so placeholders such as
// "${TTL:-5m}" can populate duration, bool, int, and other typed fields.
// Mapping keys are not expanded so route paths and field names stay structural.
func UnmarshalYAMLWithEnv(data []byte, out any) error {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return err
	}
	expandEnvInYAMLNode(&root)
	if err := root.Decode(out); err != nil {
		return fmt.Errorf("decoding config: %w", err)
	}
	return nil
}

func expandEnvInYAMLNode(node *yaml.Node) {
	expandEnvYAMLNode(node, nil)
}

func expandEnvYAMLNode(node *yaml.Node, seen map[*yaml.Node]bool) {
	if node == nil {
		return
	}
	if seen != nil {
		if seen[node] {
			return
		}
		seen[node] = true
	}

	switch node.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for i := range node.Content {
			expandEnvYAMLNode(node.Content[i], seen)
		}
	case yaml.MappingNode:
		for i := 1; i < len(node.Content); i += 2 {
			expandEnvYAMLNode(node.Content[i], seen)
		}
	case yaml.ScalarNode:
		if node.Value == "" {
			return
		}
		expanded := SafeExpandEnv(node.Value)
		if expanded != node.Value {
			node.Value = expanded
			node.Tag = scalarYAMLTag(expanded)
			if node.Tag != "!!str" {
				// A quoted placeholder may become a typed bool/null. Preserve
				// that type when a strict subtree is encoded for KnownFields.
				node.Style = 0
			}
		}
	case yaml.AliasNode:
		expandEnvYAMLNode(node.Alias, seen)
	}
}

func scalarYAMLTag(value string) string {
	switch value {
	case "true", "false":
		return "!!bool"
	case "null", "~":
		return "!!null"
	}
	return "!!str"
}
