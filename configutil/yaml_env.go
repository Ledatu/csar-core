package configutil

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

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
	if node == nil {
		return
	}

	switch node.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for i := range node.Content {
			expandEnvInYAMLNode(node.Content[i])
		}
	case yaml.MappingNode:
		for i := 1; i < len(node.Content); i += 2 {
			expandEnvInYAMLNode(node.Content[i])
		}
	case yaml.ScalarNode:
		if node.Value == "" {
			return
		}
		expanded := SafeExpandEnv(node.Value)
		if expanded != node.Value {
			node.Value = expanded
			node.Tag = scalarYAMLTag(expanded)
		}
	case yaml.AliasNode:
		expandEnvInYAMLNode(node.Alias)
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
