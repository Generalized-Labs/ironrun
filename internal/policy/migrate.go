package policy

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// MigrateV1ToV2 rewrites alias references to direct encrypted environment
// entry names. It uses yaml.Node so comments survive the migration.
func MigrateV1ToV2(data []byte) ([]byte, map[string]string, error) {
	f, err := Parse(data)
	if err != nil {
		return nil, nil, err
	}
	if f.Version != SupportedVersionV1 {
		return nil, nil, fmt.Errorf("policy migration requires version 1, got %q", f.Version)
	}
	mapping := make(map[string]string, len(f.Secrets))
	targets := map[string]string{}
	for alias, secret := range f.Secrets {
		if previous, exists := targets[secret.Env]; exists && previous != alias {
			return nil, nil, fmt.Errorf("aliases %q and %q both target %q; resolve this before migration", previous, alias, secret.Env)
		}
		targets[secret.Env] = alias
		mapping[alias] = secret.Env
	}

	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, nil, err
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, nil, fmt.Errorf("policy root must be a mapping")
	}
	root := document.Content[0]
	setScalar(root, "version", SupportedVersionV2)
	setScalar(root, "environment_set", "active")
	commands := mappingValue(root, "commands")
	if commands == nil || commands.Kind != yaml.SequenceNode {
		return nil, nil, fmt.Errorf("policy commands must be a sequence")
	}
	for _, command := range commands.Content {
		if command.Kind != yaml.MappingNode {
			continue
		}
		secrets := mappingValue(command, "secrets")
		if secrets == nil {
			continue
		}
		for _, item := range secrets.Content {
			if target, ok := mapping[item.Value]; ok {
				item.Value = target
			}
		}
	}
	deleteMappingKey(root, "secrets")

	var out bytes.Buffer
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(&document); err != nil {
		return nil, nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, nil, err
	}
	if _, err := Parse(out.Bytes()); err != nil {
		return nil, nil, fmt.Errorf("migrated policy is invalid: %w", err)
	}
	return out.Bytes(), mapping, nil
}

func mappingValue(mapping *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func setScalar(mapping *yaml.Node, key, value string) {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			mapping.Content[i+1].Kind = yaml.ScalarNode
			mapping.Content[i+1].Tag = "!!str"
			mapping.Content[i+1].Value = value
			mapping.Content[i+1].Style = yaml.DoubleQuotedStyle
			return
		}
	}
	mapping.Content = append(mapping.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value},
	)
}

func deleteMappingKey(mapping *yaml.Node, key string) {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			mapping.Content = append(mapping.Content[:i], mapping.Content[i+2:]...)
			return
		}
	}
}
