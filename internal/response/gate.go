// Package response validates bounded quarantined objects and produces only the
// contracted representation. This establishes structure and projection, not truth.
package response

import (
	"encoding/json"
	"errors"

	"github.com/kolygri/zero-trust-mcp-gateway/internal/core"
	"github.com/kolygri/zero-trust-mcp-gateway/internal/protocol"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

type Gate struct{}

func New() *Gate { return &Gate{} }

func (g *Gate) Release(tool core.Tool, raw json.RawMessage) (json.RawMessage, error) {
	if tool.MaxResultBytes <= 0 || int64(len(raw)) > tool.MaxResultBytes {
		return nil, errors.New("result exceeds quarantine bound")
	}
	var result map[string]any
	if err := protocol.StrictJSON(raw, &result); err != nil {
		return nil, errors.New("malformed result")
	}
	if result["resultType"] != "complete" || result["isError"] == true {
		return nil, errors.New("result not complete")
	}
	for key := range result {
		switch key {
		case "resultType", "isError", "content", "structuredContent", "_meta":
		default:
			return nil, errors.New("unsupported result field")
		}
	}
	if v, exists := result["isError"]; exists {
		if _, ok := v.(bool); !ok {
			return nil, errors.New("invalid result status")
		}
	}
	if content, exists := result["content"]; exists {
		items, ok := content.([]any)
		if !ok {
			return nil, errors.New("invalid result content")
		}
		for _, item := range items {
			block, ok := item.(map[string]any)
			if !ok || block["type"] != "text" {
				return nil, errors.New("unsupported content type")
			}
			if _, ok := block["text"].(string); !ok {
				return nil, errors.New("invalid text content")
			}
		}
	}
	object, ok := result["structuredContent"].(map[string]any)
	if !ok {
		return nil, errors.New("structured content required")
	}
	if len(tool.ReleaseFields) == 0 {
		return nil, errors.New("release contract missing")
	}
	projected := map[string]any{}
	for _, field := range tool.ReleaseFields {
		if field == "" {
			return nil, errors.New("invalid release contract")
		}
		if value, exists := object[field]; exists {
			projected[field] = value
		}
	}
	var schema any
	if protocol.StrictJSON(tool.OutputSchema, &schema) != nil || !closedSchema(schema) {
		return nil, errors.New("closed output schema required")
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("urn:gateway:output", schema); err != nil {
		return nil, errors.New("invalid output schema")
	}
	compiled, err := compiler.Compile("urn:gateway:output")
	if err != nil {
		return nil, errors.New("invalid output schema")
	}
	if err := compiled.Validate(projected); err != nil {
		return nil, errors.New("output schema violation")
	}
	encoded, err := json.Marshal(projected)
	if err != nil {
		return nil, errors.New("unencodable output")
	}
	safe := map[string]any{
		"resultType": "complete", "structuredContent": projected, "content": []any{map[string]any{"type": "text", "text": string(encoded)}}, "isError": false,
		"_meta": map[string]any{"io.zerotrustgateway/projectionApplied": true, "io.zerotrustgateway/integrity": "untrusted"},
	}
	return json.Marshal(safe)
}

// Every object is closed and external schema resolution is disabled. Arbitrary
// untyped nested JSON would permit a field whitelist to hide a second channel.
func closedSchema(value any) bool {
	m, ok := value.(map[string]any)
	if !ok {
		return false
	}
	if ref, ok := m["$ref"].(string); ok && (len(ref) == 0 || ref[0] != '#') {
		return false
	}
	if dynamic, ok := m["$dynamicRef"].(string); ok && (len(dynamic) == 0 || dynamic[0] != '#') {
		return false
	}
	if typ, ok := m["type"].(string); ok && typ == "object" {
		if m["additionalProperties"] != false {
			return false
		}
	}
	hasArrayType := m["type"] == "array"
	if types, ok := m["type"].([]any); ok {
		for _, typ := range types {
			if typ == "array" {
				hasArrayType = true
			}
		}
	}
	if hasArrayType {
		items, exists := m["items"]
		if !exists || items == true {
			return false
		}
	}
	if types, ok := m["type"].([]any); ok {
		for _, t := range types {
			if t == "object" && m["additionalProperties"] != false {
				return false
			}
		}
	}
	for key, v := range m {
		switch key {
		case "properties", "$defs", "definitions", "patternProperties":
			entries, ok := v.(map[string]any)
			if !ok {
				return false
			}
			for _, nested := range entries {
				if !closedSchema(nested) {
					return false
				}
			}
		case "items", "contains", "not", "if", "then", "else", "additionalProperties", "unevaluatedProperties":
			if _, boolean := v.(bool); !boolean {
				if !closedSchema(v) {
					return false
				}
			}
		case "allOf", "anyOf", "oneOf", "prefixItems":
			entries, ok := v.([]any)
			if !ok {
				return false
			}
			for _, nested := range entries {
				if !closedSchema(nested) {
					return false
				}
			}
		}
	}
	// All leaf values must declare a concrete type, use a local reference, or be a
	// composed schema. An empty schema would authorise arbitrary nested payloads.
	if _, ok := m["type"]; !ok {
		for _, key := range []string{"$ref", "$dynamicRef", "allOf", "anyOf", "oneOf"} {
			if _, exists := m[key]; exists {
				return true
			}
		}
		return false
	}
	return true
}
