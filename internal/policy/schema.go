package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/kolygri/zero-trust-mcp-gateway/internal/core"
	"github.com/kolygri/zero-trust-mcp-gateway/internal/protocol"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const schemaURL = "urn:zero-trust-gateway:schema"

func compileSchema(raw json.RawMessage, closed bool) (*jsonschema.Schema, error) {
	if len(raw) == 0 || len(raw) > 256<<10 {
		return nil, errors.New("bounded inline object schema required")
	}
	var value map[string]any
	if err := protocol.StrictJSON(raw, &value); err != nil || value == nil {
		return nil, errors.New("schema must be an unambiguous JSON object")
	}
	if value["type"] != "object" {
		return nil, errors.New("top-level schema type must be object")
	}
	if closed && value["additionalProperties"] != false {
		return nil, errors.New("input schema must set additionalProperties=false")
	}
	if err := localSchema(value); err != nil {
		return nil, err
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	if err := compiler.AddResource(schemaURL, value); err != nil {
		return nil, fmt.Errorf("invalid schema: %w", err)
	}
	result, err := compiler.Compile(schemaURL)
	if err != nil {
		return nil, errors.New("schema compilation failed")
	}
	return result, nil
}

func localSchema(v any) error {
	switch val := v.(type) {
	case map[string]any:
		for k, item := range val {
			if k == "$id" {
				return errors.New("schema $id is unsupported; use local definitions")
			}
			if k == "$ref" || k == "$dynamicRef" {
				s, ok := item.(string)
				if !ok || !strings.HasPrefix(s, "#") {
					return errors.New("external schema references are forbidden")
				}
			}
			if k == "$schema" && item != "https://json-schema.org/draft/2020-12/schema" {
				return errors.New("only JSON Schema draft 2020-12 is supported")
			}
			if err := localSchema(item); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range val {
			if err := localSchema(item); err != nil {
				return err
			}
		}
	}
	return nil
}

func ValidateArguments(t core.Tool, arguments json.RawMessage) error {
	schema, err := compileSchema(t.InputSchema, true)
	if err != nil {
		return err
	}
	var value any
	if err := protocol.StrictJSON(arguments, &value); err != nil {
		return err
	}
	if err := schema.Validate(value); err != nil {
		return errors.New("arguments violate the approved input schema")
	}
	return nil
}

// ValidateOutput validates the complete quarantined structured content before
// projection; successful validation establishes shape, not factual correctness.
func ValidateOutput(t core.Tool, output json.RawMessage) error {
	schema, err := compileSchema(t.OutputSchema, false)
	if err != nil {
		return err
	}
	var value any
	if err := protocol.StrictJSON(output, &value); err != nil {
		return err
	}
	if err := schema.Validate(value); err != nil {
		return errors.New("result violates the approved output schema")
	}
	return nil
}
