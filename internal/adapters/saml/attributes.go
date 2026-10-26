package saml

import (
	"fmt"
	"log/slog"
	"slices"
	"strings"

	samllib "github.com/crewjam/saml"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
)


const (
	locSAMLAttribute = "saml_attribute"

	attrNameFormatBasic       = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
	attrNameFormatURI         = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
	attrNameFormatUnspecified = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
)

type attrMapper struct {
	source     string
	name       string
	nameFormat string
	friendly   string
}

func parseAttrMapper(raw map[string]interface{}, protocol domain.ClientScopeProtocol) (attrMapper, bool) {
	src, _ := raw["source_attribute"].(string)
	name, _ := raw["claim_name"].(string)
	if src == "" || strings.TrimSpace(name) == "" {
		return attrMapper{}, false
	}
	var locs []string
	switch v := raw["token_location"].(type) {
	case string:
		locs = []string{v}
	case []interface{}:
		for _, x := range v {
			if s, ok := x.(string); ok {
				locs = append(locs, s)
			}
		}
	case []string:
		locs = v
	}
	if len(locs) == 0 && protocol == domain.ClientScopeProtocolSAML2 {
		locs = []string{locSAMLAttribute}
	}
	if !slices.Contains(locs, locSAMLAttribute) {
		return attrMapper{}, false
	}
	m := attrMapper{source: src, name: name, nameFormat: attrNameFormatBasic}
	switch f, _ := raw["saml_name_format"].(string); strings.ToLower(f) {
	case "", "basic", strings.ToLower(attrNameFormatBasic):
	case "uri", strings.ToLower(attrNameFormatURI):
		m.nameFormat = attrNameFormatURI
	case "unspecified", strings.ToLower(attrNameFormatUnspecified):
		m.nameFormat = attrNameFormatUnspecified
	default:
		return attrMapper{}, false
	}
	m.friendly, _ = raw["saml_friendly_name"].(string)
	return m, true
}

// buildAttributes returns the attributes of the assertion, in a stable
// order (scopes as the core returned them, mappers in their order).
func buildAttributes(as *core.IdentityAssertion, app *domain.ClientApp, log *slog.Logger) []samllib.Attribute {
	var out []samllib.Attribute
	index := map[string]int{} // attribute name -> position in out
	for _, cs := range as.Scopes {
		if cs.Protocol != domain.ClientScopeProtocolSAML2 && cs.Protocol != domain.ClientScopeProtocolBoth {
			continue
		}
		for _, raw := range cs.ClaimMappers {
			m, ok := parseAttrMapper(raw, cs.Protocol)
			if !ok {
				continue
			}
			values := attributeValues(as.UserAttributes[m.source])
			if len(values) == 0 {
				continue
			}
			if i, dup := index[m.name]; dup {
				// Two scopes map the same attribute: merge the values.
				for _, v := range values {
					if !slices.ContainsFunc(out[i].Values, func(x samllib.AttributeValue) bool { return x.Value == v }) {
						out[i].Values = append(out[i].Values, samllib.AttributeValue{Type: "xs:string", Value: v})
					}
				}
				continue
			}
			attr := samllib.Attribute{Name: m.name, NameFormat: m.nameFormat, FriendlyName: m.friendly}
			for _, v := range values {
				attr.Values = append(attr.Values, samllib.AttributeValue{Type: "xs:string", Value: v})
			}
			index[m.name] = len(out)
			out = append(out, attr)
		}
	}
	return applyRenames(out, app.AttributeMappings, app.EntityID, log)
}

// applyRenames applies Client.attribute_mappings ({"from": "to"}) in a
// stable order. A rename that would overwrite another attribute is skipped.
func applyRenames(attrs []samllib.Attribute, mappings map[string]interface{}, entityID string, log *slog.Logger) []samllib.Attribute {
	froms := make([]string, 0, len(mappings))
	for from := range mappings {
		froms = append(froms, from)
	}
	slices.Sort(froms)
	for _, from := range froms {
		to, _ := mappings[from].(string)
		if to == "" || to == from {
			continue
		}
		i := slices.IndexFunc(attrs, func(a samllib.Attribute) bool { return a.Name == from })
		if i < 0 {
			continue
		}
		if slices.ContainsFunc(attrs, func(a samllib.Attribute) bool { return a.Name == to }) {
			log.Warn("saml: attribute_mappings would overwrite an attribute, ignored",
				"entity_id", entityID, "from", from, "to", to)
			continue
		}
		attrs[i].Name = to
	}
	return attrs
}

// attributeValues turns a user attribute into SAML string values. A list
// (groups, roles) becomes a multi-valued attribute.
func attributeValues(v any) []string {
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		if x == "" {
			return nil
		}
		return []string{x}
	case []string:
		return slices.DeleteFunc(slices.Clone(x), func(s string) bool { return s == "" })
	case []interface{}:
		out := make([]string, 0, len(x))
		for _, e := range x {
			out = append(out, attributeValues(e)...)
		}
		return out
	case bool, int, int32, int64, float64:
		return []string{fmt.Sprint(x)}
	default:
		return []string{fmt.Sprint(x)}
	}
}
