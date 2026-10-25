package route

import (
	_ "embed"
	"strings"
)

//go:embed whitelist.txt
var whitelistTxt string

// Default builds the decision table from the embedded starter whitelist.
// User rules are expected to be layered on top via AddDirect/AddProxy.
func Default() *Table {
	t := New()
	for _, line := range strings.Split(whitelistTxt, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		t.AddDirect(line)
	}
	return t
}

// ParseList splits a newline- or comma-separated user list into clean rules.
// Empty entries are dropped, so a textarea from the app can be passed as-is.
func ParseList(raw string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == ',' || r == ';' || r == '\r'
	}) {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
