package fuzzy

import (
	"strings"
	"unicode"
)

func Normalize(value string) string {
	var builder strings.Builder
	builder.Grow(len(value))
	for _, r := range strings.ToLower(value) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func Match(value, query string) bool {
	if query == "" {
		return true
	}
	return strings.Contains(Normalize(value), Normalize(query))
}
