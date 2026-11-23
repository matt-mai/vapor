package ui

import (
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

var urlPattern = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://\S+`)

type replacement struct {
	start, end int
	text       string
}

func (r *Reporter) replacements(text string) []replacement {
	var spans []replacement
	for _, secret := range r.secrets {
		if secret == "" {
			continue
		}
		for offset := 0; offset < len(text); {
			index := strings.Index(text[offset:], secret)
			if index < 0 {
				break
			}
			start := offset + index
			spans = append(spans, replacement{start, start + len(secret), "[redacted]"})
			offset = start + 1
		}
	}
	for _, loc := range urlPattern.FindAllStringIndex(text, -1) {
		spans = append(spans, replacement{loc[0], loc[1], cleanURL(text[loc[0]:loc[1]])})
	}
	slices.SortFunc(spans, func(a, b replacement) int { return a.start - b.start })
	return spans
}

func cleanURL(raw string) string {
	// Ambiguous tokens (including adjacent URLs) are safer to hide in full.
	if strings.Count(raw, "://") != 1 {
		return "[redacted URL]"
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "[redacted URL]"
	}
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	return u.String()
}

func (r *Reporter) redact(text string) string {
	spans := r.replacements(text)
	var out strings.Builder
	cursor := 0
	for i := 0; i < len(spans); i++ {
		current := spans[i]
		// Union original-byte matches; substitutions must not hide later matches.
		for i+1 < len(spans) && spans[i+1].start < current.end {
			i++
			current.end = max(current.end, spans[i].end)
			current.text = "[redacted]"
		}
		out.WriteString(text[cursor:current.start])
		out.WriteString(current.text)
		cursor = current.end
	}
	out.WriteString(text[cursor:])
	return out.String()
}

func (r *Reporter) clean(text string) string {
	return strings.Map(func(c rune) rune {
		if !unicode.IsGraphic(c) || unicode.IsControl(c) {
			return ' '
		}
		return c
	}, r.redact(text))
}
