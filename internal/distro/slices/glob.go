package slices

import (
	"slices"
)

// maxGlobStates bounds the product search. Exceeding it assumes an
// intersection so validation fails closed instead of missing a conflict.
const maxGlobStates = 100_000

type globPair struct {
	first, second int
}

func globIntersects(first, second string) bool {
	a, b := []rune(first), []rune(second)
	alphabet := globAlphabet(first, second)
	start := globPair{}
	queue := []globPair{start}
	seen := map[globPair]struct{}{start: {}}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		accepted, firstStates, secondStates := globClosures(a, b, current)
		if accepted {
			return true
		}
		overBudget := globTransitions(a, b, firstStates, secondStates, alphabet, func(next globPair) bool {
			if _, exists := seen[next]; exists {
				return false
			}
			if len(seen) >= maxGlobStates {
				return true
			}
			seen[next] = struct{}{}
			queue = append(queue, next)
			return false
		})
		if overBudget {
			return true
		}
	}
	return false
}

func globClosures(a, b []rune, current globPair) (bool, []int, []int) {
	first := globClosure(a, current.first)
	second := globClosure(b, current.second)
	return globAccept(a, first) && globAccept(b, second), first, second
}

func globTransitions(a, b []rune, firstStates, secondStates []int, alphabet []rune,
	visit func(globPair) bool) bool {
	for _, char := range alphabet {
		firstNext := globAdvanceClosed(a, firstStates, char)
		secondNext := globAdvanceClosed(b, secondStates, char)
		if globVisitProduct(firstNext, secondNext, visit) {
			return true
		}
	}
	return false
}

func globVisitProduct(first, second []int, visit func(globPair) bool) bool {
	count := 0
	for _, firstState := range first {
		for _, secondState := range second {
			count++
			if count > maxGlobStates || visit(globPair{first: firstState, second: secondState}) {
				return true
			}
		}
	}
	return false
}

// A state is a bitset of pattern positions. Positions fit in one uint64 for
// paths bounded by MaxTreePathSize, but a slice keeps the code simple.
func globClosure(pattern []rune, position int) []int {
	seen := make(map[int]bool)
	var add func(int)
	add = func(pos int) {
		if seen[pos] {
			return
		}
		seen[pos] = true
		if pos >= len(pattern) {
			return
		}
		if pattern[pos] == '*' {
			if pos+1 < len(pattern) && pattern[pos+1] == '*' {
				add(pos + 2)
			} else {
				add(pos + 1)
			}
		}
	}
	add(position)
	states := make([]int, 0, len(seen))
	for pos := range seen {
		states = append(states, pos)
	}
	slices.Sort(states)
	return states
}

func globAdvanceClosed(pattern []rune, states []int, char rune) []int {
	next := make(map[int]bool)
	for _, state := range states {
		if state >= len(pattern) {
			continue
		}
		globStep(pattern, state, char, next)
	}
	merged := make([]int, 0, len(next))
	for state := range next {
		merged = append(merged, state)
	}
	slices.Sort(merged)
	closed := make([]int, 0, len(merged))
	for _, state := range merged {
		closed = append(closed, globClosure(pattern, state)...)
	}
	return uniqueInts(closed)
}

func globStep(pattern []rune, state int, char rune, next map[int]bool) {
	switch pattern[state] {
	case '*':
		if state+1 < len(pattern) && pattern[state+1] == '*' {
			next[state] = true
			return
		}
		if char != '/' {
			next[state] = true
		}
	case '?':
		if char != '/' {
			next[state+1] = true
		}
	case char:
		next[state+1] = true
	}
}

func globAccept(pattern []rune, states []int) bool {
	return slices.Contains(states, len(pattern))
}

func globAlphabet(first, second string) []rune {
	values := map[rune]bool{'/': true}
	for _, pattern := range []string{first, second} {
		for _, char := range pattern {
			if char != '*' && char != '?' {
				values[char] = true
			}
		}
	}
	for candidate := rune('a'); ; candidate++ {
		if candidate != '/' && !values[candidate] {
			values[candidate] = true
			break
		}
	}
	alphabet := make([]rune, 0, len(values))
	for char := range values {
		alphabet = append(alphabet, char)
	}
	slices.Sort(alphabet)
	return alphabet
}

func uniqueInts(values []int) []int {
	if len(values) == 0 {
		return nil
	}
	slices.Sort(values)
	return slices.Compact(values)
}

// globMatches reports whether a whole path matches a declaration pattern. The
// pattern language is upstream's: `?` is one non-slash character, `*` is zero or
// more non-slash characters and `**` also crosses slashes. Shell bracket classes
// and filepath.Match rules are deliberately not supported.
func globMatches(pattern, name string) bool {
	patternRunes := []rune(pattern)
	states := globClosure(patternRunes, 0)
	for _, char := range name {
		states = globAdvanceClosed(patternRunes, states, char)
		if len(states) == 0 {
			return false
		}
	}
	return globAccept(patternRunes, states)
}
