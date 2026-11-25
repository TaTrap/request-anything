package diff

import (
	"strconv"
	"strings"
)

// LineMatchesWildcard matches trycmd-style `[..]` inline wildcards.
func LineMatchesWildcard(expected, actual string) bool {
	if !strings.Contains(expected, "[..]") {
		return expected == actual
	}
	parts := strings.Split(expected, "[..]")
	first, last := parts[0], parts[len(parts)-1]
	if !strings.HasPrefix(actual, first) {
		return false
	}
	rest := strings.TrimPrefix(actual, first)
	if !strings.HasSuffix(rest, last) {
		return false
	}
	rest = strings.TrimSuffix(rest, last)
	for _, mid := range parts[1 : len(parts)-1] {
		idx := strings.Index(rest, mid)
		if idx < 0 {
			return false
		}
		rest = rest[idx+len(mid):]
	}
	return true
}

// LineMatchesWithin matches wildcards or numeric tolerance on a single line.
func LineMatchesWithin(expected, actual string, tol *float64) bool {
	if LineMatchesWildcard(expected, actual) {
		return true
	}
	if tol == nil || strings.Contains(expected, "[..]") {
		return false
	}
	return lineNumbersClose(expected, actual, *tol)
}

func lineNumbersClose(expected, actual string, tol float64) bool {
	en, et := splitNumbers(expected)
	an, at := splitNumbers(actual)
	if len(en) != len(an) || len(et) != len(at) {
		return false
	}
	for i := range et {
		if et[i] != at[i] {
			return false
		}
	}
	for i := range en {
		if en[i] == an[i] {
			continue
		}
		if !isFloatLexeme(en[i]) && !isFloatLexeme(an[i]) {
			return false
		}
		ef, err1 := strconv.ParseFloat(en[i], 64)
		af, err2 := strconv.ParseFloat(an[i], 64)
		if err1 != nil || err2 != nil || !Near(ef, af, tol) {
			return false
		}
	}
	return true
}

func splitNumbers(line string) ([]string, []string) {
	var nums, texts []string
	last := 0
	i := 0
	for i < len(line) {
		isDigit := line[i] >= '0' && line[i] <= '9'
		isNeg := line[i] == '-' && i+1 < len(line) && line[i+1] >= '0' && line[i+1] <= '9' &&
			(i == 0 || !isAlphaNum(line[i-1]))
		if (!isDigit && !isNeg) || (i > 0 && (isAlpha(line[i-1]) || line[i-1] == '_')) {
			i++
			continue
		}
		start := i
		i++
		for i < len(line) && line[i] >= '0' && line[i] <= '9' {
			i++
		}
		if i+1 < len(line) && line[i] == '.' && line[i+1] >= '0' && line[i+1] <= '9' {
			i++
			for i < len(line) && line[i] >= '0' && line[i] <= '9' {
				i++
			}
		}
		if i < len(line) && (line[i] == 'e' || line[i] == 'E') {
			j := i + 1
			if j < len(line) && (line[j] == '+' || line[j] == '-') {
				j++
			}
			if j < len(line) && line[j] >= '0' && line[j] <= '9' {
				for j < len(line) && line[j] >= '0' && line[j] <= '9' {
					j++
				}
				i = j
			}
		}
		texts = append(texts, line[last:start])
		nums = append(nums, line[start:i])
		last = i
	}
	texts = append(texts, line[last:])
	return nums, texts
}

func isAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isAlphaNum(b byte) bool {
	return isAlpha(b) || (b >= '0' && b <= '9')
}

// LinesMatchInAnyOrder solves bipartite matching for unordered lines (ported from rust-anything/src/app.rs).
func LinesMatchInAnyOrder(expected, actual []string, tol *float64) bool {
	if len(expected) != len(actual) {
		return false
	}
	spare := make(map[string]int, len(actual))
	for _, line := range actual {
		spare[line]++
	}
	var restExp []string
	for _, line := range expected {
		if spare[line] > 0 {
			spare[line]--
		} else {
			restExp = append(restExp, line)
		}
	}
	if len(restExp) == 0 {
		return true
	}
	var restAct []string
	for line, cnt := range spare {
		for i := 0; i < cnt; i++ {
			restAct = append(restAct, line)
		}
	}
	holder := make([]int, len(restAct))
	for i := range holder {
		holder[i] = -1
	}
	var augment func(want int, tried []bool) bool
	augment = func(want int, tried []bool) bool {
		for i := range restAct {
			if tried[i] || !LineMatchesWithin(restExp[want], restAct[i], tol) {
				continue
			}
			tried[i] = true
			if holder[i] == -1 || augment(holder[i], tried) {
				holder[i] = want
				return true
			}
		}
		return false
	}
	for want := range restExp {
		tried := make([]bool, len(restAct))
		if !augment(want, tried) {
			return false
		}
	}
	return true
}
