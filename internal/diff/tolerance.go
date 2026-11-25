package diff

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// CheckTolerance validates --float-tolerance in [0, 1).
func CheckTolerance(tol float64) error {
	if math.IsNaN(tol) || math.IsInf(tol, 0) || tol < 0.0 || tol >= 1.0 {
		return fmt.Errorf("float-tolerance must be in [0, 1), got %v", tol)
	}
	return nil
}

// Near reports whether two floats agree within tolerance * max(|a|, |b|, 1).
func Near(expected, actual, tolerance float64) bool {
	scale := math.Max(math.Max(math.Abs(expected), math.Abs(actual)), 1.0)
	return math.Abs(expected-actual) <= tolerance*scale
}

// NumbersClose compares two raw json.Number lexemes strictly: `3` vs `3.0` is a formatting mismatch, not rounding!
func NumbersClose(expNum, actNum json.Number, tolerance *float64) bool {
	es := expNum.String()
	as := actNum.String()
	if es == as {
		return true
	}
	if tolerance == nil {
		return false
	}
	if !isFloatLexeme(es) && !isFloatLexeme(as) {
		return false
	}
	if isFloatLexeme(es) != isFloatLexeme(as) {
		return false // Forbids equating integer `3` with float `3.0`
	}
	ef, err1 := strconv.ParseFloat(es, 64)
	af, err2 := strconv.ParseFloat(as, 64)
	if err1 != nil || err2 != nil {
		return false
	}
	return Near(ef, af, *tolerance)
}

func isFloatLexeme(s string) bool {
	return strings.ContainsAny(s, ".eE")
}
