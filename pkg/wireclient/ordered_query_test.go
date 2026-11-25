package wireclient

import (
	"testing"
)

func TestOrderedQueryVerbatimAndTrailingAmp(t *testing.T) {
	raw := "iid=&resolution=1216*2623&text=hello%20world&tag=a&tag=b&flag&"
	q := ParseRawQuery(raw)
	if !q.TrailingAmp {
		t.Fatalf("expected TrailingAmp=true")
	}
	if got := q.Encode(); got != raw {
		t.Fatalf("verbatim roundtrip mismatch:\nwant: %q\ngot:  %q", raw, got)
	}
	if len(q.Params) != 6 {
		t.Fatalf("expected 6 params, got %d", len(q.Params))
	}
	if q.Params[0].RawKey != "iid" || !q.Params[0].HasEq || q.Params[0].RawValue != "" {
		t.Fatalf("expected iid= with HasEq=true, got %+v", q.Params[0])
	}
	if q.Params[5].RawKey != "flag" || q.Params[5].HasEq {
		t.Fatalf("expected flag without =, got %+v", q.Params[5])
	}

	// Modifying one field keeps untouched fields verbatim (e.g. `*` and `%20`).
	q.Set("text", "a b")
	want := "iid=&resolution=1216*2623&text=a%20b&tag=a&tag=b&flag&"
	if got := q.Encode(); got != want {
		t.Fatalf("modified encode mismatch:\nwant: %q\ngot:  %q", want, got)
	}
}
