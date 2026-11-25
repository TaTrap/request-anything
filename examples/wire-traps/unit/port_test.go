package wiretraps

import (
	"context"
	"testing"
)

func TestBuildRequestSmoke(t *testing.T) {
	req, err := BuildRequest(context.Background(), &SessionState{}, Input{})
	if err != nil {
		t.Fatal(err)
	}
	if req.Method == "" || req.RawPath == "" {
		t.Fatalf("expected valid method and path, got %+v", req)
	}
}
