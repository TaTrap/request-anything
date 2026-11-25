package diff

import (
	"context"
	"encoding/json"

	internaldiff "github.com/TaTrap/request-anything/internal/diff"
	"github.com/TaTrap/request-anything/pkg/models"
)

// Options configures a 6-layer surgical diff run.
type Options = internaldiff.Options

// ProtoField represents one decoded wire-level protobuf field without needing a .proto schema.
type ProtoField = internaldiff.ProtoField

// CompareRequests runs the 6-Layer Surgical Wire Diff Engine and returns findings + explicit unknowns.
func CompareRequests(ctx context.Context, caseID string, expected *models.WireRequest, actual *models.WireRequest, expResp, actResp *models.WireResponse, opts Options) *models.DiffResult {
	return internaldiff.CompareRequests(ctx, caseID, expected, actual, expResp, actResp, opts)
}

// DiffProtoWire compares two raw protobuf payloads field by field without a .proto schema.
func DiffProtoWire(prefix string, expRaw, actRaw []byte) []models.DiffFinding {
	return internaldiff.DiffProtoWire(prefix, expRaw, actRaw)
}

// DecodeProtoWire parses raw bytes into ProtoField entries.
func DecodeProtoWire(raw []byte) ([]ProtoField, error) {
	return internaldiff.DecodeProtoWire(raw)
}

// NumbersClose compares two raw json.Number lexemes honoring optional tolerance without equating ints with floats.
func NumbersClose(expNum, actNum json.Number, tolerance *float64) bool {
	return internaldiff.NumbersClose(expNum, actNum, tolerance)
}

// CheckTolerance validates --float-tolerance in [0, 1).
func CheckTolerance(tol float64) error {
	return internaldiff.CheckTolerance(tol)
}
