package diff

import (
	"encoding/hex"
	"fmt"

	"github.com/TaTrap/request-anything/internal/models"
	"google.golang.org/protobuf/encoding/protowire"
)

// ProtoField represents one decoded wire-level protobuf field without needing a .proto schema.
type ProtoField struct {
	Number   protowire.Number
	Type     protowire.Type
	Varint   uint64
	Fixed32  uint32
	Fixed64  uint64
	Bytes    []byte
	Children []ProtoField
}

// DecodeProtoWire parses raw bytes into a slice of ProtoField entries recursively when safe.
func DecodeProtoWire(raw []byte) ([]ProtoField, error) {
	var fields []ProtoField
	b := raw
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		b = b[n:]
		f := ProtoField{Number: num, Type: typ}
		switch typ {
		case protowire.VarintType:
			v, m := protowire.ConsumeVarint(b)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			f.Varint = v
			b = b[m:]
		case protowire.Fixed32Type:
			v, m := protowire.ConsumeFixed32(b)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			f.Fixed32 = v
			b = b[m:]
		case protowire.Fixed64Type:
			v, m := protowire.ConsumeFixed64(b)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			f.Fixed64 = v
			b = b[m:]
		case protowire.BytesType:
			v, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			f.Bytes = append([]byte(nil), v...)
			if len(v) > 0 {
				if sub, err := DecodeProtoWire(v); err == nil && len(sub) > 0 {
					f.Children = sub
				}
			}
			b = b[m:]
		case protowire.StartGroupType:
			v, m := protowire.ConsumeGroup(num, b)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			f.Bytes = append([]byte(nil), v...)
			b = b[m:]
		default:
			return nil, fmt.Errorf("unsupported wire type %d at field %d", typ, num)
		}
		fields = append(fields, f)
	}
	return fields, nil
}

// DiffProtoWire compares two raw protobuf payloads field by field (tag order, wire_type, scalar/bytes, nested messages).
func DiffProtoWire(prefix string, expRaw, actRaw []byte) []models.DiffFinding {
	expFields, errExp := DecodeProtoWire(expRaw)
	actFields, errAct := DecodeProtoWire(actRaw)
	if errExp != nil || errAct != nil {
		return []models.DiffFinding{{
			Layer:    "L3",
			Path:     prefix,
			Severity: "error",
			Kind:     "protobuf_parse_error",
			Expected: hex.EncodeToString(expRaw),
			Actual:   hex.EncodeToString(actRaw),
			Message:  fmt.Sprintf("protobuf wire parse error (expectedErr=%v actualErr=%v)", errExp, errAct),
		}}
	}
	return diffProtoFields(prefix, expFields, actFields)
}

func diffProtoFields(prefix string, exp, act []ProtoField) []models.DiffFinding {
	var findings []models.DiffFinding
	maxLen := len(exp)
	if len(act) > maxLen {
		maxLen = len(act)
	}
	for i := 0; i < maxLen; i++ {
		if i >= len(exp) {
			findings = append(findings, models.DiffFinding{
				Layer:    "L3",
				Path:     fmt.Sprintf("%s.field[%d](tag=%d)", prefix, i, act[i].Number),
				Severity: "error",
				Kind:     "protobuf_extra_field",
				Actual:   formatProtoField(act[i]),
				Message:  fmt.Sprintf("unexpected extra protobuf field tag=%d at index %d", act[i].Number, i),
			})
			continue
		}
		if i >= len(act) {
			findings = append(findings, models.DiffFinding{
				Layer:    "L3",
				Path:     fmt.Sprintf("%s.field[%d](tag=%d)", prefix, i, exp[i].Number),
				Severity: "error",
				Kind:     "protobuf_missing_field",
				Expected: formatProtoField(exp[i]),
				Message:  fmt.Sprintf("missing protobuf field tag=%d at index %d", exp[i].Number, i),
			})
			continue
		}
		ef, af := exp[i], act[i]
		p := fmt.Sprintf("%s.tag_%d[%d]", prefix, ef.Number, i)
		if ef.Number != af.Number || ef.Type != af.Type {
			findings = append(findings, models.DiffFinding{
				Layer:    "L3",
				Path:     p,
				Severity: "error",
				Kind:     "protobuf_tag_or_type_mismatch",
				Expected: fmt.Sprintf("tag=%d wire=%s", ef.Number, wireTypeName(ef.Type)),
				Actual:   fmt.Sprintf("tag=%d wire=%s", af.Number, wireTypeName(af.Type)),
				Message:  fmt.Sprintf("protobuf tag/wire mismatch at index %d", i),
			})
			continue
		}
		switch ef.Type {
		case protowire.VarintType:
			if ef.Varint != af.Varint {
				findings = append(findings, models.DiffFinding{
					Layer:    "L3",
					Path:     p,
					Severity: "error",
					Kind:     "protobuf_varint_mismatch",
					Expected: fmt.Sprintf("%d", ef.Varint),
					Actual:   fmt.Sprintf("%d", af.Varint),
					Message:  fmt.Sprintf("protobuf varint mismatch at tag %d", ef.Number),
				})
			}
		case protowire.Fixed32Type:
			if ef.Fixed32 != af.Fixed32 {
				findings = append(findings, models.DiffFinding{
					Layer:    "L3",
					Path:     p,
					Severity: "error",
					Kind:     "protobuf_fixed32_mismatch",
					Expected: fmt.Sprintf("0x%08x", ef.Fixed32),
					Actual:   fmt.Sprintf("0x%08x", af.Fixed32),
					Message:  fmt.Sprintf("protobuf fixed32 mismatch at tag %d", ef.Number),
				})
			}
		case protowire.Fixed64Type:
			if ef.Fixed64 != af.Fixed64 {
				findings = append(findings, models.DiffFinding{
					Layer:    "L3",
					Path:     p,
					Severity: "error",
					Kind:     "protobuf_fixed64_mismatch",
					Expected: fmt.Sprintf("0x%016x", ef.Fixed64),
					Actual:   fmt.Sprintf("0x%016x", af.Fixed64),
					Message:  fmt.Sprintf("protobuf fixed64 mismatch at tag %d", ef.Number),
				})
			}
		case protowire.BytesType, protowire.StartGroupType:
			if string(ef.Bytes) != string(af.Bytes) {
				if len(ef.Children) > 0 && len(af.Children) > 0 {
					findings = append(findings, diffProtoFields(p, ef.Children, af.Children)...)
				} else {
					findings = append(findings, models.DiffFinding{
						Layer:    "L3",
						Path:     p,
						Severity: "error",
						Kind:     "protobuf_bytes_mismatch",
						Expected: formatBytesPreview(ef.Bytes),
						Actual:   formatBytesPreview(af.Bytes),
						Message:  fmt.Sprintf("protobuf bytes mismatch at tag %d", ef.Number),
					})
				}
			}
		}
	}
	return findings
}

func wireTypeName(t protowire.Type) string {
	switch t {
	case protowire.VarintType:
		return "varint"
	case protowire.Fixed32Type:
		return "fixed32"
	case protowire.Fixed64Type:
		return "fixed64"
	case protowire.BytesType:
		return "bytes"
	case protowire.StartGroupType:
		return "group"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

func formatProtoField(f ProtoField) string {
	switch f.Type {
	case protowire.VarintType:
		return fmt.Sprintf("tag=%d varint=%d", f.Number, f.Varint)
	case protowire.Fixed32Type:
		return fmt.Sprintf("tag=%d fixed32=0x%08x", f.Number, f.Fixed32)
	case protowire.Fixed64Type:
		return fmt.Sprintf("tag=%d fixed64=0x%016x", f.Number, f.Fixed64)
	default:
		return fmt.Sprintf("tag=%d bytes=%s", f.Number, formatBytesPreview(f.Bytes))
	}
}

func formatBytesPreview(b []byte) string {
	if len(b) > 64 {
		return fmt.Sprintf("len=%d hex=%s...", len(b), hex.EncodeToString(b[:32]))
	}
	return fmt.Sprintf("len=%d hex=%s", len(b), hex.EncodeToString(b))
}
