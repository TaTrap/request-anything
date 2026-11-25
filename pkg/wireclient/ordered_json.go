package wireclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/TaTrap/request-anything/pkg/models"
)

// OrderedPair holds one key-value pair inside an OrderedMap.
type OrderedPair struct {
	Key   string
	Value any
}

// OrderedMap preserves insertion order of JSON object keys without sorting.
type OrderedMap struct {
	Pairs []OrderedPair
}

// NewOrderedMap returns an empty OrderedMap.
func NewOrderedMap() *OrderedMap {
	return &OrderedMap{}
}

// Set updates an existing key in-place or appends a new key.
func (m *OrderedMap) Set(key string, val any) {
	for i := range m.Pairs {
		if m.Pairs[i].Key == key {
			m.Pairs[i].Value = val
			return
		}
	}
	m.Pairs = append(m.Pairs, OrderedPair{Key: key, Value: val})
}

// Get retrieves a key's value if present.
func (m *OrderedMap) Get(key string) (any, bool) {
	for _, p := range m.Pairs {
		if p.Key == key {
			return p.Value, true
		}
	}
	return nil, false
}

// JSONMarshalOptions controls Android JSONObject solidus escaping and indentation.
type JSONMarshalOptions struct {
	EscapeSolidus bool   // Escapes '/' -> '\/' inside string literals (affects body MD5 & Content-Length!)
	Indent        string // Optional pretty indent; empty = compact single-line
}

// UnmarshalOrdered decodes JSON bytes preserving object key order and raw json.Number lexemes.
func UnmarshalOrdered(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	val, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("unexpected trailing JSON content")
	}
	return val, nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	return decodeFromToken(dec, tok)
}

func decodeFromToken(dec *json.Decoder, tok json.Token) (any, error) {
	d, ok := tok.(json.Delim)
	if !ok {
		return tok, nil
	}
	switch d {
	case '{':
		m := NewOrderedMap()
		for dec.More() {
			kTok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, ok := kTok.(string)
			if !ok {
				return nil, fmt.Errorf("expected string key, got %T", kTok)
			}
			val, err := decodeValue(dec)
			if err != nil {
				return nil, err
			}
			m.Pairs = append(m.Pairs, OrderedPair{Key: key, Value: val})
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return nil, fmt.Errorf("expected closing '}'")
		}
		return m, nil
	case '[':
		var arr []any
		for dec.More() {
			val, err := decodeValue(dec)
			if err != nil {
				return nil, err
			}
			arr = append(arr, val)
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return nil, fmt.Errorf("expected closing ']'")
		}
		if arr == nil {
			arr = []any{}
		}
		return arr, nil
	default:
		return nil, fmt.Errorf("unexpected delimiter %q", d)
	}
}

// MarshalOrdered serializes OrderedMap/slices/json.Number without HTML escaping and optional `\/` solidus escaping.
func MarshalOrdered(v any, opts JSONMarshalOptions) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeOrderedJSON(&buf, v, opts, 0); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeOrderedJSON(buf *bytes.Buffer, v any, opts JSONMarshalOptions, depth int) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeJSONString(buf, x, opts.EscapeSolidus)
	case json.Number:
		buf.WriteString(x.String())
	case int:
		buf.WriteString(strconv.Itoa(x))
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
	case uint64:
		buf.WriteString(strconv.FormatUint(x, 10))
	case float64:
		b, err := json.Marshal(x)
		if err != nil {
			return err
		}
		buf.Write(b)
	case *OrderedMap:
		if x == nil {
			buf.WriteString("null")
			return nil
		}
		buf.WriteByte('{')
		for i, p := range x.Pairs {
			if i > 0 {
				buf.WriteByte(',')
			}
			if opts.Indent != "" {
				buf.WriteByte('\n')
				buf.WriteString(strings.Repeat(opts.Indent, depth+1))
			}
			writeJSONString(buf, p.Key, opts.EscapeSolidus)
			buf.WriteByte(':')
			if opts.Indent != "" {
				buf.WriteByte(' ')
			}
			if err := writeOrderedJSON(buf, p.Value, opts, depth+1); err != nil {
				return err
			}
		}
		if opts.Indent != "" && len(x.Pairs) > 0 {
			buf.WriteByte('\n')
			buf.WriteString(strings.Repeat(opts.Indent, depth))
		}
		buf.WriteByte('}')
	case OrderedMap:
		return writeOrderedJSON(buf, &x, opts, depth)
	case []any:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if opts.Indent != "" {
				buf.WriteByte('\n')
				buf.WriteString(strings.Repeat(opts.Indent, depth+1))
			}
			if err := writeOrderedJSON(buf, item, opts, depth+1); err != nil {
				return err
			}
		}
		if opts.Indent != "" && len(x) > 0 {
			buf.WriteByte('\n')
			buf.WriteString(strings.Repeat(opts.Indent, depth))
		}
		buf.WriteByte(']')
	default:
		// Fallback with SetEscapeHTML(false)
		var tmp bytes.Buffer
		enc := json.NewEncoder(&tmp)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(x); err != nil {
			return err
		}
		raw := bytes.TrimRight(tmp.Bytes(), "\n")
		if opts.EscapeSolidus {
			raw = escapeSolidusInRawJSON(raw)
		}
		buf.Write(raw)
	}
	return nil
}

func writeJSONString(buf *bytes.Buffer, s string, escapeSolidus bool) {
	buf.WriteByte('"')
	for i := 0; i < len(s); {
		b := s[i]
		if b < utf8.RuneSelf {
			switch b {
			case '"':
				buf.WriteString(`\"`)
			case '\\':
				buf.WriteString(`\\`)
			case '/':
				if escapeSolidus {
					buf.WriteString(`\/`)
				} else {
					buf.WriteByte('/')
				}
			case '\b':
				buf.WriteString(`\b`)
			case '\f':
				buf.WriteString(`\f`)
			case '\n':
				buf.WriteString(`\n`)
			case '\r':
				buf.WriteString(`\r`)
			case '\t':
				buf.WriteString(`\t`)
			default:
				if b < 0x20 {
					fmt.Fprintf(buf, `\u%04x`, b)
				} else {
					buf.WriteByte(b)
				}
			}
			i++
			continue
		}
		r, width := utf8.DecodeRuneInString(s[i:])
		buf.WriteRune(r)
		i += width
	}
	buf.WriteByte('"')
}

func escapeSolidusInRawJSON(raw []byte) []byte {
	var out bytes.Buffer
	inStr := false
	escaped := false
	for _, b := range raw {
		if !inStr {
			out.WriteByte(b)
			if b == '"' {
				inStr = true
			}
			continue
		}
		if escaped {
			out.WriteByte(b)
			escaped = false
			continue
		}
		if b == '\\' {
			out.WriteByte(b)
			escaped = true
			continue
		}
		if b == '"' {
			out.WriteByte(b)
			inStr = false
			continue
		}
		if b == '/' {
			out.WriteString(`\/`)
			continue
		}
		out.WriteByte(b)
	}
	return out.Bytes()
}

// DetectJSONStyle inspects raw JSON bytes to detect Android `\/` solidus escaping.
func DetectJSONStyle(raw []byte) models.JSONStyle {
	style := models.JSONStyle{
		PreserveRawNumbers: true,
	}
	if bytes.Contains(raw, []byte(`\/`)) {
		style.EscapeSolidus = true
	}
	return style
}
