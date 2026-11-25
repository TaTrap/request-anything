package wireclient

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"

	"github.com/TaTrap/request-anything/pkg/models"
	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// DecompressBody decodes gzip, br, zstd, deflate, or zlib HTTP payloads.
func DecompressBody(raw []byte, encoding string) ([]byte, error) {
	if len(raw) == 0 {
		return raw, nil
	}
	enc := strings.ToLower(strings.TrimSpace(encoding))
	if enc == "" && len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
		enc = "gzip"
	}
	switch enc {
	case "", "raw", "identity":
		return raw, nil
	case "gzip":
		r, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return io.ReadAll(r)
	case "br":
		return io.ReadAll(brotli.NewReader(bytes.NewReader(raw)))
	case "zstd":
		dec, err := zstd.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		defer dec.Close()
		return io.ReadAll(dec)
	case "deflate":
		zr, err := zlib.NewReader(bytes.NewReader(raw))
		if err == nil {
			defer zr.Close()
			if out, rerr := io.ReadAll(zr); rerr == nil {
				return out, nil
			}
		}
		r := flate.NewReader(bytes.NewReader(raw))
		defer r.Close()
		return io.ReadAll(r)
	default:
		return raw, nil
	}
}

// DetectBodyKind infers payload kind from Content-Type and decoded byte inspection.
func DetectBodyKind(decoded []byte, contentType string) string {
	if len(decoded) == 0 {
		return "empty"
	}
	ct := strings.ToLower(contentType)
	switch {
	case strings.Contains(ct, "json"):
		return "json"
	case strings.Contains(ct, "x-www-form-urlencoded"):
		return "form"
	case strings.Contains(ct, "multipart/form-data"):
		return "multipart"
	case strings.Contains(ct, "protobuf"), strings.Contains(ct, "x-protobuf"):
		return "protobuf"
	}
	trim := bytes.TrimSpace(decoded)
	if len(trim) > 0 && (trim[0] == '{' || trim[0] == '[') && json.Valid(trim) {
		return "json"
	}
	return "binary"
}

// FinalizeBody computes RawSHA256, DecodedSHA, Kind, and JSONStyle on decoded payload bytes.
func FinalizeBody(body *models.WireBody, contentType string) {
	if len(body.RawBytes) == 0 {
		if body.Encoding == "" {
			body.Encoding = "raw"
		}
		if body.Kind == "" {
			body.Kind = "empty"
		}
		sum := sha256.Sum256(nil)
		body.RawSHA256 = hex.EncodeToString(sum[:])
		body.DecodedSHA = body.RawSHA256
		return
	}
	if body.Encoding == "" {
		if len(body.RawBytes) >= 2 && body.RawBytes[0] == 0x1f && body.RawBytes[1] == 0x8b {
			body.Encoding = "gzip"
		} else {
			body.Encoding = "raw"
		}
	}
	sum := sha256.Sum256(body.RawBytes)
	body.RawSHA256 = hex.EncodeToString(sum[:])

	decoded, err := DecompressBody(body.RawBytes, body.Encoding)
	if err != nil {
		decoded = body.RawBytes
	}
	dSum := sha256.Sum256(decoded)
	body.DecodedSHA = hex.EncodeToString(dSum[:])

	if body.Kind == "" || body.Kind == "unknown" {
		body.Kind = DetectBodyKind(decoded, contentType)
	}
	if body.Kind == "json" {
		body.JSONStyle = DetectJSONStyle(decoded)
	}
}

// DecodedResponseBytes decompresses response body bytes according to Body.Encoding or Content-Encoding header.
func DecodedResponseBytes(resp *models.WireResponse) []byte {
	if resp == nil || len(resp.Body.RawBytes) == 0 {
		return nil
	}
	enc := resp.Body.Encoding
	if enc == "" {
		for _, h := range resp.Headers {
			if strings.EqualFold(h.RawName, "content-encoding") {
				enc = h.Value
				break
			}
		}
	}
	decoded, err := DecompressBody(resp.Body.RawBytes, enc)
	if err != nil {
		return resp.Body.RawBytes
	}
	return decoded
}
