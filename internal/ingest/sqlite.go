package ingest

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/TaTrap/request-anything/internal/models"
	"github.com/TaTrap/request-anything/pkg/wireclient"
)

type compressedCaptureSession struct {
	ID              int    `json:"id"`
	Key             string `json:"key"`
	Scheme          string `json:"scheme"`
	Authority       string `json:"authority"`
	Domain          string `json:"domain"`
	Method          string `json:"method"`
	StatusCode      int    `json:"status_code"`
	URLPath         string `json:"url_path"`
	IsWS            bool   `json:"is_ws"`
	RequestHeaders  string `json:"request_headers"`
	RequestBody     string `json:"request_body"`
	RequestHex      string `json:"request_hex"`
	ResponseHeaders string `json:"response_headers"`
	ResponseBody    string `json:"response_body"`
	ResponseHex     string `json:"response_hex"`
	RecordType      string `json:"record_type"`
}

// ParseSQLite imports captures from gzipped `capture_requests` BLOBs or flat SQLite tables (Reqable / HTTP Toolkit).
func ParseSQLite(path string) ([]*models.GoldenFixture, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite %s: %w", path, err)
	}
	defer db.Close()

	if hasCaptureRequestsTable(db) {
		return parseCompressedCaptureSQLite(db)
	}

	table, cols, err := findCaptureTable(db)
	if err != nil {
		return nil, err
	}

	query := fmt.Sprintf("SELECT %s FROM %s", strings.Join(quoteCols(cols), ", "), quoteIdent(table))
	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("querying %s: %w", table, err)
	}
	defer rows.Close()

	colIdx := make(map[string]int, len(cols))
	for i, c := range cols {
		colIdx[strings.ToLower(c)] = i
	}

	var fixtures []*models.GoldenFixture
	rowNum := 0
	for rows.Next() {
		rowNum++
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}

		getStr := func(candidates ...string) string {
			for _, name := range candidates {
				if idx, ok := colIdx[name]; ok && vals[idx] != nil {
					switch v := vals[idx].(type) {
					case string:
						return v
					case []byte:
						return string(v)
					default:
						return fmt.Sprint(v)
					}
				}
			}
			return ""
		}
		getBytes := func(candidates ...string) []byte {
			for _, name := range candidates {
				if idx, ok := colIdx[name]; ok && vals[idx] != nil {
					switch v := vals[idx].(type) {
					case []byte:
						return append([]byte(nil), v...)
					case string:
						return []byte(v)
					}
				}
			}
			return nil
		}
		getInt := func(candidates ...string) int {
			for _, name := range candidates {
				if idx, ok := colIdx[name]; ok && vals[idx] != nil {
					switch v := vals[idx].(type) {
					case int64:
						return int(v)
					case int:
						return v
					}
				}
			}
			return 0
		}

		method := strings.ToUpper(getStr("method", "req_method", "http_method"))
		rawURL := getStr("url", "request_url", "full_url")
		if rawURL == "" {
			host := getStr("host", "authority")
			pathVal := getStr("path", "raw_path")
			if host != "" {
				rawURL = "https://" + host + pathVal
			}
		}
		if rawURL == "" {
			continue
		}
		if method == "" {
			method = "GET"
		}
		scheme, authority, rawPath, rawQuery := SplitRawURL(rawURL)
		oq := wireclient.ParseRawQuery(rawQuery)

		headersRaw := getStr("request_headers", "req_headers", "headers")
		headers, cookieCount := parseFlexibleHeaders(headersRaw)

		bodyBytes := getBytes("request_body", "req_body", "body")
		proto := getStr("http_version", "proto")
		if proto == "" {
			proto = "HTTP/2"
		}
		cookieMode := models.CookieSingleHeader
		if cookieCount > 1 {
			cookieMode = models.CookieH2Crumbs
		}
		fidelity := models.FidelityHookDump
		if f := getStr("capture_fidelity"); f != "" {
			fidelity = models.CaptureFidelity(f)
		}

		wb := models.WireBody{
			Encoding: HeaderValue(headers, "content-encoding"),
			RawBytes: bodyBytes,
		}
		FinalizeBody(&wb, HeaderValue(headers, "content-type"))

		var resp *models.WireResponse
		if status := getInt("status", "status_code", "response_status", "resp_status"); status > 0 {
			rHeaders, _ := parseFlexibleHeaders(getStr("response_headers", "resp_headers"))
			rBody := getBytes("response_body", "resp_body")
			rwb := models.WireBody{Encoding: HeaderValue(rHeaders, "content-encoding"), RawBytes: rBody}
			FinalizeBody(&rwb, HeaderValue(rHeaders, "content-type"))
			resp = &models.WireResponse{Status: status, Headers: rHeaders, Body: rwb}
		}

		name := fmt.Sprintf("sqlite_%03d_%s_%s", rowNum, strings.ToLower(method), SafeSlug(rawPath))
		fixtures = append(fixtures, &models.GoldenFixture{
			Schema: models.SchemaFixture,
			ID:     name,
			Name:   name,
			Source: "sqlite",
			Request: models.WireRequest{
				Schema:      models.SchemaFixture,
				Method:      method,
				Scheme:      scheme,
				Authority:   authority,
				RawPath:     rawPath,
				RawQuery:    rawQuery,
				TrailingAmp: oq.TrailingAmp,
				Query:       oq.Params,
				Headers:     headers,
				Body:        wb,
				Transport: models.TransportMeta{
					CaptureFidelity: fidelity,
					CookieWireMode:  cookieMode,
					Proto:           proto,
				},
			},
			Response: resp,
		})
	}
	return fixtures, rows.Err()
}

func hasCaptureRequestsTable(db *sql.DB) bool {
	var count int
	err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='capture_requests'").Scan(&count)
	return err == nil && count > 0
}

func parseCompressedCaptureSQLite(db *sql.DB) ([]*models.GoldenFixture, error) {
	rows, err := db.Query("SELECT run_id, mode, key, ordinal, payload FROM capture_requests ORDER BY run_id ASC, ordinal ASC")
	if err != nil {
		return nil, fmt.Errorf("querying capture_requests: %w", err)
	}
	defer rows.Close()

	var fixtures []*models.GoldenFixture
	idx := 0
	for rows.Next() {
		var runID int64
		var mode, key string
		var ordinal int64
		var blob []byte
		if err := rows.Scan(&runID, &mode, &key, &ordinal, &blob); err != nil {
			return nil, err
		}
		rawJSON, err := decompressCapturePayload(blob)
		if err != nil {
			continue
		}
		var sess compressedCaptureSession
		if err := json.Unmarshal(rawJSON, &sess); err != nil {
			continue
		}
		method := strings.ToUpper(strings.TrimSpace(sess.Method))
		if method == "" {
			if sess.IsWS {
				continue
			}
			method = "GET"
		}

		var scheme, authority, rawPath, rawQuery string
		if strings.Contains(sess.URLPath, "://") {
			scheme, authority, rawPath, rawQuery = SplitRawURL(sess.URLPath)
		} else {
			scheme = strings.ToLower(strings.TrimSpace(sess.Scheme))
			if scheme == "" {
				scheme = "https"
			}
			authority = strings.TrimSpace(sess.Authority)
			if authority == "" {
				authority = strings.TrimSpace(sess.Domain)
			}
			if p, q, hasQ := strings.Cut(sess.URLPath, "?"); hasQ {
				rawPath = p
				rawQuery = q
			} else {
				rawPath = sess.URLPath
			}
			if rawPath == "" {
				rawPath = "/"
			}
		}
		oq := wireclient.ParseRawQuery(rawQuery)
		headers, cookieCount := parseFlexibleHeaders(sess.RequestHeaders)

		bodyBytes := decodeHexOrText(sess.RequestHex, sess.RequestBody)
		wb := models.WireBody{
			Encoding: HeaderValue(headers, "content-encoding"),
			RawBytes: bodyBytes,
		}
		FinalizeBody(&wb, HeaderValue(headers, "content-type"))

		cookieMode := models.CookieSingleHeader
		if cookieCount > 1 {
			cookieMode = models.CookieH2Crumbs
		}

		var resp *models.WireResponse
		if sess.StatusCode > 0 {
			rHeaders, _ := parseFlexibleHeaders(sess.ResponseHeaders)
			rBody := decodeHexOrText(sess.ResponseHex, sess.ResponseBody)
			rwb := models.WireBody{
				Encoding: HeaderValue(rHeaders, "content-encoding"),
				RawBytes: rBody,
			}
			FinalizeBody(&rwb, HeaderValue(rHeaders, "content-type"))
			resp = &models.WireResponse{
				Status:  sess.StatusCode,
				Headers: rHeaders,
				Body:    rwb,
			}
		}

		idx++
		name := fmt.Sprintf("cap_r%d_%03d_%s_%s", runID, ordinal, strings.ToLower(method), SafeSlug(rawPath))
		if ordinal == 0 {
			name = fmt.Sprintf("cap_r%d_%03d_%s_%s", runID, idx, strings.ToLower(method), SafeSlug(rawPath))
		}
		fixtures = append(fixtures, &models.GoldenFixture{
			Schema: models.SchemaFixture,
			ID:     name,
			Name:   name,
			Source: fmt.Sprintf("capture_sqlite:%s", mode),
			Request: models.WireRequest{
				Schema:      models.SchemaFixture,
				Method:      method,
				Scheme:      scheme,
				Authority:   authority,
				RawPath:     rawPath,
				RawQuery:    rawQuery,
				TrailingAmp: oq.TrailingAmp,
				Query:       oq.Params,
				Headers:     headers,
				Body:        wb,
				Transport: models.TransportMeta{
					CaptureFidelity: models.FidelityHookDump,
					CookieWireMode:  cookieMode,
					Proto:           "HTTP/2",
				},
			},
			Response: resp,
		})
	}
	return fixtures, rows.Err()
}

func decompressCapturePayload(blob []byte) ([]byte, error) {
	if len(blob) >= 2 && blob[0] == 0x1f && blob[1] == 0x8b {
		return wireclient.DecompressBody(blob, "gzip")
	}
	if len(blob) >= 1 && blob[0] == 0x78 {
		if out, err := wireclient.DecompressBody(blob, "deflate"); err == nil {
			return out, nil
		}
	}
	return blob, nil
}

func decodeHexOrText(hexStr, text string) []byte {
	cleanHex := strings.NewReplacer(" ", "", ":", "", "\n", "", "\r", "").Replace(strings.TrimSpace(hexStr))
	if cleanHex != "" {
		if b, err := hex.DecodeString(cleanHex); err == nil {
			return b
		}
	}
	if text == "" {
		return nil
	}
	return []byte(text)
}

func findCaptureTable(db *sql.DB) (string, []string, error) {
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
	if err != nil {
		return "", nil, err
	}
	defer rows.Close()
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err == nil {
			tables = append(tables, name)
		}
	}
	for _, t := range tables {
		colRows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", quoteIdent(t)))
		if err != nil {
			continue
		}
		var cols []string
		hasURL := false
		for colRows.Next() {
			var cid int
			var name, ctype string
			var notnull, pk int
			var dflt any
			if err := colRows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err == nil {
				cols = append(cols, name)
				low := strings.ToLower(name)
				if low == "url" || low == "request_url" || low == "full_url" || low == "path" {
					hasURL = true
				}
			}
		}
		colRows.Close()
		if hasURL && len(cols) > 0 {
			return t, cols, nil
		}
	}
	return "", nil, fmt.Errorf("no HTTP capture table found in sqlite database")
}

func parseFlexibleHeaders(raw string) ([]models.HeaderKV, int) {
	trim := strings.TrimSpace(raw)
	if trim == "" {
		return nil, 0
	}
	var headers []models.HeaderKV
	cookieCount := 0

	// Format 1: JSON array of [name, value] or {name, value}
	if strings.HasPrefix(trim, "[") {
		var pairs [][]string
		if json.Unmarshal([]byte(trim), &pairs) == nil {
			for _, p := range pairs {
				if len(p) >= 2 {
					if strings.EqualFold(p[0], "cookie") {
						cookieCount++
					}
					headers = append(headers, models.HeaderKV{RawName: p[0], Value: p[1], IsPseudo: strings.HasPrefix(p[0], ":")})
				}
			}
			return headers, cookieCount
		}
		var objs []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		}
		if json.Unmarshal([]byte(trim), &objs) == nil {
			for _, o := range objs {
				if strings.EqualFold(o.Name, "cookie") {
					cookieCount++
				}
				headers = append(headers, models.HeaderKV{RawName: o.Name, Value: o.Value, IsPseudo: strings.HasPrefix(o.Name, ":")})
			}
			return headers, cookieCount
		}
	}

	// Format 2: Ordered JSON object
	if strings.HasPrefix(trim, "{") {
		if val, err := wireclient.UnmarshalOrdered([]byte(trim)); err == nil {
			if om, ok := val.(*wireclient.OrderedMap); ok {
				for _, p := range om.Pairs {
					if strings.EqualFold(p.Key, "cookie") {
						cookieCount++
					}
					headers = append(headers, models.HeaderKV{RawName: p.Key, Value: fmt.Sprint(p.Value), IsPseudo: strings.HasPrefix(p.Key, ":")})
				}
				return headers, cookieCount
			}
		}
	}

	// Format 3: Raw CRLF/LF lines
	for _, line := range strings.Split(strings.ReplaceAll(trim, "\r\n", "\n"), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			name := strings.TrimSpace(k)
			if strings.EqualFold(name, "cookie") {
				cookieCount++
			}
			headers = append(headers, models.HeaderKV{RawName: name, Value: strings.TrimLeft(v, " \t")})
		}
	}
	return headers, cookieCount
}

func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

func quoteCols(cols []string) []string {
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = quoteIdent(c)
	}
	return out
}
