package ingest

import (
	"fmt"
	"strings"

	"github.com/TaTrap/request-anything/internal/models"
	"github.com/TaTrap/request-anything/pkg/wireclient"
)

// ParseCurl imports a cURL command line into a GoldenFixture preserving header order and raw query.
func ParseCurl(cmdLine string, name string) (*models.GoldenFixture, error) {
	tokens, err := splitShellWords(cmdLine)
	if err != nil {
		return nil, err
	}
	if len(tokens) == 0 || !strings.EqualFold(tokens[0], "curl") {
		return nil, fmt.Errorf("input does not start with `curl`")
	}

	var (
		method      string
		rawURL      string
		headers     []models.HeaderKV
		dataParts   []string
		cookieCount int
		proto       = "HTTP/1.1"
	)

	args := tokens[1:]
	for i := 0; i < len(args); i++ {
		arg := args[i]
		next := func() (string, error) {
			i++
			if i >= len(args) {
				return "", fmt.Errorf("flag %s requires a value", arg)
			}
			return args[i], nil
		}
		switch arg {
		case "-X", "--request":
			v, err := next()
			if err != nil {
				return nil, err
			}
			method = strings.ToUpper(v)
		case "-H", "--header":
			h, err := next()
			if err != nil {
				return nil, err
			}
			k, v, ok := strings.Cut(h, ":")
			if !ok {
				continue
			}
			rawName := strings.TrimSpace(k)
			val := strings.TrimLeft(v, " \t")
			if strings.EqualFold(rawName, "cookie") {
				cookieCount++
			}
			headers = append(headers, models.HeaderKV{
				RawName:  rawName,
				Value:    val,
				IsPseudo: strings.HasPrefix(rawName, ":"),
			})
		case "-d", "--data", "--data-raw", "--data-binary", "--data-ascii", "--data-urlencode":
			v, err := next()
			if err != nil {
				return nil, err
			}
			dataParts = append(dataParts, v)
		case "--json":
			v, err := next()
			if err != nil {
				return nil, err
			}
			dataParts = append(dataParts, v)
			if HeaderValue(headers, "content-type") == "" {
				headers = append(headers, models.HeaderKV{RawName: "Content-Type", Value: "application/json"})
			}
			if HeaderValue(headers, "accept") == "" {
				headers = append(headers, models.HeaderKV{RawName: "Accept", Value: "application/json"})
			}
		case "-A", "--user-agent":
			v, err := next()
			if err != nil {
				return nil, err
			}
			headers = append(headers, models.HeaderKV{RawName: "User-Agent", Value: v})
		case "-b", "--cookie":
			v, err := next()
			if err != nil {
				return nil, err
			}
			cookieCount++
			headers = append(headers, models.HeaderKV{RawName: "Cookie", Value: v})
		case "-e", "--referer":
			v, err := next()
			if err != nil {
				return nil, err
			}
			headers = append(headers, models.HeaderKV{RawName: "Referer", Value: v})
		case "--http2", "--http2-prior-knowledge":
			proto = "HTTP/2"
		case "--http1.1":
			proto = "HTTP/1.1"
		case "--url":
			v, err := next()
			if err != nil {
				return nil, err
			}
			rawURL = v
		case "-o", "--output", "-w", "--write-out", "-m", "--max-time", "--connect-timeout", "-x", "--proxy", "-u", "--user":
			if _, err := next(); err != nil {
				return nil, err
			}
		default:
			if strings.HasPrefix(arg, "-X") && len(arg) > 2 {
				method = strings.ToUpper(arg[2:])
			} else if strings.HasPrefix(arg, "-H") && len(arg) > 2 {
				if k, v, ok := strings.Cut(arg[2:], ":"); ok {
					headers = append(headers, models.HeaderKV{RawName: strings.TrimSpace(k), Value: strings.TrimLeft(v, " \t")})
				}
			} else if !strings.HasPrefix(arg, "-") {
				rawURL = arg
			}
		}
	}

	if rawURL == "" {
		return nil, fmt.Errorf("no URL found in curl command")
	}
	scheme, authority, rawPath, rawQuery := SplitRawURL(rawURL)
	oq := wireclient.ParseRawQuery(rawQuery)
	bodyBytes := []byte(strings.Join(dataParts, "&"))
	if method == "" {
		if len(bodyBytes) > 0 {
			method = "POST"
		} else {
			method = "GET"
		}
	}
	cookieMode := models.CookieSingleHeader
	if proto == "HTTP/2" && cookieCount > 1 {
		cookieMode = models.CookieH2Crumbs
	}
	if name == "" {
		name = strings.ToLower(method) + "_" + SafeSlug(rawPath)
	}

	ct := HeaderValue(headers, "content-type")
	ce := HeaderValue(headers, "content-encoding")
	wireBody := models.WireBody{
		Encoding: ce,
		RawBytes: bodyBytes,
	}
	FinalizeBody(&wireBody, ct)

	return &models.GoldenFixture{
		Schema: models.SchemaFixture,
		ID:     SafeSlug(name),
		Name:   name,
		Source: "curl",
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
			Body:        wireBody,
			Transport: models.TransportMeta{
				CaptureFidelity: models.FidelityHookDump,
				CookieWireMode:  cookieMode,
				Proto:           proto,
			},
		},
	}, nil
}

func splitShellWords(line string) ([]string, error) {
	line = strings.ReplaceAll(line, "\\\r\n", " ")
	line = strings.ReplaceAll(line, "\\\n", " ")
	var (
		words []string
		cur   strings.Builder
		inTok bool
		i     int
	)
	flush := func() {
		if inTok {
			words = append(words, cur.String())
			cur.Reset()
			inTok = false
		}
	}
	for i < len(line) {
		c := line[i]
		switch c {
		case ' ', '\t', '\r', '\n':
			flush()
			i++
		case '$':
			if i+1 < len(line) && line[i+1] == '\'' {
				inTok = true
				i += 2
				for i < len(line) && line[i] != '\'' {
					if line[i] == '\\' && i+1 < len(line) {
						i++
						switch line[i] {
						case 'n':
							cur.WriteByte('\n')
						case 'r':
							cur.WriteByte('\r')
						case 't':
							cur.WriteByte('\t')
						default:
							cur.WriteByte(line[i])
						}
					} else {
						cur.WriteByte(line[i])
					}
					i++
				}
				if i >= len(line) {
					return nil, fmt.Errorf("unterminated $'...' string")
				}
				i++
			} else {
				inTok = true
				cur.WriteByte(c)
				i++
			}
		case '\'':
			inTok = true
			i++
			for i < len(line) && line[i] != '\'' {
				cur.WriteByte(line[i])
				i++
			}
			if i >= len(line) {
				return nil, fmt.Errorf("unterminated single quote")
			}
			i++
		case '"':
			inTok = true
			i++
			for i < len(line) && line[i] != '"' {
				if line[i] == '\\' && i+1 < len(line) {
					next := line[i+1]
					if next == '"' || next == '\\' || next == '$' || next == '`' {
						cur.WriteByte(next)
						i += 2
						continue
					}
				}
				cur.WriteByte(line[i])
				i++
			}
			if i >= len(line) {
				return nil, fmt.Errorf("unterminated double quote")
			}
			i++
		case '\\':
			inTok = true
			if i+1 < len(line) {
				cur.WriteByte(line[i+1])
				i += 2
			} else {
				i++
			}
		default:
			inTok = true
			cur.WriteByte(c)
			i++
		}
	}
	flush()
	return words, nil
}
