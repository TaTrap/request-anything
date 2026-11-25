package wireclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/TaTrap/request-anything/pkg/models"
	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

// ClientOptions configures the unified bogdanfinn tls-client + fhttp + utls sender.
type ClientOptions struct {
	Profile            profiles.ClientProfile
	TimeoutSeconds     int
	InsecureSkipVerify bool
	ProxyURL           string
	FollowRedirects    bool
}

// Client transmits OrderedRequest instances over bogdanfinn/tls-client (HTTP/1.1 & HTTP/2 + uTLS)
// or raw TCP/TLS when exact HTTP/1.1 non-canonical header casing is required.
type Client struct {
	httpClient tls_client.HttpClient
	opts       ClientOptions
}

// NewClient creates a wireclient backed by bogdanfinn/tls-client + fhttp + utls.
func NewClient(opts ClientOptions) (*Client, error) {
	if opts.TimeoutSeconds <= 0 {
		opts.TimeoutSeconds = 30
	}
	if opts.Profile.GetClientHelloId().Client == "" {
		opts.Profile = profiles.Okhttp4Android13
	}
	if opts.ProxyURL == "" {
		opts.ProxyURL = DiffProxyURL()
	}
	// Automatic insecure verify when talking to local diff/MITM proxy
	insecure := opts.InsecureSkipVerify || opts.ProxyURL != ""

	tcOpts := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(opts.TimeoutSeconds),
		tls_client.WithClientProfile(opts.Profile),
	}
	if insecure {
		tcOpts = append(tcOpts, tls_client.WithInsecureSkipVerify())
	}
	if !opts.FollowRedirects {
		tcOpts = append(tcOpts, tls_client.WithNotFollowRedirects())
	}
	if opts.ProxyURL != "" {
		tcOpts = append(tcOpts, tls_client.WithProxyUrl(opts.ProxyURL))
	}

	hc, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), tcOpts...)
	if err != nil {
		return nil, fmt.Errorf("creating tls-client: %w", err)
	}
	return &Client{
		httpClient: hc,
		opts:       opts,
	}, nil
}

// Do transmits req preserving exact header order, pseudo-header order, cookie crumbs, and raw query bytes.
func (c *Client) Do(ctx context.Context, req *OrderedRequest) (*RawResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("nil request")
	}
	if req.ForceHTTP1Raw {
		return c.doRawHTTP1(ctx, req)
	}

	scheme := req.Scheme
	if scheme == "" {
		scheme = "https"
	}
	path := req.RawPath
	if path == "" {
		path = "/"
	}
	rawQuery := ""
	if req.Query != nil {
		rawQuery = req.Query.Encode()
	}

	baseURL := fmt.Sprintf("%s://%s%s", scheme, req.Authority, path)
	var bodyReader io.Reader
	if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	}
	fReq, err := fhttp.NewRequestWithContext(ctx, req.Method, baseURL, bodyReader)
	if err != nil {
		return nil, err
	}
	// Restore verbatim raw path & raw query so url.Parse never normalizes `*`, `%20`, or trailing `&`.
	fReq.URL.Path = path
	fReq.URL.RawPath = path
	fReq.URL.RawQuery = rawQuery
	if req.Authority != "" {
		fReq.Host = req.Authority
	}
	if len(req.Body) > 0 {
		fReq.ContentLength = int64(len(req.Body))
	}

	hdrs := NewOrderedHeaders(nil)
	if req.Headers != nil {
		hdrs = NewOrderedHeaders(req.Headers.Items)
	}
	if req.CookieWireMode != "" {
		hdrs.ApplyCookieMode(req.CookieWireMode)
	}
	fReq.Header = hdrs.ToFHTTPHeaders(req.PseudoOrder)

	resp, err := c.httpClient.Do(fReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var respHeaders []models.HeaderKV
	for k, vals := range resp.Header {
		for _, v := range vals {
			respHeaders = append(respHeaders, models.HeaderKV{RawName: k, Value: v})
		}
	}
	return &RawResponse{
		Status:  resp.StatusCode,
		Proto:   resp.Proto,
		Headers: respHeaders,
		Body:    respBytes,
	}, nil
}

// doRawHTTP1 sends exact raw HTTP/1.1 bytes over TCP/TLS with TCP_NODELAY enabled so exact lowercase header casing survives.
func (c *Client) doRawHTTP1(ctx context.Context, req *OrderedRequest) (*RawResponse, error) {
	scheme := req.Scheme
	if scheme == "" {
		scheme = "https"
	}
	targetAddr := req.Authority
	if !strings.Contains(targetAddr, ":") {
		if scheme == "http" {
			targetAddr += ":80"
		} else {
			targetAddr += ":443"
		}
	}

	var conn net.Conn
	var err error
	dialer := &net.Dialer{Timeout: time.Duration(c.opts.TimeoutSeconds) * time.Second}

	if c.opts.ProxyURL != "" {
		pURL, parseErr := url.Parse(c.opts.ProxyURL)
		if parseErr != nil {
			return nil, parseErr
		}
		conn, err = dialer.DialContext(ctx, "tcp", pURL.Host)
		if err != nil {
			return nil, err
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
		}
		if scheme == "https" {
			connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)
			if _, err := conn.Write([]byte(connectReq)); err != nil {
				conn.Close()
				return nil, err
			}
			br := bufio.NewReader(conn)
			statusLine, err := br.ReadString('\n')
			if err != nil || !strings.Contains(statusLine, "200") {
				conn.Close()
				return nil, fmt.Errorf("CONNECT failed: %q (%v)", statusLine, err)
			}
			for {
				l, err := br.ReadString('\n')
				if err != nil || strings.TrimSpace(l) == "" {
					break
				}
			}
			tlsConn := tls.Client(conn, &tls.Config{
				ServerName:         strings.Split(targetAddr, ":")[0],
				InsecureSkipVerify: true,
			})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			conn = tlsConn
		}
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", targetAddr)
		if err != nil {
			return nil, err
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
		}
		if scheme == "https" {
			tlsConn := tls.Client(conn, &tls.Config{
				ServerName:         strings.Split(targetAddr, ":")[0],
				InsecureSkipVerify: c.opts.InsecureSkipVerify,
			})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			conn = tlsConn
		}
	}
	defer conn.Close()

	uri := BuildRawRequestURI(req.RawPath, req.Query)
	var wire bytes.Buffer
	fmt.Fprintf(&wire, "%s %s HTTP/1.1\r\n", req.Method, uri)

	hasHost := false
	hasContentLen := false
	if req.Headers != nil {
		for _, kv := range req.Headers.Items {
			if kv.IsPseudo || strings.HasPrefix(kv.RawName, ":") {
				continue
			}
			if strings.EqualFold(kv.RawName, "host") {
				hasHost = true
			}
			if strings.EqualFold(kv.RawName, "content-length") {
				hasContentLen = true
			}
			fmt.Fprintf(&wire, "%s: %s\r\n", kv.RawName, kv.Value)
		}
	}
	if !hasHost && req.Authority != "" {
		fmt.Fprintf(&wire, "Host: %s\r\n", req.Authority)
	}
	if len(req.Body) > 0 && !hasContentLen {
		fmt.Fprintf(&wire, "Content-Length: %d\r\n", len(req.Body))
	}
	wire.WriteString("\r\n")
	wire.Write(req.Body)

	if _, err := conn.Write(wire.Bytes()); err != nil {
		return nil, err
	}
	return readRawHTTP1Response(bufio.NewReader(conn))
}

func readRawHTTP1Response(br *bufio.Reader) (*RawResponse, error) {
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	parts := strings.SplitN(strings.TrimSpace(statusLine), " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("malformed HTTP response line %q", statusLine)
	}
	status, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, err
	}
	var headers []models.HeaderKV
	var cl = -1
	chunked := false
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			break
		}
		if k, v, ok := strings.Cut(trimmed, ":"); ok {
			val := strings.TrimLeft(v, " \t")
			headers = append(headers, models.HeaderKV{RawName: k, Value: val})
			if strings.EqualFold(k, "content-length") {
				if n, perr := strconv.Atoi(strings.TrimSpace(val)); perr == nil {
					cl = n
				}
			}
			if strings.EqualFold(k, "transfer-encoding") && strings.Contains(strings.ToLower(val), "chunked") {
				chunked = true
			}
		}
	}
	var body []byte
	if chunked {
		var buf bytes.Buffer
		for {
			szLine, err := br.ReadString('\n')
			if err != nil {
				break
			}
			szStr, _, _ := strings.Cut(strings.TrimSpace(szLine), ";")
			n, err := strconv.ParseInt(szStr, 16, 64)
			if err != nil || n == 0 {
				break
			}
			chunk := make([]byte, n)
			if _, err := io.ReadFull(br, chunk); err != nil {
				break
			}
			buf.Write(chunk)
			_, _ = br.ReadString('\n')
		}
		body = buf.Bytes()
	} else if cl > 0 {
		body = make([]byte, cl)
		if _, err := io.ReadFull(br, body); err != nil {
			return nil, err
		}
	} else if cl < 0 {
		body, _ = io.ReadAll(br)
	}
	return &RawResponse{
		Status:  status,
		Proto:   parts[0],
		Headers: headers,
		Body:    body,
	}, nil
}
