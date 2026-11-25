package capture

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/TaTrap/request-anything/internal/models"
	"github.com/TaTrap/request-anything/pkg/wireclient"
	"golang.org/x/net/http2/hpack"
)

const h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// LoopbackProxy listens on 127.0.0.1:0 and captures raw HTTP/1.1, raw 9-byte HTTP/2 frames + hpack.Decoder,
// and TLS ClientHello JA3/JA4 without conflicting with bogdanfinn/fhttp.
type LoopbackProxy struct {
	listener net.Listener
	ca       *LocalCA
	mu       sync.Mutex
	captured []*models.WireRequest
	conns    map[net.Conn]struct{}
	handler  func(*models.WireRequest) *models.WireResponse
	wg       sync.WaitGroup
	closed   bool
}

// StartLoopbackProxy starts a raw net.Conn loopback diff/MITM proxy on 127.0.0.1:0.
func StartLoopbackProxy(handler func(*models.WireRequest) *models.WireResponse) (*LoopbackProxy, error) {
	ca, err := NewLocalCA()
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &LoopbackProxy{
		listener: ln,
		ca:       ca,
		conns:    make(map[net.Conn]struct{}),
		handler:  handler,
	}
	p.wg.Add(1)
	go p.acceptLoop()
	return p, nil
}

// URL returns the http://127.0.0.1:port address suitable for REQUEST_ANYTHING_DIFF_PROXY.
func (p *LoopbackProxy) URL() string {
	return "http://" + p.listener.Addr().String()
}

// Addr returns host:port of the listener.
func (p *LoopbackProxy) Addr() string {
	return p.listener.Addr().String()
}

// Captured returns a snapshot of all captured WireRequests in arrival order.
func (p *LoopbackProxy) Captured() []*models.WireRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*models.WireRequest, len(p.captured))
	copy(out, p.captured)
	return out
}

// Reset clears captured requests.
func (p *LoopbackProxy) Reset() {
	p.mu.Lock()
	p.captured = nil
	p.mu.Unlock()
}

// Close shuts down the listener, closes active connections immediately, and waits for handlers.
func (p *LoopbackProxy) Close() error {
	p.mu.Lock()
	p.closed = true
	for c := range p.conns {
		_ = c.Close()
	}
	p.mu.Unlock()
	err := p.listener.Close()
	p.wg.Wait()
	return err
}

func (p *LoopbackProxy) trackConn(c net.Conn, add bool) {
	p.mu.Lock()
	if add {
		p.conns[c] = struct{}{}
	} else {
		delete(p.conns, c)
	}
	p.mu.Unlock()
}

func (p *LoopbackProxy) record(req *models.WireRequest) {
	p.mu.Lock()
	p.captured = append(p.captured, req)
	p.mu.Unlock()
}

func (p *LoopbackProxy) acceptLoop() {
	defer p.wg.Done()
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
		}
		p.trackConn(conn, true)
		p.wg.Add(1)
		go func(c net.Conn) {
			defer p.wg.Done()
			defer p.trackConn(c, false)
			defer c.Close()
			p.handleConn(c, "http", "", nil)
		}(conn)
	}
}

type prefixConn struct {
	net.Conn
	r io.Reader
}

func (pc *prefixConn) Read(b []byte) (int, error) {
	return pc.r.Read(b)
}

func (p *LoopbackProxy) handleConn(conn net.Conn, scheme, connectHost string, tlsInfo *ClientHelloInfo) {
	peek := make([]byte, 24)
	n, err := io.ReadAtLeast(conn, peek, 3)
	if err != nil && n == 0 {
		return
	}
	peek = peek[:n]

	// 1. Raw TLS record (0x16 0x03) -> peek ClientHello for JA3/JA4, terminate TLS with local CA
	if len(peek) >= 5 && peek[0] == 0x16 && peek[1] == 0x03 {
		recLen := int(binary.BigEndian.Uint16(peek[3:5]))
		totalNeed := 5 + recLen
		helloBuf := make([]byte, totalNeed)
		copy(helloBuf, peek)
		if totalNeed > len(peek) {
			if _, rerr := io.ReadFull(conn, helloBuf[len(peek):]); rerr != nil {
				return
			}
		}
		chInfo, _ := ParseClientHello(helloBuf)
		sni := connectHost
		if chInfo != nil && chInfo.SNI != "" {
			sni = chInfo.SNI
		}
		cert, cerr := p.ca.CertForHost(sni)
		if cerr != nil {
			return
		}
		pc := &prefixConn{
			Conn: conn,
			r:    io.MultiReader(bytes.NewReader(helloBuf), conn),
		}
		tlsConn := tls.Server(pc, &tls.Config{
			Certificates: []tls.Certificate{*cert},
			NextProtos:   []string{"h2", "http/1.1"},
		})
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		defer tlsConn.Close()
		p.handleConn(tlsConn, "https", sni, chInfo)
		return
	}

	// 2. HTTP/2 Connection Preface -> raw 9-byte H2 frame loop + hpack.Decoder
	if strings.HasPrefix(string(peek), "PRI * HTTP/2.0") {
		prefaceBuf := make([]byte, len(h2Preface))
		copy(prefaceBuf, peek)
		if len(peek) < len(h2Preface) {
			if _, rerr := io.ReadFull(conn, prefaceBuf[len(peek):]); rerr != nil {
				return
			}
		}
		if string(prefaceBuf) == h2Preface {
			p.serveRawHTTP2(conn, scheme, connectHost, tlsInfo)
			return
		}
	}

	// 3. HTTP/1.1 raw reader (supports CONNECT tunnel or direct raw HTTP/1.1)
	pc := &prefixConn{
		Conn: conn,
		r:    io.MultiReader(bytes.NewReader(peek), conn),
	}
	p.serveRawHTTP1(pc, scheme, connectHost, tlsInfo)
}

type h2StreamState struct {
	method      string
	authority   string
	reqScheme   string
	rawTarget   string
	pseudoOrder []string
	headers     []models.HeaderKV
	cookieCount int
	hpackBuf    bytes.Buffer
	bodyBuf     bytes.Buffer
	endStream   bool
}

func (p *LoopbackProxy) serveRawHTTP2(conn net.Conn, scheme, connectHost string, tlsInfo *ClientHelloInfo) {
	// Send Server SETTINGS frame (empty: RFC 7540 header table 4096, max frame 16384).
	_, _ = conn.Write(buildH2Frame(0x04, 0x00, 0, nil))

	var (
		h2Settings       [][2]uint32
		windowUpdate     uint32
		peerMaxFrameSize = 16384
		streams          = make(map[uint32]*h2StreamState)
		activeDecode     *h2StreamState
	)

	getStream := func(id uint32) *h2StreamState {
		st, ok := streams[id]
		if !ok {
			st = &h2StreamState{
				authority: connectHost,
				reqScheme: scheme,
			}
			streams[id] = st
		}
		return st
	}

	dec := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		if activeDecode == nil {
			return
		}
		isPseudo := strings.HasPrefix(f.Name, ":")
		if isPseudo {
			activeDecode.pseudoOrder = append(activeDecode.pseudoOrder, f.Name)
			switch f.Name {
			case ":method":
				activeDecode.method = f.Value
			case ":authority":
				activeDecode.authority = f.Value
			case ":scheme":
				activeDecode.reqScheme = f.Value
			case ":path":
				activeDecode.rawTarget = f.Value
			}
		} else if strings.EqualFold(f.Name, "cookie") {
			activeDecode.cookieCount++
		}
		activeDecode.headers = append(activeDecode.headers, models.HeaderKV{
			RawName:  f.Name,
			Value:    f.Value,
			IsPseudo: isPseudo,
		})
	})

	hdr := make([]byte, 9)
	for {
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		length := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
		frameType := hdr[3]
		flags := hdr[4]
		streamID := binary.BigEndian.Uint32(hdr[5:9]) & 0x7fffffff

		payload := make([]byte, length)
		if length > 0 {
			if _, err := io.ReadFull(conn, payload); err != nil {
				return
			}
		}

		var st *h2StreamState
		switch frameType {
		case 0x04: // SETTINGS
			if flags&0x01 == 0 {
				for i := 0; i+6 <= len(payload); i += 6 {
					id := binary.BigEndian.Uint16(payload[i : i+2])
					val := binary.BigEndian.Uint32(payload[i+2 : i+6])
					h2Settings = append(h2Settings, [2]uint32{uint32(id), val})
					if id == 0x5 && val >= 16384 && val <= 16777215 {
						peerMaxFrameSize = int(val)
					}
				}
				_, _ = conn.Write(buildH2Frame(0x04, 0x01, 0, nil)) // SETTINGS ACK
			}
		case 0x08: // WINDOW_UPDATE
			if len(payload) >= 4 && streamID == 0 {
				windowUpdate = binary.BigEndian.Uint32(payload[:4]) & 0x7fffffff
			}
		case 0x01: // HEADERS
			st = getStream(streamID)
			frag := payload
			padLen := 0
			if flags&0x08 != 0 && len(frag) > 0 { // PADDED
				padLen = int(frag[0])
				frag = frag[1:]
			}
			if flags&0x20 != 0 && len(frag) >= 5 { // PRIORITY
				frag = frag[5:]
			}
			if padLen > 0 && padLen <= len(frag) {
				frag = frag[:len(frag)-padLen]
			}
			st.hpackBuf.Write(frag)
			if flags&0x04 != 0 { // END_HEADERS
				activeDecode = st
				_, _ = dec.Write(st.hpackBuf.Bytes())
				activeDecode = nil
				st.hpackBuf.Reset()
			}
			if flags&0x01 != 0 { // END_STREAM
				st.endStream = true
			}
		case 0x09: // CONTINUATION
			st = getStream(streamID)
			st.hpackBuf.Write(payload)
			if flags&0x04 != 0 { // END_HEADERS
				activeDecode = st
				_, _ = dec.Write(st.hpackBuf.Bytes())
				activeDecode = nil
				st.hpackBuf.Reset()
			}
		case 0x00: // DATA
			st = getStream(streamID)
			frag := payload
			if flags&0x08 != 0 && len(frag) > 0 {
				padLen := int(frag[0])
				frag = frag[1:]
				if padLen <= len(frag) {
					frag = frag[:len(frag)-padLen]
				}
			}
			st.bodyBuf.Write(frag)
			if len(frag) > 0 {
				var wu [4]byte
				binary.BigEndian.PutUint32(wu[:], uint32(len(frag))&0x7fffffff)
				_, _ = conn.Write(buildH2Frame(0x08, 0x00, 0, wu[:]))
				_, _ = conn.Write(buildH2Frame(0x08, 0x00, streamID, wu[:]))
			}
			if flags&0x01 != 0 { // END_STREAM
				st.endStream = true
			}
		case 0x03: // RST_STREAM
			delete(streams, streamID)
		case 0x06: // PING
			if flags&0x01 == 0 {
				_, _ = conn.Write(buildH2Frame(0x06, 0x01, 0, payload))
			}
		case 0x07: // GOAWAY
			return
		}

		if st != nil && st.endStream && streamID != 0 {
			delete(streams, streamID)
			rawPath, rawQuery := splitTarget(st.rawTarget)
			oq := wireclient.ParseRawQuery(rawQuery)
			cookieMode := models.CookieSingleHeader
			if st.cookieCount > 1 {
				cookieMode = models.CookieH2Crumbs
			}
			wb := finalizeCapturedBody(st.bodyBuf.Bytes(), st.headers)
			meta := models.TransportMeta{
				CaptureFidelity: models.FidelityLosslessWire,
				CookieWireMode:  cookieMode,
				Proto:           "HTTP/2",
				H2Settings:      h2Settings,
				H2WindowUpdate:  windowUpdate,
				PseudoOrder:     st.pseudoOrder,
			}
			if tlsInfo != nil {
				meta.TLSVersion = tlsInfo.TLSVersion
				meta.JA3Hash = tlsInfo.JA3Hash
				meta.JA4 = tlsInfo.JA4
				if len(tlsInfo.ALPN) > 0 {
					meta.ALPN = tlsInfo.ALPN[0]
				}
			}
			wireReq := &models.WireRequest{
				Schema:      models.SchemaFixture,
				Method:      st.method,
				Scheme:      st.reqScheme,
				Authority:   st.authority,
				RawPath:     rawPath,
				RawQuery:    rawQuery,
				TrailingAmp: oq.TrailingAmp,
				Query:       oq.Params,
				Headers:     st.headers,
				Body:        wb,
				Transport:   meta,
			}
			p.record(wireReq)

			resp := p.invokeHandler(wireReq)
			writeH2Response(conn, streamID, resp, peerMaxFrameSize)
		}
	}
}

func (p *LoopbackProxy) serveRawHTTP1(conn net.Conn, scheme, connectHost string, tlsInfo *ClientHelloInfo) {
	br := bufio.NewReader(conn)
	reqLine, err := br.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.SplitN(strings.TrimRight(reqLine, "\r\n"), " ", 3)
	if len(parts) < 2 {
		return
	}
	method := strings.ToUpper(parts[0])
	target := parts[1]
	proto := "HTTP/1.1"
	if len(parts) == 3 {
		proto = parts[2]
	}

	var headers []models.HeaderKV
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			break
		}
		if k, v, ok := strings.Cut(trimmed, ":"); ok {
			headers = append(headers, models.HeaderKV{
				RawName: k,
				Value:   strings.TrimLeft(v, " \t"),
			})
		}
	}

	if method == "CONNECT" {
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		p.handleConn(conn, "https", target, tlsInfo)
		return
	}

	var body []byte
	for _, kv := range headers {
		if strings.EqualFold(kv.RawName, "transfer-encoding") && strings.Contains(strings.ToLower(kv.Value), "chunked") {
			body, _ = readHTTP1Chunked(br)
			break
		}
		if strings.EqualFold(kv.RawName, "content-length") {
			if n, perr := strconv.Atoi(strings.TrimSpace(kv.Value)); perr == nil && n > 0 {
				body = make([]byte, n)
				_, _ = io.ReadFull(br, body)
			}
		}
	}

	authority := connectHost
	if authority == "" {
		authority = headerLookup(headers, "host")
	}
	reqScheme := scheme
	rawTarget := target
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		if idx := strings.Index(target, "://"); idx >= 0 {
			reqScheme = target[:idx]
			rest := target[idx+3:]
			if slash := strings.IndexByte(rest, '/'); slash >= 0 {
				authority = rest[:slash]
				rawTarget = rest[slash:]
			} else {
				authority = rest
				rawTarget = "/"
			}
		}
	}
	rawPath, rawQuery := splitTarget(rawTarget)
	oq := wireclient.ParseRawQuery(rawQuery)
	wb := finalizeCapturedBody(body, headers)

	meta := models.TransportMeta{
		CaptureFidelity: models.FidelityLosslessWire,
		CookieWireMode:  models.CookieSingleHeader,
		Proto:           proto,
	}
	if tlsInfo != nil {
		meta.TLSVersion = tlsInfo.TLSVersion
		meta.JA3Hash = tlsInfo.JA3Hash
		meta.JA4 = tlsInfo.JA4
		if len(tlsInfo.ALPN) > 0 {
			meta.ALPN = tlsInfo.ALPN[0]
		}
	}
	wireReq := &models.WireRequest{
		Schema:      models.SchemaFixture,
		Method:      method,
		Scheme:      reqScheme,
		Authority:   authority,
		RawPath:     rawPath,
		RawQuery:    rawQuery,
		TrailingAmp: oq.TrailingAmp,
		Query:       oq.Params,
		Headers:     headers,
		Body:        wb,
		Transport:   meta,
	}
	p.record(wireReq)

	resp := p.invokeHandler(wireReq)
	respBody := resp.Body.RawBytes
	var out bytes.Buffer
	fmt.Fprintf(&out, "HTTP/1.1 %d OK\r\n", resp.Status)
	hasCL := false
	for _, h := range resp.Headers {
		if strings.EqualFold(h.RawName, "content-length") {
			hasCL = true
		}
		fmt.Fprintf(&out, "%s: %s\r\n", h.RawName, h.Value)
	}
	if !hasCL {
		fmt.Fprintf(&out, "Content-Length: %d\r\n", len(respBody))
	}
	out.WriteString("Connection: close\r\n\r\n")
	out.Write(respBody)
	_, _ = conn.Write(out.Bytes())
}

func (p *LoopbackProxy) invokeHandler(req *models.WireRequest) *models.WireResponse {
	if p.handler != nil {
		if resp := p.handler(req); resp != nil {
			return resp
		}
	}
	return &models.WireResponse{
		Status:  200,
		Headers: []models.HeaderKV{{RawName: "content-type", Value: "application/json"}},
		Body:    models.WireBody{RawBytes: []byte(`{"status_code":0,"ok":true}`)},
	}
}

func writeH2Response(conn net.Conn, streamID uint32, resp *models.WireResponse, maxFrameSize int) {
	if maxFrameSize <= 0 {
		maxFrameSize = 16384
	}
	var hdrBlock bytes.Buffer
	enc := hpack.NewEncoder(&hdrBlock)
	_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(resp.Status)})
	for _, h := range resp.Headers {
		if !strings.HasPrefix(h.RawName, ":") {
			_ = enc.WriteField(hpack.HeaderField{Name: strings.ToLower(h.RawName), Value: h.Value})
		}
	}
	hdrBytes := hdrBlock.Bytes()
	body := resp.Body.RawBytes
	for offset := 0; offset < len(hdrBytes) || offset == 0; {
		end := offset + maxFrameSize
		if end > len(hdrBytes) {
			end = len(hdrBytes)
		}
		var chunk []byte
		if offset < end {
			chunk = hdrBytes[offset:end]
		}
		fType := byte(0x01) // HEADERS
		var flags byte
		if offset > 0 {
			fType = 0x09 // CONTINUATION
		} else if len(body) == 0 {
			flags |= 0x01 // END_STREAM
		}
		if end >= len(hdrBytes) {
			flags |= 0x04 // END_HEADERS
		}
		_, _ = conn.Write(buildH2Frame(fType, flags, streamID, chunk))
		offset = end
		if end >= len(hdrBytes) {
			break
		}
	}
	for offset := 0; offset < len(body); {
		end := offset + maxFrameSize
		if end > len(body) {
			end = len(body)
		}
		var flags byte
		if end >= len(body) {
			flags = 0x01 // END_STREAM
		}
		_, _ = conn.Write(buildH2Frame(0x00, flags, streamID, body[offset:end]))
		offset = end
	}
}

func buildH2Frame(frameType, flags byte, streamID uint32, payload []byte) []byte {
	frame := make([]byte, 9+len(payload))
	l := len(payload)
	frame[0] = byte(l >> 16)
	frame[1] = byte(l >> 8)
	frame[2] = byte(l)
	frame[3] = frameType
	frame[4] = flags
	binary.BigEndian.PutUint32(frame[5:9], streamID&0x7fffffff)
	copy(frame[9:], payload)
	return frame
}

func splitTarget(target string) (string, string) {
	if target == "" {
		return "/", ""
	}
	if qIdx := strings.IndexByte(target, '?'); qIdx >= 0 {
		return target[:qIdx], target[qIdx+1:]
	}
	return target, ""
}

func headerLookup(headers []models.HeaderKV, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.RawName, name) {
			return h.Value
		}
	}
	return ""
}

func finalizeCapturedBody(raw []byte, headers []models.HeaderKV) models.WireBody {
	wb := models.WireBody{
		Encoding: headerLookup(headers, "content-encoding"),
		RawBytes: append([]byte(nil), raw...),
	}
	wireclient.FinalizeBody(&wb, headerLookup(headers, "content-type"))
	return wb
}

func readHTTP1Chunked(br *bufio.Reader) ([]byte, error) {
	var out bytes.Buffer
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return out.Bytes(), err
		}
		szStr, _, _ := strings.Cut(strings.TrimSpace(line), ";")
		n, err := strconv.ParseInt(szStr, 16, 64)
		if err != nil || n == 0 {
			return out.Bytes(), nil
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return out.Bytes(), err
		}
		out.Write(buf)
		_, _ = br.ReadString('\n')
	}
}
