package capture

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// ClientHelloInfo captures raw TLS ClientHello metadata for JA3 and JA4 calculation.
type ClientHelloInfo struct {
	TLSVersion   string
	SNI          string
	ALPN         []string
	CipherSuites []uint16
	Extensions   []uint16
	Curves       []uint16
	PointFormats []uint8
	SigAlgs      []uint16
	JA3String    string
	JA3Hash      string
	JA4          string
}

func isGREASE(v uint16) bool {
	return (v&0x0f0f) == 0x0a0a && (v>>8) == (v&0xff)
}

// ParseClientHello inspects raw TLS record bytes (beginning with 0x16) and computes JA3 + JA4.
func ParseClientHello(raw []byte) (*ClientHelloInfo, error) {
	if len(raw) < 9 || raw[0] != 0x16 {
		return nil, fmt.Errorf("not a TLS handshake record")
	}
	recLen := int(binary.BigEndian.Uint16(raw[3:5]))
	if len(raw) < 5+recLen || recLen < 4 {
		return nil, fmt.Errorf("truncated TLS ClientHello record")
	}
	hs := raw[5 : 5+recLen]
	if hs[0] != 0x01 {
		return nil, fmt.Errorf("handshake type 0x%02x is not ClientHello", hs[0])
	}
	if len(hs) < 4+34 {
		return nil, fmt.Errorf("short ClientHello")
	}
	pos := 4
	legacyVer := binary.BigEndian.Uint16(hs[pos : pos+2])
	pos += 2 + 32 // skip version + random

	if pos >= len(hs) {
		return nil, fmt.Errorf("missing session id len")
	}
	sessLen := int(hs[pos])
	pos++
	if pos+sessLen+2 > len(hs) {
		return nil, fmt.Errorf("truncated session id")
	}
	pos += sessLen

	csLen := int(binary.BigEndian.Uint16(hs[pos : pos+2]))
	pos += 2
	if pos+csLen > len(hs) {
		return nil, fmt.Errorf("truncated cipher suites")
	}
	var ciphers []uint16
	for i := 0; i+1 < csLen; i += 2 {
		c := binary.BigEndian.Uint16(hs[pos+i : pos+i+2])
		if !isGREASE(c) {
			ciphers = append(ciphers, c)
		}
	}
	pos += csLen

	if pos >= len(hs) {
		return nil, fmt.Errorf("missing compression len")
	}
	compLen := int(hs[pos])
	pos += 1 + compLen
	if pos+2 > len(hs) {
		return nil, fmt.Errorf("missing extensions len")
	}
	extTotal := int(binary.BigEndian.Uint16(hs[pos : pos+2]))
	pos += 2
	if pos+extTotal > len(hs) {
		extTotal = len(hs) - pos
	}

	info := &ClientHelloInfo{
		TLSVersion:   fmt.Sprintf("0x%04x", legacyVer),
		CipherSuites: ciphers,
	}
	supportedTLS13 := false
	extEnd := pos + extTotal
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(hs[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(hs[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > extEnd {
			break
		}
		extData := hs[pos : pos+extLen]
		pos += extLen
		if !isGREASE(extType) {
			info.Extensions = append(info.Extensions, extType)
		}

		switch extType {
		case 0x0000: // SNI
			if len(extData) >= 5 {
				nameLen := int(binary.BigEndian.Uint16(extData[3:5]))
				if 5+nameLen <= len(extData) {
					info.SNI = string(extData[5 : 5+nameLen])
				}
			}
		case 0x000a: // supported_groups
			if len(extData) >= 2 {
				l := int(binary.BigEndian.Uint16(extData[:2]))
				for i := 2; i+1 < len(extData) && i < 2+l; i += 2 {
					g := binary.BigEndian.Uint16(extData[i : i+2])
					if !isGREASE(g) {
						info.Curves = append(info.Curves, g)
					}
				}
			}
		case 0x000b: // ec_point_formats
			if len(extData) >= 1 {
				l := int(extData[0])
				for i := 1; i < len(extData) && i < 1+l; i++ {
					info.PointFormats = append(info.PointFormats, extData[i])
				}
			}
		case 0x000d: // signature_algorithms
			if len(extData) >= 2 {
				l := int(binary.BigEndian.Uint16(extData[:2]))
				for i := 2; i+1 < len(extData) && i < 2+l; i += 2 {
					info.SigAlgs = append(info.SigAlgs, binary.BigEndian.Uint16(extData[i:i+2]))
				}
			}
		case 0x0010: // ALPN
			if len(extData) >= 2 {
				l := int(binary.BigEndian.Uint16(extData[:2]))
				p := 2
				for p < len(extData) && p < 2+l {
					n := int(extData[p])
					p++
					if p+n <= len(extData) {
						info.ALPN = append(info.ALPN, string(extData[p:p+n]))
					}
					p += n
				}
			}
		case 0x002b: // supported_versions
			if len(extData) >= 1 {
				l := int(extData[0])
				for i := 1; i+1 < len(extData) && i < 1+l; i += 2 {
					v := binary.BigEndian.Uint16(extData[i : i+2])
					if v == 0x0304 {
						supportedTLS13 = true
					}
				}
			}
		}
	}

	if supportedTLS13 {
		info.TLSVersion = "TLS 1.3"
	} else if legacyVer == 0x0303 {
		info.TLSVersion = "TLS 1.2"
	}

	info.JA3String = fmt.Sprintf("%d,%s,%s,%s,%s",
		legacyVer,
		joinUint16Dec(info.CipherSuites),
		joinUint16Dec(info.Extensions),
		joinUint16Dec(info.Curves),
		joinUint8Dec(info.PointFormats),
	)
	sum := md5.Sum([]byte(info.JA3String))
	info.JA3Hash = hex.EncodeToString(sum[:])

	verCode := "12"
	if supportedTLS13 {
		verCode = "13"
	}
	sniFlag := "i"
	if info.SNI != "" {
		sniFlag = "d"
	}
	alpnCode := "00"
	if len(info.ALPN) > 0 && len(info.ALPN[0]) >= 2 {
		a := info.ALPN[0]
		alpnCode = string([]byte{a[0], a[len(a)-1]})
	} else if len(info.ALPN) > 0 && info.ALPN[0] == "h2" {
		alpnCode = "h2"
	}
	ja4A := fmt.Sprintf("t%s%s%02d%02d%s", verCode, sniFlag, len(info.CipherSuites)%100, len(info.Extensions)%100, alpnCode)

	sortedCiphers := append([]uint16(nil), info.CipherSuites...)
	sort.Slice(sortedCiphers, func(i, j int) bool { return sortedCiphers[i] < sortedCiphers[j] })
	sortedExts := make([]uint16, 0, len(info.Extensions))
	for _, e := range info.Extensions {
		if e != 0x0000 && e != 0x0010 {
			sortedExts = append(sortedExts, e)
		}
	}
	sort.Slice(sortedExts, func(i, j int) bool { return sortedExts[i] < sortedExts[j] })
	cHash := sha256Prefix12(joinUint16Hex(sortedCiphers))
	extSig := joinUint16Hex(sortedExts)
	if len(info.SigAlgs) > 0 {
		extSig += "_" + joinUint16Hex(info.SigAlgs)
	}
	eHash := sha256Prefix12(extSig)
	info.JA4 = fmt.Sprintf("%s_%s_%s", ja4A, cHash, eHash)

	return info, nil
}

func sha256Prefix12(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func joinUint16Dec(vals []uint16) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, "-")
}

func joinUint8Dec(vals []uint8) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, "-")
}

func joinUint16Hex(vals []uint16) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}
