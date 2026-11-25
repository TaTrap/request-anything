package models

// Schema identifiers for versioned JSON artifacts.
const (
	SchemaFixture = "request-anything/fixture@1"
	SchemaAnalyze = "request-anything/analyze@1"
	SchemaBridge  = "request-anything/bridge@1"
	SchemaReport  = "request-anything/report@1"
)

// CaptureFidelity tracks how faithful the original traffic source is to the wire.
type CaptureFidelity string

const (
	FidelityLosslessWire CaptureFidelity = "lossless_wire" // Native MITM, PCAP+SSLKEYLOG, raw socket
	FidelityLossyHAR     CaptureFidelity = "lossy_har"     // .har / DevTools (loses H2 pseudo order, crumbs, JA4)
	FidelityHookDump     CaptureFidelity = "hook_dump"     // Frida, gzipped capture SQLite, cURL (raw payload/headers, no TLS wire)
)

// CookieWireMode captures whether HTTP/2 sends Cronet-style separate cookie crumbs or one joined header.
type CookieWireMode string

const (
	CookieSingleHeader CookieWireMode = "single_header" // Cookie: a=1; b=2
	CookieH2Crumbs     CookieWireMode = "h2_crumbs"     // Cronet HTTP/2: each cookie in its own `cookie:` header frame entry
)

// JSONStyle preserves serializer quirks that alter raw byte length and body MD5 digests.
type JSONStyle struct {
	EscapeSolidus      bool `json:"escape_solidus"`       // Escapes '/' as '\/' like Android org.json.JSONObject
	PreserveRawNumbers bool `json:"preserve_raw_numbers"` // Preserves raw numeric lexemes (3 vs 3.0, 1e21)
}

// HeaderKV represents a single ordered HTTP header or HTTP/2 pseudo-header.
type HeaderKV struct {
	RawName  string `json:"raw_name"`
	Value    string `json:"value"`
	IsPseudo bool   `json:"is_pseudo,omitempty"`
}

// QueryParam preserves exact wire parameter order, duplicate keys, encoding, and `=` presence.
type QueryParam struct {
	RawKey   string `json:"raw_key"`
	RawValue string `json:"raw_value"`
	HasEq    bool   `json:"has_eq"`
	Modified bool   `json:"-"`
}

// TransportMeta describes observed TLS/HTTP2/HTTP3 wire characteristics.
type TransportMeta struct {
	CaptureFidelity CaptureFidelity `json:"capture_fidelity"`
	CookieWireMode  CookieWireMode  `json:"cookie_wire_mode"`
	Proto           string          `json:"proto"` // HTTP/1.1 | HTTP/2 | HTTP/3
	TLSVersion      string          `json:"tls_version,omitempty"`
	ALPN            string          `json:"alpn,omitempty"`
	JA3Hash         string          `json:"ja3_hash,omitempty"`
	JA4             string          `json:"ja4,omitempty"`
	H2Settings      [][2]uint32     `json:"h2_settings,omitempty"`
	H2WindowUpdate  uint32          `json:"h2_window_update,omitempty"`
	PseudoOrder     []string        `json:"pseudo_order,omitempty"`
}

// WireBody holds metadata and hashes for raw and decoded HTTP payloads.
type WireBody struct {
	Encoding   string    `json:"encoding"` // raw | gzip | br | zstd | deflate
	Kind       string    `json:"kind"`     // empty | json | form | multipart | protobuf | binary
	JSONStyle  JSONStyle `json:"json_style,omitempty"`
	RawSHA256  string    `json:"raw_sha256"`
	BinFile    string    `json:"bin_file,omitempty"`
	DecodedSHA string    `json:"decoded_sha256,omitempty"`
	RawBytes   []byte    `json:"-"` // In-memory raw payload; persisted to BinFile on disk
}

// WireRequest is a lossless representation of a single HTTP request on the wire.
type WireRequest struct {
	Schema      string        `json:"schema"`
	Method      string        `json:"method"`
	Scheme      string        `json:"scheme"`
	Authority   string        `json:"authority"`
	RawPath     string        `json:"raw_path"`
	RawQuery    string        `json:"raw_query"`
	TrailingAmp bool          `json:"trailing_amp,omitempty"`
	Query       []QueryParam  `json:"query"`
	Headers     []HeaderKV    `json:"headers"`
	Body        WireBody      `json:"body"`
	Transport   TransportMeta `json:"transport"`
}

// WireResponse captures HTTP response status, ordered headers, and body.
type WireResponse struct {
	Status  int        `json:"status"`
	Headers []HeaderKV `json:"headers"`
	Body    WireBody   `json:"body"`
}

// GoldenFixture is the immutable recorded baseline for a single request or scenario case.
type GoldenFixture struct {
	Schema     string        `json:"schema"`
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Source     string        `json:"source"`
	Scenario   string        `json:"scenario,omitempty"` // e.g., fresh_install, warm_start, post_login
	DurationMs float64       `json:"duration_ms,omitempty"`
	Request    WireRequest   `json:"request"`
	Response   *WireResponse `json:"response,omitempty"`
	Tags       []string      `json:"tags,omitempty"`
	CreatedAt  string        `json:"created_at,omitempty"`
}

// FieldRule declares how a dynamic, signed, chained, or ignored field is validated.
type FieldRule struct {
	Target     string            `yaml:"target" json:"target"`                               // e.g. query.ts, header.Signature, body.json.nonce
	Mode       string            `yaml:"mode" json:"mode"`                                   // exact | dynamic | signed | chained | ignore
	SignerMode string            `yaml:"signer_mode,omitempty" json:"signer_mode,omitempty"` // byte_pinned | oracle_verify
	Regex      string            `yaml:"regex,omitempty" json:"regex,omitempty"`
	MinLen     int               `yaml:"min_len,omitempty" json:"min_len,omitempty"`
	MaxLen     int               `yaml:"max_len,omitempty" json:"max_len,omitempty"`
	OracleHook string            `yaml:"oracle_hook,omitempty" json:"oracle_hook,omitempty"` // e.g. builtin:claims-json | builtin:body-md5 | builtin:nonempty | cmd:...
	Claims     map[string]string `yaml:"claims,omitempty" json:"claims,omitempty"`           // Expected bindings inside signature
	FromStep   string            `yaml:"from_step,omitempty" json:"from_step,omitempty"`
	Reason     string            `yaml:"reason,omitempty" json:"reason,omitempty"` // Required for mode=ignore
}

// PositiveAssertion proves business/runtime success beyond error-status parity.
type PositiveAssertion struct {
	Name     string   `yaml:"name" json:"name"`
	Type     string   `yaml:"type" json:"type"` // non_empty_field | status_in | json_path_eq | json_path_ne | required_endpoints | zero_native_exceptions | req_id_correlation
	Target   string   `yaml:"target,omitempty" json:"target,omitempty"`
	Expected []string `yaml:"expected,omitempty" json:"expected,omitempty"`
	Reason   string   `yaml:"reason,omitempty" json:"reason,omitempty"`
}

// ContractSpec locks down every variance and positive success rule for a unit.
type ContractSpec struct {
	Schema             string              `yaml:"schema" json:"schema"`
	Unit               string              `yaml:"unit" json:"unit"`
	StrictTransport    bool                `yaml:"strict_transport" json:"strict_transport"`
	FloatTolerance     *float64            `yaml:"float_tolerance,omitempty" json:"float_tolerance,omitempty"`
	IgnoreKeyOrder     bool                `yaml:"ignore_key_order" json:"ignore_key_order"`
	CookieWireMode     CookieWireMode      `yaml:"cookie_wire_mode" json:"cookie_wire_mode"`
	EscapeSolidus      bool                `yaml:"escape_solidus" json:"escape_solidus"`
	Rules              []FieldRule         `yaml:"rules" json:"rules"`
	PositiveAssertions []PositiveAssertion `yaml:"positive_assertions" json:"positive_assertions"`
}

// DiffFinding describes a single byte/field mismatch or an explicit unknown coverage gap.
type DiffFinding struct {
	Layer    string `json:"layer"` // L1 | L2 | L3 | L4 | L5 | L6
	Path     string `json:"path"`
	Severity string `json:"severity"` // error | unknown
	Kind     string `json:"kind"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	Message  string `json:"message"`
}

// DiffResult summarizes the 6-layer comparison of one case.
type DiffResult struct {
	CaseID   string        `json:"case_id"`
	Passed   bool          `json:"passed"`
	Findings []DiffFinding `json:"findings,omitempty"`
	Unknowns []DiffFinding `json:"unknowns,omitempty"`
	Summary  string        `json:"summary"`
}

// KnownDiffEntry records an explicitly accepted divergence with mandatory justification.
type KnownDiffEntry struct {
	CaseID   string `json:"case_id"`
	Layer    string `json:"layer"`
	Path     string `json:"path"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
	Reason   string `json:"reason"`
}

// Trend tracks consecutive diff pass counts across edits to detect stalling.
type Trend struct {
	Passed  []int `json:"passed"`
	Total   int   `json:"total"`
	Stalled bool  `json:"stalled"`
}

// UnitManifest is persisted as `request-anything.json` inside a scaffolded Go unit folder.
type UnitManifest struct {
	Schema          string   `json:"schema"`
	Root            string   `json:"root"`
	Unit            string   `json:"unit"`
	FixtureFile     string   `json:"fixture_file"`
	ContractFile    string   `json:"contract_file"`
	PackageName     string   `json:"package_name"`
	EndpointName    string   `json:"endpoint_name"`
	SignerMode      string   `json:"signer_mode,omitempty"`
	FloatTolerance  *float64 `json:"float_tolerance,omitempty"`
	IgnoreKeyOrder  bool     `json:"ignore_key_order,omitempty"`
	StrictTransport bool     `json:"strict_transport,omitempty"`
}

// Check represents a single verification item inside GateOutcome.
type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

// GateOutcome is the final verdict produced by `request-anything gate`.
type GateOutcome struct {
	Passed   bool          `json:"passed"`
	Checks   []Check       `json:"checks"`
	Unknowns []DiffFinding `json:"unknowns,omitempty"`
	Trend    *Trend        `json:"trend,omitempty"`
}
