# Port checkout_wire_traps to Go (POST)

Edit **only** ./examples/wire-traps/unit/port.go (and unit tests in port_test.go). Do not edit client_gen.go, pinned_gen.go, or the recorded fixture.

## Recorded Wire Baseline
- Method & Path: POST /v2/checkout
- Proto: HTTP/1.1 | CaptureFidelity: lossless_wire | CookieWireMode: single_header | EscapeSolidus: true
- Raw Query: "iid=&resolution=1080*2400&tag=a&tag=b&" (TrailingAmp=true)

## Rules
1. Keep exact header/query order using pkg/wireclient (OrderedHeaders, OrderedQuery, OrderedJSON).
2. Never use net/http.Header, url.Values.Encode(), or stdlib json.Marshal on unordered maps.
3. Preserve raw '*' and trailing '&' when query parameters are unmodified.
4. If EscapeSolidus=true, marshal JSON with wireclient.JSONMarshalOptions{EscapeSolidus: true} so body digests and Content-Length match.
5. Never put private keys, raw passwords, or .secblob into fixtures.
6. Done means BOTH diff=0 AND positive assertions pass:
   - request-anything diff ./examples/wire-traps/unit
   - request-anything gate ./examples/wire-traps/unit
