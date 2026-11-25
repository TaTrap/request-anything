# Wire Traps Showcase (`examples/wire-traps`)

This minimal checkout request (`capture.http`) packs **6 subtle HTTP wire traps** that silently break naive Go `net/http`, `url.Values.Encode()`, and `encoding/json` ports:

1. **Trailing `&`** (`?iid=&resolution=1080*2400&tag=a&tag=b&`)
2. **Literal `*` in query value** (`1080*2400` vs percent-encoded `1080%2A2400`) + duplicate `tag` keys
3. **Non-canonical HTTP/1.1 header casing** (`x-client-ver`, `content-md5` lowercased on the wire)
4. **Android `JSONObject` solidus escaping** (`https:\/\/pay.example.com\/ok` vs unescaped `/`)
5. **Raw JSON numeric lexeme** (`19.0` vs `19`)
6. **`Content-MD5` integrity coupling** (failing `escape_solidus` or `19.0` changes both `Content-Length` and the body MD5 digest)

## Run in 10 Seconds

From the repository root:

```bash
# 1. Watch 6-layer diff catch all 8 mismatches from a naive net/http + json.Marshal port:
request-anything diff ./examples/wire-traps/unit --actual ./examples/wire-traps/naive_broken/post_v2_checkout.fixture.json

# 2. Compile & execute ./examples/wire-traps/unit/port.go live through LoopbackProxy (0 mismatches):
request-anything diff ./examples/wire-traps/unit

# 3. Run the full Hard Gate (gofmt, go vet, go test, secret-hygiene, wire-diff, positive-assertions):
request-anything gate ./examples/wire-traps/unit
```
