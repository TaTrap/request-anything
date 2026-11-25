---
name: request-anything
description: Port HTTP/HTTPS/HTTP2/Protobuf API requests and stateful mobile/web flows to Go with exact wire-level parity, NativeOracle session correlation, and hard verification gates.
---

# Porting Requests to Go with `request-anything`

`request-anything` gives you Wire-Level Ground Truth; you write the Go logic in `port.go`. Never report a port complete until `gate` passes with 0 wire mismatches, 0 undeclared silent ignores, and all `positive-assertions` green.

## Core Loop (Single Endpoint / Unit)

1. **Import & Redact:** `request-anything import` from cURL, HAR, gzipped capture / HTTP Toolkit SQLite, Frida JSON, raw HTTP, or `.mitm`. Secrets (`password`, `device_private_key`, `.secblob`) are redacted by default before hitting fixtures.
2. **Analyze & Scaffold:** `request-anything analyze` & `request-anything scaffold` create `client_gen.go` (generated `bogdanfinn/tls-client` + `fhttp` + `utls` + proxy hook + kill switch), `port.go`, `contract.yaml`, and `TASK.md`.
3. **Edit ONLY `port.go`:**
   - Use `pkg/wireclient.OrderedQuery` verbatim passthrough (`*` in `1216*2623`, trailing `&`, `?iid=` with `HasEq=true`).
   - Use `pkg/wireclient.OrderedHeaders` (`h2_crumbs` vs `single_header`, `ForceHTTP1Raw` for non-canonical HTTP/1.1 casing).
   - Use `pkg/wireclient.MarshalOrdered` (`SetEscapeHTML(false)`, `EscapeSolidus: true` for Android `\/` so body MD5 digests match).
   - If using `NativeOracle` (`unidbg`/Frida), pass every `Sign`, `DeliverResponse(reqID)`, `Snapshot`, `Restore` through `SerializedOracle` (per-handle mutex lane).
4. **Diff & Gate:** Run `request-anything diff <unit>` then `request-anything gate <unit>`.
   - After 3 consecutive `port.go` edits with no pass improvement (`STALL_AFTER=3`), stop editing and ask the user.
   - Respect **Coverage Honesty**: unobserved layers (HPACK dynamic table, QPACK, unvirtualized native RNG, `lossy_har`) are explicitly reported as `unknown`.
