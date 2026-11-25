# Whole-Flow Session Porting (`flow.yaml`)

1. **Scenario Matrix:** Capture across `fresh_install`, `warm_start`, `post_login`, `retry`, `restore_session`, `changed_did_iid`, and `error_response`.
2. **Per-Step Portable Snapshots:** Every step with `snapshot_before: true` persists `SessionState` + `NativeSnapshot` (`Payload []byte`) so step N replays deterministically even after a sidecar restart.
3. **Parallel Burst & Branching:** `parallel_group` runs HTTP bursts concurrently while serializing all `NativeOracle` calls per `SessionHandle` via mutex lane; `branch_on` routes error codes (`4001` challenge, `4029` step-up) and pumps `/telemetry/report` packets.
4. **Positive Assertions & Lift:** `gate` validates DID/IID non-empty, zero native exceptions, required endpoint chain, and `reqID` correlation. Lift only at 0% fallback via `flow lift`.
