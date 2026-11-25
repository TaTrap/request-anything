package flow

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/TaTrap/request-anything/internal/models"
	"github.com/TaTrap/request-anything/internal/oracle"
	"github.com/TaTrap/request-anything/pkg/wireclient"
	"github.com/bogdanfinn/tls-client/profiles"
	"gopkg.in/yaml.v3"
)

// BranchRule controls conditional DAG jumps based on HTTP status or JSON error code.
type BranchRule struct {
	Status   int    `yaml:"status,omitempty" json:"status,omitempty"`
	JSONPath string `yaml:"json_path,omitempty" json:"json_path,omitempty"`
	Equals   string `yaml:"equals,omitempty" json:"equals,omitempty"`
	NextStep string `yaml:"next_step" json:"next_step"`
}

// Step defines one node in a multi-step flow DAG.
type Step struct {
	ID             string            `yaml:"id" json:"id"`
	Name           string            `yaml:"name" json:"name"`
	Endpoint       string            `yaml:"endpoint" json:"endpoint"`
	UnitDir        string            `yaml:"unit_dir,omitempty" json:"unit_dir,omitempty"`
	Method         string            `yaml:"method" json:"method"`
	RawPath        string            `yaml:"raw_path" json:"raw_path"`
	RawQuery       string            `yaml:"raw_query,omitempty" json:"raw_query,omitempty"`
	Headers        []models.HeaderKV `yaml:"headers,omitempty" json:"headers,omitempty"`
	Body           string            `yaml:"body,omitempty" json:"body,omitempty"`
	SignWithOracle bool              `yaml:"sign_with_oracle,omitempty" json:"sign_with_oracle,omitempty"`
	SnapshotBefore bool              `yaml:"snapshot_before,omitempty" json:"snapshot_before,omitempty"`
	ParallelGroup  string            `yaml:"parallel_group,omitempty" json:"parallel_group,omitempty"`
	BranchOn       []BranchRule      `yaml:"branch_on,omitempty" json:"branch_on,omitempty"`
}

// FlowSpec describes a stateful multi-step session flow (`flow.yaml`).
type FlowSpec struct {
	Schema             string                     `yaml:"schema" json:"schema"`
	Name               string                     `yaml:"name" json:"name"`
	BaseURL            string                     `yaml:"base_url,omitempty" json:"base_url,omitempty"`
	FallbackCmd        []string                   `yaml:"fallback_cmd,omitempty" json:"fallback_cmd,omitempty"`
	Steps              []Step                     `yaml:"steps" json:"steps"`
	PositiveAssertions []models.PositiveAssertion `yaml:"positive_assertions,omitempty" json:"positive_assertions,omitempty"`
}

// SessionState holds mutable cross-step state (DID, IID, cookies, variables) alongside disk-portable native state.
type SessionState struct {
	StepID         string                 `json:"step_id"`
	DeviceID       string                 `json:"device_id,omitempty"`
	InstallID      string                 `json:"install_id,omitempty"`
	Variables      map[string]string      `json:"variables,omitempty"`
	Cookies        map[string]string      `json:"cookies,omitempty"`
	NativeSnapshot *oracle.NativeSnapshot `json:"native_snapshot,omitempty"`
}

// StepResult captures the outcome of executing one DAG step.
type StepResult struct {
	StepID          string               `json:"step_id"`
	RequestID       string               `json:"request_id"`
	Endpoint        string               `json:"endpoint"`
	Status          int                  `json:"status"`
	UsedFallback    bool                 `json:"used_fallback,omitempty"`
	FollowUpPackets []oracle.AsyncPacket `json:"follow_up_packets,omitempty"`
	Response        *models.WireResponse `json:"response,omitempty"`
	NextBranch      string               `json:"next_branch,omitempty"`
}

// FlowOutcome summarizes a full or partial (from-step) flow replay.
type FlowOutcome struct {
	FlowName        string               `json:"flow_name"`
	Passed          bool                 `json:"passed"`
	StepsExecuted   []StepResult         `json:"steps_executed"`
	VisitedPaths    []string             `json:"visited_paths"`
	FallbackCount   int                  `json:"fallback_count"`
	FallbackRate    float64              `json:"fallback_rate"`
	OracleHealth    *oracle.OracleHealth `json:"oracle_health,omitempty"`
	ReqIDCorrelated bool                 `json:"req_id_correlated"`
	Failures        []string             `json:"failures,omitempty"`
}

// StepExecutor sends an OrderedRequest (or mock transport in tests) and returns a WireResponse.
type StepExecutor func(ctx context.Context, state *SessionState, step Step, reqID string) (*models.WireResponse, bool, error)

// PacketSender delivers out-of-band native async packets (e.g. /telemetry/report).
type PacketSender func(ctx context.Context, pkt oracle.AsyncPacket) error

// Runner executes a FlowSpec with per-step snapshots, parallel bursts, branching, and SerializedOracle locking.
type Runner struct {
	FlowDir      string
	Oracle       *oracle.SerializedOracle
	Handle       oracle.SessionHandle
	Executor     StepExecutor
	PacketSender PacketSender
	reqSeq       atomic.Uint64
}

// OpenDefaultOracle connects to rpcURL (or REQUEST_ANYTHING_ORACLE_RPC) if non-empty, else opens an in-process MockOracle.
func OpenDefaultOracle(ctx context.Context, rpcURL string) (*oracle.SerializedOracle, oracle.SessionHandle, func(), error) {
	if rpcURL == "" {
		rpcURL = strings.TrimSpace(os.Getenv("REQUEST_ANYTHING_ORACLE_RPC"))
	}
	var base oracle.NativeOracle
	if rpcURL != "" {
		base = oracle.NewRPCClient(rpcURL)
	} else {
		base = oracle.NewMockOracle()
	}
	so := oracle.NewSerializedOracle(base)
	h, err := so.Open(ctx, oracle.SessionConfig{})
	if err != nil {
		return nil, "", func() {}, err
	}
	return so, h, func() { _ = so.Close(context.Background(), h) }, nil
}

// DefaultHTTPExecutor builds a wireclient-backed StepExecutor targeting baseURL (and optional diff/MITM proxyURL).
func DefaultHTTPExecutor(baseURL string, extraProxy ...string) StepExecutor {
	return func(ctx context.Context, state *SessionState, step Step, reqID string) (*models.WireResponse, bool, error) {
		targetBase := baseURL
		if targetBase == "" {
			targetBase = "https://127.0.0.1"
		}
		u, err := url.Parse(targetBase)
		if err != nil {
			return nil, false, err
		}
		var proxyURL string
		if len(extraProxy) > 0 {
			proxyURL = extraProxy[0]
		}
		c, err := wireclient.NewClient(wireclient.ClientOptions{
			Profile:            profiles.Okhttp4Android13,
			InsecureSkipVerify: true,
			ProxyURL:           proxyURL,
		})
		if err != nil {
			return nil, false, err
		}
		req := &wireclient.OrderedRequest{
			Method:    step.Method,
			Scheme:    u.Scheme,
			Authority: u.Host,
			RawPath:   step.RawPath,
			Query:     wireclient.ParseRawQuery(step.RawQuery),
			Headers:   wireclient.NewOrderedHeaders(step.Headers),
			Body:      []byte(step.Body),
		}
		rawResp, err := c.Do(ctx, req)
		if err != nil {
			return nil, false, err
		}
		return &models.WireResponse{
			Status:  rawResp.Status,
			Headers: rawResp.Headers,
			Body:    models.WireBody{RawBytes: rawResp.Body, Encoding: "raw"},
		}, false, nil
	}
}

// Run executes the flow starting from `startStepID` (or step 0 if empty), restoring snapshot if starting mid-flow.
func (r *Runner) Run(ctx context.Context, spec *FlowSpec, startStepID string, state *SessionState) (*FlowOutcome, error) {
	if spec == nil || len(spec.Steps) == 0 {
		return nil, fmt.Errorf("empty flow spec")
	}
	if state == nil {
		state = &SessionState{
			Variables: make(map[string]string),
			Cookies:   make(map[string]string),
		}
	}
	if state.Variables == nil {
		state.Variables = make(map[string]string)
	}
	if state.Cookies == nil {
		state.Cookies = make(map[string]string)
	}

	stepIdxMap := make(map[string]int, len(spec.Steps))
	for i, s := range spec.Steps {
		stepIdxMap[s.ID] = i
	}

	idx := 0
	if startStepID != "" {
		foundIdx, ok := stepIdxMap[startStepID]
		if !ok {
			return nil, fmt.Errorf("unknown step %q", startStepID)
		}
		if r.FlowDir != "" {
			loadedSnap, lerr := LoadStepSnapshot(r.FlowDir, startStepID)
			if lerr == nil && loadedSnap != nil {
				state = loadedSnap
				if r.Oracle != nil && r.Handle != "" && state.NativeSnapshot != nil {
					if rerr := r.Oracle.Restore(ctx, r.Handle, state.NativeSnapshot); rerr != nil {
						return nil, fmt.Errorf("restoring native snapshot for %s: %w", startStepID, rerr)
					}
				}
			}
		}
		idx = foundIdx
	}

	outcome := &FlowOutcome{
		FlowName:        spec.Name,
		ReqIDCorrelated: true,
	}
	visitedMap := make(map[string]bool)
	var stateMu sync.Mutex

	for idx < len(spec.Steps) {
		cur := spec.Steps[idx]

		// Handle parallel_group burst: collect contiguous steps sharing the same ParallelGroup
		if cur.ParallelGroup != "" {
			grp := cur.ParallelGroup
			end := idx
			for end < len(spec.Steps) && spec.Steps[end].ParallelGroup == grp {
				end++
			}
			batch := spec.Steps[idx:end]
			if cur.SnapshotBefore && r.FlowDir != "" {
				_ = r.saveSnapshot(ctx, cur.ID, state)
			}

			results := make([]StepResult, len(batch))
			errs := make([]error, len(batch))
			var wg sync.WaitGroup
			for bi, st := range batch {
				wg.Add(1)
				go func(pos int, s Step) {
					defer wg.Done()
					reqID := fmt.Sprintf("%s-%d", s.ID, r.reqSeq.Add(1))
					resp, fellBack, err := r.executeSingleStep(ctx, &stateMu, state, s, reqID)
					errs[pos] = err
					sr := StepResult{
						StepID:       s.ID,
						RequestID:    reqID,
						Endpoint:     s.RawPath,
						UsedFallback: fellBack,
						Response:     resp,
					}
					if resp != nil {
						sr.Status = resp.Status
					}
					results[pos] = sr
				}(bi, st)
			}
			wg.Wait()

			for bi, err := range errs {
				if err != nil {
					outcome.Failures = append(outcome.Failures, fmt.Sprintf("step %s: %v", batch[bi].ID, err))
				}
				outcome.StepsExecuted = append(outcome.StepsExecuted, results[bi])
				if !visitedMap[batch[bi].RawPath] {
					visitedMap[batch[bi].RawPath] = true
					outcome.VisitedPaths = append(outcome.VisitedPaths, batch[bi].RawPath)
				}
				if results[bi].UsedFallback {
					outcome.FallbackCount++
				}
				if batch[bi].SignWithOracle && err == nil && r.Oracle != nil && r.Handle != "" {
					if pkts, perr := r.pumpFollowUp(ctx, results[bi].RequestID, results[bi].Response, visitedMap, outcome); perr == nil {
						results[bi].FollowUpPackets = pkts
					} else {
						outcome.ReqIDCorrelated = false
						outcome.Failures = append(outcome.Failures, perr.Error())
					}
				}
			}
			idx = end
			continue
		}

		// Sequential single step
		if cur.SnapshotBefore && r.FlowDir != "" {
			if serr := r.saveSnapshot(ctx, cur.ID, state); serr != nil {
				return nil, serr
			}
		}
		reqID := fmt.Sprintf("%s-%d", cur.ID, r.reqSeq.Add(1))
		resp, fellBack, err := r.executeSingleStep(ctx, &stateMu, state, cur, reqID)
		sr := StepResult{
			StepID:       cur.ID,
			RequestID:    reqID,
			Endpoint:     cur.RawPath,
			UsedFallback: fellBack,
			Response:     resp,
		}
		if resp != nil {
			sr.Status = resp.Status
		}
		if err != nil {
			outcome.Failures = append(outcome.Failures, fmt.Sprintf("step %s: %v", cur.ID, err))
			outcome.StepsExecuted = append(outcome.StepsExecuted, sr)
			break
		}
		if !visitedMap[cur.RawPath] {
			visitedMap[cur.RawPath] = true
			outcome.VisitedPaths = append(outcome.VisitedPaths, cur.RawPath)
		}
		if fellBack {
			outcome.FallbackCount++
		}

		if cur.SignWithOracle && r.Oracle != nil && r.Handle != "" {
			pkts, perr := r.pumpFollowUp(ctx, reqID, resp, visitedMap, outcome)
			if perr != nil {
				outcome.ReqIDCorrelated = false
				outcome.Failures = append(outcome.Failures, perr.Error())
			}
			sr.FollowUpPackets = pkts
		}

		nextIdx := idx + 1
		for _, br := range cur.BranchOn {
			if matchesBranch(br, resp) {
				if targetIdx, exists := stepIdxMap[br.NextStep]; exists {
					sr.NextBranch = br.NextStep
					nextIdx = targetIdx
					break
				}
			}
		}
		outcome.StepsExecuted = append(outcome.StepsExecuted, sr)
		idx = nextIdx
	}

	if len(outcome.StepsExecuted) > 0 {
		outcome.FallbackRate = float64(outcome.FallbackCount) / float64(len(outcome.StepsExecuted))
	}
	if r.Oracle != nil && r.Handle != "" {
		if h, herr := r.Oracle.Health(ctx, r.Handle); herr == nil {
			outcome.OracleHealth = h
			if !h.Healthy || h.WorkerExceptions > 0 {
				outcome.Failures = append(outcome.Failures, fmt.Sprintf("native worker unhealthy: exceptions=%d (%s)", h.WorkerExceptions, h.LastError))
			}
		}
	}
	outcome.Passed = len(outcome.Failures) == 0 && outcome.ReqIDCorrelated
	return outcome, nil
}

func (r *Runner) executeSingleStep(ctx context.Context, mu *sync.Mutex, state *SessionState, s Step, reqID string) (*models.WireResponse, bool, error) {
	if wireclient.ShouldUseOriginal(s.Endpoint) {
		return &models.WireResponse{Status: 200, Body: models.WireBody{RawBytes: []byte(`{"fallback":true}`)}}, true, nil
	}
	expandedQuery := expandVars(s.RawQuery, state, mu)
	expandedBody := expandVars(s.Body, state, mu)
	expandedStep := s
	expandedStep.RawQuery = expandedQuery
	expandedStep.Body = expandedBody
	if r.Oracle != nil && r.Handle != "" && s.SignWithOracle {
		signOut, err := r.Oracle.Sign(ctx, r.Handle, reqID, oracle.SignInput{
			Method:   s.Method,
			URL:      s.RawPath,
			RawQuery: expandedQuery,
			Headers:  expandedStep.Headers,
			Body:     []byte(expandedBody),
		})
		if err != nil {
			return nil, false, err
		}
		if signOut != nil {
			if len(signOut.Headers) > 0 {
				hdrs := wireclient.NewOrderedHeaders(expandedStep.Headers)
				hKeys := make([]string, 0, len(signOut.Headers))
				for k := range signOut.Headers {
					hKeys = append(hKeys, k)
				}
				sort.Strings(hKeys)
				for _, k := range hKeys {
					hdrs.Set(k, signOut.Headers[k])
				}
				expandedStep.Headers = hdrs.Items
			}
			if len(signOut.QueryParams) > 0 {
				oq := wireclient.ParseRawQuery(expandedStep.RawQuery)
				qKeys := make([]string, 0, len(signOut.QueryParams))
				for k := range signOut.QueryParams {
					qKeys = append(qKeys, k)
				}
				sort.Strings(qKeys)
				for _, k := range qKeys {
					oq.Set(k, signOut.QueryParams[k])
				}
				expandedStep.RawQuery = oq.Encode()
			}
		}
		// Flush queued pre-response async packets if any
		if pkts, perr := r.Oracle.PendingPackets(ctx, r.Handle); perr == nil && r.PacketSender != nil {
			for _, p := range pkts {
				_ = r.PacketSender(ctx, p)
			}
		}
	}
	if r.Executor == nil {
		return nil, false, fmt.Errorf("no StepExecutor configured")
	}
	resp, fellBack, err := r.Executor(ctx, state, expandedStep, reqID)
	if err == nil && resp != nil {
		extractResponseState(mu, state, resp)
	}
	return resp, fellBack, err
}

func (r *Runner) pumpFollowUp(ctx context.Context, reqID string, resp *models.WireResponse, visited map[string]bool, out *FlowOutcome) ([]oracle.AsyncPacket, error) {
	delRes, err := r.Oracle.DeliverResponse(ctx, r.Handle, reqID, resp)
	if err != nil {
		return nil, err
	}
	if delRes == nil {
		return nil, nil
	}
	for _, pkt := range delRes.Packets {
		if !visited[pkt.Endpoint] {
			visited[pkt.Endpoint] = true
			out.VisitedPaths = append(out.VisitedPaths, pkt.Endpoint)
		}
		if r.PacketSender != nil {
			if serr := r.PacketSender(ctx, pkt); serr != nil {
				return delRes.Packets, serr
			}
		}
	}
	return delRes.Packets, nil
}

func (r *Runner) saveSnapshot(ctx context.Context, stepID string, state *SessionState) error {
	cp := SessionState{
		StepID:    stepID,
		DeviceID:  state.DeviceID,
		InstallID: state.InstallID,
		Variables: make(map[string]string, len(state.Variables)),
		Cookies:   make(map[string]string, len(state.Cookies)),
	}
	for k, v := range state.Variables {
		cp.Variables[k] = v
	}
	for k, v := range state.Cookies {
		cp.Cookies[k] = v
	}
	if r.Oracle != nil && r.Handle != "" {
		ns, err := r.Oracle.Snapshot(ctx, r.Handle)
		if err != nil {
			return err
		}
		cp.NativeSnapshot = ns
	}
	return SaveStepSnapshot(r.FlowDir, &cp)
}

// SaveStepSnapshot writes a portable snapshot (including NativeSnapshot.Payload) to disk.
func SaveStepSnapshot(flowDir string, snap *SessionState) error {
	dir := filepath.Join(flowDir, ".request-anything", "snapshots")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, snap.StepID+".json"), append(data, '\n'), 0o600)
}

// LoadStepSnapshot restores a portable snapshot from disk.
func LoadStepSnapshot(flowDir, stepID string) (*SessionState, error) {
	data, err := os.ReadFile(filepath.Join(flowDir, ".request-anything", "snapshots", stepID+".json"))
	if err != nil {
		return nil, err
	}
	var st SessionState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// SaveFlow / LoadFlow persist flow.yaml definitions.
func SaveFlow(flowDir string, spec *FlowSpec) error {
	data, err := yaml.Marshal(spec)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(flowDir, "flow.yaml"), data, 0o644)
}

func LoadFlow(flowDir string) (*FlowSpec, error) {
	data, err := os.ReadFile(filepath.Join(flowDir, "flow.yaml"))
	if err != nil {
		return nil, err
	}
	var spec FlowSpec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return nil, err
	}
	return &spec, nil
}

// LiftFlow verifies zero fallback and copies/cleans fallback hooks into a pure Go flow folder.
func LiftFlow(flowDir string, out *FlowOutcome) error {
	if out == nil || !out.Passed {
		return fmt.Errorf("refusing flow lift: flow replay did not pass")
	}
	if out.FallbackCount > 0 || out.FallbackRate > 0 {
		return fmt.Errorf("refusing flow lift: fallback rate %.1f%% must be 0%%", out.FallbackRate*100)
	}
	liftedMarker := filepath.Join(flowDir, "LIFTED.md")
	return os.WriteFile(liftedMarker, []byte(fmt.Sprintf("# Lifted Flow: %s\n\nAll %d steps executed in pure Go with 0%% fallback.\n", out.FlowName, len(out.StepsExecuted))), 0o644)
}

func expandVars(in string, state *SessionState, mu *sync.Mutex) string {
	mu.Lock()
	defer mu.Unlock()
	out := strings.ReplaceAll(in, "{{device_id}}", state.DeviceID)
	out = strings.ReplaceAll(out, "{{install_id}}", state.InstallID)
	for k, v := range state.Variables {
		out = strings.ReplaceAll(out, "{{"+k+"}}", v)
	}
	return out
}

func extractResponseState(mu *sync.Mutex, state *SessionState, resp *models.WireResponse) {
	mu.Lock()
	defer mu.Unlock()
	decoded := wireclient.DecodedResponseBytes(resp)
	if len(decoded) == 0 {
		return
	}
	val, err := wireclient.UnmarshalOrdered(decoded)
	if err != nil {
		return
	}
	om, ok := val.(*wireclient.OrderedMap)
	if !ok {
		return
	}
	if did, exists := om.Get("device_id"); exists && fmt.Sprint(did) != "" {
		state.DeviceID = fmt.Sprint(did)
		state.Variables["device_id"] = state.DeviceID
	}
	if iid, exists := om.Get("install_id"); exists && fmt.Sprint(iid) != "" {
		state.InstallID = fmt.Sprint(iid)
		state.Variables["install_id"] = state.InstallID
	}
}

func matchesBranch(br BranchRule, resp *models.WireResponse) bool {
	if resp == nil {
		return false
	}
	if br.Status > 0 && resp.Status != br.Status {
		return false
	}
	decoded := wireclient.DecodedResponseBytes(resp)
	if br.JSONPath != "" && len(decoded) > 0 {
		val, err := wireclient.UnmarshalOrdered(decoded)
		if err != nil {
			return false
		}
		om, ok := val.(*wireclient.OrderedMap)
		if !ok {
			return false
		}
		v, exists := om.Get(br.JSONPath)
		if !exists {
			return false
		}
		return fmt.Sprint(v) == br.Equals
	}
	return br.Status > 0
}
