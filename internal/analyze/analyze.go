package analyze

import (
	"fmt"
	"sort"
	"strings"

	"github.com/TaTrap/request-anything/internal/ingest"
	"github.com/TaTrap/request-anything/internal/models"
	"github.com/TaTrap/request-anything/internal/risks"
	"github.com/TaTrap/request-anything/pkg/wireclient"
)

// UnitPlan describes one endpoint unit, its dependency wave, readiness score, and risks.
type UnitPlan struct {
	ID        string       `json:"id"`
	Endpoint  string       `json:"endpoint"`
	Method    string       `json:"method"`
	Wave      int          `json:"wave"`
	Readiness int          `json:"readiness"`
	DependsOn []string     `json:"depends_on,omitempty"`
	Produces  []string     `json:"produces,omitempty"`
	Consumes  []string     `json:"consumes,omitempty"`
	Risks     []risks.Risk `json:"risks,omitempty"`
	Fidelity  string       `json:"capture_fidelity"`
}

// ScenarioField summarizes variance across the 7-scenario matrix.
type ScenarioField struct {
	Target         string            `json:"target"`
	Classification string            `json:"classification"` // constant | device_bound | session_bound | per_request_nonce | signed | dynamic
	ValuesByCase   map[string]string `json:"values_by_case"`
}

// Report is the top-level analysis result (`schema: request-anything/analyze@1`).
type Report struct {
	Schema         string          `json:"schema"`
	Units          []UnitPlan      `json:"units"`
	StartHere      []string        `json:"start_here"`
	ScenarioMatrix []ScenarioField `json:"scenario_matrix,omitempty"`
}

// AnalyzeFixtures builds dependency waves, risks, and start_here priority ordering.
func AnalyzeFixtures(fixtures []*models.GoldenFixture) *Report {
	producers := make(map[string]string) // token/cookie -> unit ID
	plans := make([]UnitPlan, 0, len(fixtures))

	for _, f := range fixtures {
		ep := f.Request.RawPath
		id := f.ID
		if id == "" {
			id = ingest.SafeSlug(f.Request.Method + "_" + ep)
		}
		var prod []string
		if f.Response != nil {
			for _, h := range f.Response.Headers {
				if strings.EqualFold(h.RawName, "set-cookie") {
					if cname, _, ok := strings.Cut(h.Value, "="); ok {
						cname = strings.TrimSpace(cname)
						prod = append(prod, "cookie."+cname)
						producers["cookie."+cname] = id
					}
				}
			}
			lowBody := strings.ToLower(string(f.Response.Body.RawBytes))
			for _, tok := range []string{"device_id", "install_id", "session_key", "token"} {
				if strings.Contains(lowBody, `"`+tok+`"`) {
					prod = append(prod, tok)
					if _, exists := producers[tok]; !exists {
						producers[tok] = id
					}
				}
			}
		}
		if strings.Contains(strings.ToLower(ep), "register") {
			prod = append(prod, "device_id", "install_id")
			producers["device_id"] = id
			producers["install_id"] = id
		}

		rList := risks.AnalyzeFixture(f)
		score := 100
		for _, r := range rList {
			switch r.Severity {
			case "high":
				score -= 12
			case "medium":
				score -= 6
			case "low":
				score -= 2
			}
		}
		if score < 0 {
			score = 0
		}

		plans = append(plans, UnitPlan{
			ID:        id,
			Endpoint:  ep,
			Method:    f.Request.Method,
			Readiness: score,
			Produces:  prod,
			Risks:     rList,
			Fidelity:  string(f.Request.Transport.CaptureFidelity),
		})
	}

	// Second pass: resolve consumers & wave numbers
	for i, f := range fixtures {
		var cons []string
		depsSet := make(map[string]bool)
		for _, q := range f.Request.Query {
			if q.RawKey == "device_id" || q.RawKey == "iid" {
				key := "device_id"
				if q.RawKey == "iid" {
					key = "install_id"
				}
				cons = append(cons, key)
				if pid, ok := producers[key]; ok && pid != plans[i].ID {
					depsSet[pid] = true
				}
			}
		}
		for _, h := range f.Request.Headers {
			if strings.EqualFold(h.RawName, "cookie") {
				for _, crumb := range wireclient.SplitCookieCrumbs(h.Value) {
					if cname, _, ok := strings.Cut(crumb, "="); ok {
						ck := "cookie." + cname
						if pid, exists := producers[ck]; exists && pid != plans[i].ID {
							cons = append(cons, ck)
							depsSet[pid] = true
						}
					}
				}
			}
		}
		for d := range depsSet {
			plans[i].DependsOn = append(plans[i].DependsOn, d)
		}
		sort.Strings(plans[i].DependsOn)
		plans[i].Consumes = cons
		if len(plans[i].DependsOn) > 0 {
			plans[i].Wave = 1
		}
		if strings.Contains(strings.ToLower(plans[i].Endpoint), "login") {
			plans[i].Wave = 1
		} else if len(plans[i].DependsOn) > 0 {
			plans[i].Wave = 2
		}
	}

	sort.SliceStable(plans, func(i, j int) bool {
		if plans[i].Wave != plans[j].Wave {
			return plans[i].Wave < plans[j].Wave
		}
		return plans[i].Readiness > plans[j].Readiness
	})

	start := make([]string, 0, len(plans))
	for _, p := range plans {
		start = append(start, p.ID)
	}

	return &Report{
		Schema:         models.SchemaAnalyze,
		Units:          plans,
		StartHere:      start,
		ScenarioMatrix: ClassifyScenarioMatrix(fixtures),
	}
}

// ClassifyScenarioMatrix compares values across scenario captures (fresh_install, warm_start, post_login, retry, restore_session, changed_did_iid, error_response).
func ClassifyScenarioMatrix(fixtures []*models.GoldenFixture) []ScenarioField {
	if len(fixtures) < 2 {
		return nil
	}
	fieldValues := make(map[string]map[string]string)
	record := func(target, scenario, val string) {
		if scenario == "" {
			scenario = "default"
		}
		m, ok := fieldValues[target]
		if !ok {
			m = make(map[string]string)
			fieldValues[target] = m
		}
		m[scenario] = val
	}

	for idx, f := range fixtures {
		sc := f.Scenario
		if sc == "" {
			sc = fmt.Sprintf("case_%d", idx+1)
		}
		for _, q := range f.Request.Query {
			record("query."+q.RawKey, sc, q.RawValue)
		}
		for _, h := range f.Request.Headers {
			if !h.IsPseudo {
				record("header."+strings.ToLower(h.RawName), sc, h.Value)
			}
		}
	}

	var keys []string
	for k := range fieldValues {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []ScenarioField
	for _, k := range keys {
		vals := fieldValues[k]
		uniq := make(map[string]bool)
		for _, v := range vals {
			uniq[v] = true
		}
		class := "constant"
		if len(uniq) > 1 {
			low := strings.ToLower(k)
			switch {
			case low == "header.signature" || low == "header.content-md5" || strings.Contains(low, "sig") || strings.HasSuffix(low, "-md5") || strings.Contains(low, "hmac"):
				class = "signed"
			case strings.Contains(low, "device_id") || strings.Contains(low, "iid") || strings.Contains(low, "did"):
				class = "device_bound"
			case strings.Contains(low, "cookie") || strings.Contains(low, "token") || strings.Contains(low, "session"):
				class = "session_bound"
			case strings.Contains(low, "ts") || strings.Contains(low, "timestamp") || strings.Contains(low, "nonce"):
				class = "per_request_nonce"
			default:
				class = "dynamic"
			}
		}
		out = append(out, ScenarioField{
			Target:         k,
			Classification: class,
			ValuesByCase:   vals,
		})
	}
	return out
}
