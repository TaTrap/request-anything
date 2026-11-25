package scaffold

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/TaTrap/request-anything/internal/contract"
	"github.com/TaTrap/request-anything/internal/ingest"
	"github.com/TaTrap/request-anything/internal/models"
	"github.com/TaTrap/request-anything/internal/pin"
	"github.com/TaTrap/request-anything/internal/recording"
	"github.com/TaTrap/request-anything/internal/redact"
)

const ManifestFile = "request-anything.json"

// Options controls scaffolding a Go request-porting unit.
type Options struct {
	Root         string
	OutDir       string
	Fixture      *models.GoldenFixture
	PackageName  string
	EndpointName string
	StubPort     bool // When true, writes panic("todo") stubs in port.go; when false, writes clean baseline pass-through port
	PinClock     bool
	Force        bool
}

// Outcome describes all generated artifacts.
type Outcome struct {
	UnitDir      string `json:"unit_dir"`
	ManifestPath string `json:"manifest_path"`
	ContractPath string `json:"contract_path"`
	PortPath     string `json:"port_path"`
	ClientGen    string `json:"client_gen_path"`
	FixturePath  string `json:"fixture_path"`
}

// Scaffold creates a Go unit directory with separated client_gen.go (generated) and port.go (AI-edited).
func Scaffold(opts Options) (*Outcome, error) {
	if opts.Fixture == nil {
		return nil, fmt.Errorf("scaffold requires a GoldenFixture")
	}
	if opts.OutDir == "" {
		return nil, fmt.Errorf("OutDir is required")
	}
	absOut, err := filepath.Abs(opts.OutDir)
	if err != nil {
		return nil, err
	}
	if !opts.Force {
		if _, err := os.Stat(filepath.Join(absOut, ManifestFile)); err == nil {
			return nil, fmt.Errorf("%s already exists; pass --force or run refresh", absOut)
		}
	}
	if err := os.MkdirAll(absOut, 0o755); err != nil {
		return nil, err
	}

	pkg := opts.PackageName
	if pkg == "" {
		pkg = sanitizeGoPkg(filepath.Base(absOut))
	}
	epName := opts.EndpointName
	if epName == "" {
		epName = opts.Fixture.Name
	}

	// Save redacted fixture inside unitDir/fixtures/ and reload the redacted baseline so secrets never reach code/TASK.md.
	fixDir := filepath.Join(absOut, "fixtures")
	fixPath, _, err := ingest.SaveFixture(fixDir, opts.Fixture, redact.Options{})
	if err != nil {
		return nil, err
	}
	cleanFix, err := ingest.LoadFixture(fixPath)
	if err != nil {
		return nil, err
	}
	relFix, _ := filepath.Rel(absOut, fixPath)

	// Generate & save contract.yaml + TASK.md from the redacted fixture
	spec := contract.Generate(epName, cleanFix)
	if err := contract.Save(absOut, spec); err != nil {
		return nil, err
	}
	taskText := contract.GenerateTaskMD(absOut, epName, cleanFix, spec)
	if err := os.WriteFile(filepath.Join(absOut, contract.TaskFile), []byte(taskText), 0o644); err != nil {
		return nil, err
	}

	if opts.PinClock {
		if err := pin.Save(absOut, pin.DefaultPin()); err != nil {
			return nil, err
		}
	}

	signerMode := detectSignerMode(spec)
	manifest := models.UnitManifest{
		Schema:       models.SchemaBridge,
		Root:         portableRoot(absOut, opts.Root),
		Unit:         epName,
		FixtureFile:  filepath.ToSlash(relFix),
		ContractFile: contract.FileName,
		PackageName:  pkg,
		EndpointName: epName,
		SignerMode:   signerMode,
	}
	manPath := filepath.Join(absOut, ManifestFile)
	manBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(manPath, append(manBytes, '\n'), 0o644); err != nil {
		return nil, err
	}

	if err := os.WriteFile(filepath.Join(absOut, "pinned_gen.go"), []byte(pin.GeneratedGoSource(pkg)), 0o644); err != nil {
		return nil, err
	}
	clientGenPath := filepath.Join(absOut, "client_gen.go")
	if err := os.WriteFile(clientGenPath, []byte(renderClientGen(pkg, epName, cleanFix)), 0o644); err != nil {
		return nil, err
	}
	portPath := filepath.Join(absOut, "port.go")
	if err := os.WriteFile(portPath, []byte(renderPortGo(pkg, cleanFix, opts.StubPort)), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(absOut, "port_test.go"), []byte(renderPortTest(pkg)), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(absOut, "wire_capture_gen_test.go"), []byte(renderWireCaptureTest(pkg, signerMode != "")), 0o644); err != nil {
		return nil, err
	}
	if err := ensureGoMod(absOut, pkg); err != nil {
		return nil, err
	}

	if err := recording.SaveFingerprint(absOut, epName, absOut, recording.UnitInputs(contract.FileName)); err != nil {
		return nil, err
	}

	return &Outcome{
		UnitDir:      absOut,
		ManifestPath: manPath,
		ContractPath: filepath.Join(absOut, contract.FileName),
		PortPath:     portPath,
		ClientGen:    clientGenPath,
		FixturePath:  fixPath,
	}, nil
}

// Refresh parses port.go AST and regenerates client_gen.go, pinned_gen.go, wire_capture_gen_test.go, TASK.md,
// and updates recorded-from.json WITHOUT touching port.go.
func Refresh(unitDir string) error {
	absDir, err := filepath.Abs(unitDir)
	if err != nil {
		return err
	}
	manBytes, err := os.ReadFile(filepath.Join(absDir, ManifestFile))
	if err != nil {
		return err
	}
	var m models.UnitManifest
	if err := json.Unmarshal(manBytes, &m); err != nil {
		return err
	}
	fix, err := ingest.LoadFixture(filepath.Join(absDir, filepath.FromSlash(m.FixtureFile)))
	if err != nil {
		return err
	}
	spec, err := contract.Load(absDir)
	if err != nil {
		spec = contract.Generate(m.EndpointName, fix)
	}

	// Verify port.go parses cleanly and exports required symbols
	portPath := filepath.Join(absDir, "port.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, portPath, nil, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", portPath, err)
	}
	found := map[string]bool{}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil {
			found[fn.Name.Name] = true
		}
	}
	for _, reqFn := range []string{"BuildRequest", "SignRequest", "ParseResponse"} {
		if !found[reqFn] {
			return fmt.Errorf("port.go missing required function %s", reqFn)
		}
	}

	signerMode := detectSignerMode(spec)
	if m.SignerMode != signerMode {
		m.SignerMode = signerMode
		if updated, merr := json.MarshalIndent(m, "", "  "); merr == nil {
			_ = os.WriteFile(filepath.Join(absDir, ManifestFile), append(updated, '\n'), 0o644)
		}
	}

	if err := os.WriteFile(filepath.Join(absDir, "pinned_gen.go"), []byte(pin.GeneratedGoSource(m.PackageName)), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(absDir, "client_gen.go"), []byte(renderClientGen(m.PackageName, m.EndpointName, fix)), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(absDir, "wire_capture_gen_test.go"), []byte(renderWireCaptureTest(m.PackageName, m.SignerMode != "")), 0o644); err != nil {
		return err
	}
	taskText := contract.GenerateTaskMD(absDir, m.EndpointName, fix, spec)
	if err := os.WriteFile(filepath.Join(absDir, contract.TaskFile), []byte(taskText), 0o644); err != nil {
		return err
	}
	if err := ensureGoMod(absDir, m.PackageName); err != nil {
		return err
	}
	return recording.SaveFingerprint(absDir, m.EndpointName, absDir, recording.UnitInputs(m.ContractFile))
}

func detectSignerMode(spec *models.ContractSpec) string {
	if spec == nil {
		return ""
	}
	for _, r := range spec.Rules {
		if r.Mode == "signed" {
			if r.SignerMode != "" {
				return r.SignerMode
			}
			return "oracle_verify"
		}
	}
	return ""
}

func useEmbeddedBody(fix *models.GoldenFixture) bool {
	if fix == nil || len(fix.Request.Body.RawBytes) == 0 || fix.Request.Body.BinFile == "" {
		return false
	}
	enc := strings.ToLower(strings.TrimSpace(fix.Request.Body.Encoding))
	if enc != "" && enc != "raw" && enc != "identity" {
		return true
	}
	if fix.Request.Body.Kind == "protobuf" || fix.Request.Body.Kind == "binary" {
		return true
	}
	return !utf8.Valid(fix.Request.Body.RawBytes)
}

func sanitizeGoPkg(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" || (out[0] >= '0' && out[0] <= '9') {
		return "reqport"
	}
	return out
}

func portableRoot(absOut, root string) string {
	if root == "" {
		return "."
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "."
	}
	if rel, rerr := filepath.Rel(absOut, absRoot); rerr == nil && !filepath.IsAbs(rel) {
		return filepath.ToSlash(rel)
	}
	return "."
}

func findAncestorGoMod(dir string) string {
	cur := dir
	for {
		if _, err := os.Stat(filepath.Join(cur, "go.mod")); err == nil {
			return cur
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return ""
		}
		cur = parent
	}
}

// FindModuleRoot locates the github.com/TaTrap/request-anything Go module directory on disk.
func FindModuleRoot() (string, error) {
	return findRequestAnythingModuleRoot()
}

func findRequestAnythingModuleRoot() (string, error) {
	checkDir := func(start string) string {
		cur := start
		for cur != "" {
			gm := filepath.Join(cur, "go.mod")
			if data, err := os.ReadFile(gm); err == nil {
				if strings.Contains(string(data), "module github.com/TaTrap/request-anything") {
					return cur
				}
			}
			parent := filepath.Dir(cur)
			if parent == cur {
				break
			}
			cur = parent
		}
		return ""
	}
	if envRoot := os.Getenv("REQUEST_ANYTHING_MOD_ROOT"); envRoot != "" {
		if found := checkDir(envRoot); found != "" {
			return found, nil
		}
	}
	for _, home := range []string{os.Getenv("HOME"), os.Getenv("USERPROFILE")} {
		if home == "" {
			continue
		}
		if b, rerr := os.ReadFile(filepath.Join(home, ".config", "request-anything", "modroot")); rerr == nil {
			if p := strings.TrimSpace(string(b)); p != "" {
				if found := checkDir(p); found != "" {
					return found, nil
				}
			}
		}
	}
	if uh, herr := os.UserHomeDir(); herr == nil && uh != "" {
		if b, rerr := os.ReadFile(filepath.Join(uh, ".config", "request-anything", "modroot")); rerr == nil {
			if p := strings.TrimSpace(string(b)); p != "" {
				if found := checkDir(p); found != "" {
					return found, nil
				}
			}
		}
	}
	if exe, err := os.Executable(); err == nil {
		if found := checkDir(filepath.Dir(exe)); found != "" {
			return found, nil
		}
	}
	if _, file, _, ok := runtime.Caller(0); ok {
		if found := checkDir(filepath.Dir(file)); found != "" {
			return found, nil
		}
	}
	if wd, err := os.Getwd(); err == nil {
		if found := checkDir(wd); found != "" {
			return found, nil
		}
	}
	return "", fmt.Errorf("cannot locate github.com/TaTrap/request-anything module root for standalone go.mod generation")
}

func parseGoModMeta(text string) (goVersion string, reqLines []string, reqMods map[string]bool) {
	goVersion = "go 1.24.0"
	reqMods = make(map[string]bool)
	inRequire := false
	for _, rawLine := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "go ") {
			goVersion = line
			continue
		}
		if line == "require (" {
			inRequire = true
			continue
		}
		if inRequire {
			if line == ")" {
				inRequire = false
				continue
			}
			if line != "" && !strings.HasPrefix(line, "//") {
				reqLines = append(reqLines, "\t"+line)
				fields := strings.Fields(line)
				if len(fields) > 0 {
					reqMods[fields[0]] = true
				}
			}
			continue
		}
		if strings.HasPrefix(line, "require ") && !strings.Contains(line, "(") {
			rest := strings.TrimSpace(strings.TrimPrefix(line, "require "))
			if rest != "" {
				reqLines = append(reqLines, "\t"+rest)
				fields := strings.Fields(rest)
				if len(fields) > 0 {
					reqMods[fields[0]] = true
				}
			}
		}
	}
	return goVersion, reqLines, reqMods
}

func ensureGoMod(unitDir, pkg string) error {
	modRoot, err := findRequestAnythingModuleRoot()
	if err != nil {
		return err
	}
	rootGoModBytes, err := os.ReadFile(filepath.Join(modRoot, "go.mod"))
	if err != nil {
		return err
	}
	rootGoMod := string(rootGoModBytes)
	goVersion, reqLines, _ := parseGoModMeta(rootGoMod)

	ancDir := findAncestorGoMod(unitDir)
	if ancDir != "" {
		return ensureHostGoMod(ancDir, modRoot, rootGoMod, reqLines)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "module %s\n\n%s\n\nrequire (\n\tgithub.com/TaTrap/request-anything v0.0.0\n", pkg, goVersion)
	for _, rl := range reqLines {
		b.WriteString(rl)
		b.WriteByte('\n')
	}
	fmt.Fprintf(&b, ")\n\nreplace github.com/TaTrap/request-anything => %s\n", filepath.ToSlash(modRoot))
	if err := os.WriteFile(filepath.Join(unitDir, "go.mod"), []byte(b.String()), 0o644); err != nil {
		return err
	}
	if sumBytes, err := os.ReadFile(filepath.Join(modRoot, "go.sum")); err == nil {
		_ = os.WriteFile(filepath.Join(unitDir, "go.sum"), sumBytes, 0o644)
	}
	return nil
}

func ensureHostGoMod(ancDir, modRoot, rootGoMod string, rootReqLines []string) error {
	hostGoModPath := filepath.Join(ancDir, "go.mod")
	hostBytes, err := os.ReadFile(hostGoModPath)
	if err != nil {
		return err
	}
	hostText := string(hostBytes)
	if strings.Contains(hostText, "module github.com/TaTrap/request-anything") {
		return nil // Already inside request-anything repository
	}

	_, _, hostMods := parseGoModMeta(hostText)
	var missing []string
	if !hostMods["github.com/TaTrap/request-anything"] {
		missing = append(missing, "\tgithub.com/TaTrap/request-anything v0.0.0")
	}
	for _, rl := range rootReqLines {
		fields := strings.Fields(rl)
		if len(fields) > 0 && !hostMods[fields[0]] {
			missing = append(missing, rl)
		}
	}

	updated := strings.ReplaceAll(hostText, "\r\n", "\n")
	if !strings.HasSuffix(updated, "\n") {
		updated += "\n"
	}
	if len(missing) > 0 {
		updated += "\nrequire (\n" + strings.Join(missing, "\n") + "\n)\n"
	}
	replaceTarget := "replace github.com/TaTrap/request-anything => " + filepath.ToSlash(modRoot)
	if !strings.Contains(updated, "replace github.com/TaTrap/request-anything") {
		updated += "\n" + replaceTarget + "\n"
	}
	if updated != strings.ReplaceAll(hostText, "\r\n", "\n") {
		if err := os.WriteFile(hostGoModPath, []byte(updated), 0o644); err != nil {
			return err
		}
	}

	return mergeGoSum(filepath.Join(modRoot, "go.sum"), filepath.Join(ancDir, "go.sum"))
}

func mergeGoSum(srcPath, dstPath string) error {
	srcBytes, err := os.ReadFile(srcPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var dstText string
	seen := make(map[string]bool)
	if dstBytes, rerr := os.ReadFile(dstPath); rerr == nil {
		dstText = strings.ReplaceAll(string(dstBytes), "\r\n", "\n")
		for _, line := range strings.Split(dstText, "\n") {
			t := strings.TrimSpace(line)
			if t != "" {
				seen[t] = true
			}
		}
	}
	var additions []string
	for _, line := range strings.Split(strings.ReplaceAll(string(srcBytes), "\r\n", "\n"), "\n") {
		t := strings.TrimSpace(line)
		if t != "" && !seen[t] {
			seen[t] = true
			additions = append(additions, t)
		}
	}
	if len(additions) == 0 {
		return nil
	}
	if dstText != "" && !strings.HasSuffix(dstText, "\n") {
		dstText += "\n"
	}
	dstText += strings.Join(additions, "\n") + "\n"
	return os.WriteFile(dstPath, []byte(dstText), 0o644)
}

func renderClientGen(pkg, endpoint string, fix *models.GoldenFixture) string {
	embedImport := ""
	embedDecl := ""
	if useEmbeddedBody(fix) {
		embedImport = "\n\t_ \"embed\""
		embedDecl = fmt.Sprintf("\n//go:embed fixtures/%s\nvar recordedRequestBody []byte\n", fix.Request.Body.BinFile)
	}
	return fmt.Sprintf(`// Code generated by request-anything. DO NOT EDIT.
package %s

import (
	"context"%s
	"fmt"

	"github.com/TaTrap/request-anything/pkg/models"
	"github.com/TaTrap/request-anything/pkg/oracle"
	"github.com/TaTrap/request-anything/pkg/wireclient"
	"github.com/bogdanfinn/tls-client/profiles"
)
%s
// ClientRunner wraps wireclient, NativeOracle correlation, and kill switches.
type ClientRunner struct {
	Client   *wireclient.Client
	Oracle   oracle.NativeOracle
	Handle   oracle.SessionHandle
	Endpoint string
}

func NewClientRunner(o oracle.NativeOracle, h oracle.SessionHandle) (*ClientRunner, error) {
	c, err := wireclient.NewClient(wireclient.ClientOptions{
		Profile: profiles.Okhttp4Android13,
	})
	if err != nil {
		return nil, err
	}
	return &ClientRunner{
		Client:   c,
		Oracle:   o,
		Handle:   h,
		Endpoint: %q,
	}, nil
}

func (r *ClientRunner) Execute(ctx context.Context, state *SessionState, reqID string, in Input) (Output, *wireclient.RawResponse, error) {
	if wireclient.ShouldUseOriginal(r.Endpoint) {
		return Output{}, nil, fmt.Errorf("kill switch active: REQUEST_ANYTHING_EP_%s=original (%%s)", r.Endpoint)
	}
	req, err := BuildRequest(ctx, state, in)
	if err != nil {
		return Output{}, nil, err
	}
	if err := SignRequest(ctx, state, r.Oracle, r.Handle, reqID, req); err != nil {
		return Output{}, nil, err
	}
	rawResp, err := r.Client.Do(ctx, req)
	if err != nil {
		return Output{}, nil, err
	}
	if r.Oracle != nil && r.Handle != "" {
		wResp := &models.WireResponse{
			Status:  rawResp.Status,
			Headers: rawResp.Headers,
			Body:    models.WireBody{RawBytes: rawResp.Body},
		}
		if res, dErr := r.Oracle.DeliverResponse(ctx, r.Handle, reqID, wResp); dErr != nil {
			return Output{}, rawResp, dErr
		} else if res != nil && len(res.Packets) > 0 {
			state.FollowUpPackets = append(state.FollowUpPackets, res.Packets...)
		}
	}
	out, err := ParseResponse(ctx, state, r.Oracle, reqID, rawResp)
	return out, rawResp, err
}

var _ = %q
`, pkg, embedImport, embedDecl, endpoint, strings.ToUpper(endpoint), fix.Request.Method)
}

func renderPortGo(pkg string, fix *models.GoldenFixture, stub bool) string {
	var bodyInit string
	if stub {
		bodyInit = `	panic("todo: implement BuildRequest")`
	} else {
		bodyExpr := fmt.Sprintf("[]byte(%q)", string(fix.Request.Body.RawBytes))
		if useEmbeddedBody(fix) {
			bodyExpr = "append([]byte(nil), recordedRequestBody...)"
		}
		bodyInit = fmt.Sprintf(`	q := wireclient.ParseRawQuery(%q)
	applied := make(map[string]bool, len(in.ExtraOrder))
	for _, k := range in.ExtraOrder {
		if v, ok := in.Extra[k]; ok {
			q.Set(k, v)
			applied[k] = true
		}
	}
	if len(in.Extra) > len(applied) {
		extraKeys := make([]string, 0, len(in.Extra))
		for k := range in.Extra {
			if !applied[k] {
				extraKeys = append(extraKeys, k)
			}
		}
		sort.Strings(extraKeys)
		for _, k := range extraKeys {
			q.Set(k, in.Extra[k])
		}
	}
	hdrs := wireclient.NewOrderedHeaders(nil)
	for _, h := range defaultHeaders {
		hdrs.Add(h.RawName, h.Value)
	}
	return &wireclient.OrderedRequest{
		Method:         %q,
		Scheme:         %q,
		Authority:      %q,
		RawPath:        %q,
		Query:          q,
		Headers:        hdrs,
		CookieWireMode: %q,
		PseudoOrder:    defaultPseudoOrder,
		Body:           %s,
		ForceHTTP1Raw:  %v,
	}, nil`, fix.Request.RawQuery, fix.Request.Method, fix.Request.Scheme, fix.Request.Authority, fix.Request.RawPath,
			fix.Request.Transport.CookieWireMode, bodyExpr, strings.EqualFold(fix.Request.Transport.Proto, "HTTP/1.1"))
	}

	var hdrLines strings.Builder
	for _, h := range fix.Request.Headers {
		if !h.IsPseudo {
			fmt.Fprintf(&hdrLines, "\t{RawName: %q, Value: %q},\n", h.RawName, h.Value)
		}
	}

	return fmt.Sprintf(`package %s

import (
	"context"
	"sort"

	"github.com/TaTrap/request-anything/pkg/models"
	"github.com/TaTrap/request-anything/pkg/oracle"
	"github.com/TaTrap/request-anything/pkg/wireclient"
)

type Input struct {
	Extra      map[string]string
	ExtraOrder []string
}

type Output struct {
	Status int
	Raw    []byte
}

type SessionState struct {
	DeviceID        string
	InstallID       string
	FollowUpPackets []oracle.AsyncPacket
}

var defaultHeaders = []models.HeaderKV{
%s}

var defaultPseudoOrder = %#v

func BuildRequest(ctx context.Context, state *SessionState, in Input) (*wireclient.OrderedRequest, error) {
%s
}

func SignRequest(ctx context.Context, state *SessionState, o oracle.NativeOracle, h oracle.SessionHandle, reqID string, req *wireclient.OrderedRequest) error {
	if o == nil || h == "" {
		return nil
	}
	out, err := o.Sign(ctx, h, reqID, oracle.SignInput{
		Method:   req.Method,
		URL:      req.Scheme + "://" + req.Authority + req.RawPath,
		RawQuery: req.Query.Encode(),
		Headers:  req.Headers.Items,
		Body:     req.Body,
		NowMs:    pinnedNowMs(),
	})
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(out.Headers))
	for k := range out.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, exists := req.Headers.Get(k); exists {
			req.Headers.Set(k, out.Headers[k])
		}
	}
	return nil
}

func ParseResponse(ctx context.Context, state *SessionState, o oracle.NativeOracle, reqID string, resp *wireclient.RawResponse) (Output, error) {
	return Output{Status: resp.Status, Raw: resp.Body}, nil
}
`, pkg, hdrLines.String(), fix.Request.Transport.PseudoOrder, bodyInit)
}

func renderPortTest(pkg string) string {
	return fmt.Sprintf(`package %s

import (
	"context"
	"testing"
)

func TestBuildRequestSmoke(t *testing.T) {
	req, err := BuildRequest(context.Background(), &SessionState{}, Input{})
	if err != nil {
		t.Fatal(err)
	}
	if req.Method == "" || req.RawPath == "" {
		t.Fatalf("expected valid method and path, got %%+v", req)
	}
}
`, pkg)
}

func renderWireCaptureTest(pkg string, useOracle bool) string {
	return fmt.Sprintf(`// Code generated by request-anything. DO NOT EDIT.
package %s

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/TaTrap/request-anything/pkg/oracle"
)

func TestRequestAnythingWireCapture(t *testing.T) {
	if os.Getenv("REQUEST_ANYTHING_RUN_CAPTURE") != "1" {
		t.Skip("set REQUEST_ANYTHING_RUN_CAPTURE=1 to execute live wire capture")
	}
	ctx := context.Background()
	var orc oracle.NativeOracle
	var handle oracle.SessionHandle
	if rpcURL := os.Getenv("REQUEST_ANYTHING_ORACLE_RPC"); rpcURL != "" {
		so := oracle.NewSerializedOracle(oracle.NewRPCClient(rpcURL))
		h, err := so.Open(ctx, oracle.SessionConfig{
			DeviceID:  os.Getenv("REQUEST_ANYTHING_DID"),
			InstallID: os.Getenv("REQUEST_ANYTHING_IID"),
			NowMs:     pinnedNowMs(),
		})
		if err != nil {
			t.Fatal(err)
		}
		defer so.Close(ctx, h)
		orc = so
		handle = h
	} else if %v || os.Getenv("REQUEST_ANYTHING_FORCE_ORACLE") == "1" {
		so := oracle.NewSerializedOracle(oracle.NewMockOracle())
		h, err := so.Open(ctx, oracle.SessionConfig{
			DeviceID:  os.Getenv("REQUEST_ANYTHING_DID"),
			InstallID: os.Getenv("REQUEST_ANYTHING_IID"),
			NowMs:     pinnedNowMs(),
		})
		if err != nil {
			t.Fatal(err)
		}
		defer so.Close(ctx, h)
		orc = so
		handle = h
	}
	runner, err := NewClientRunner(orc, handle)
	if err != nil {
		t.Fatal(err)
	}
	var input Input
	if raw := os.Getenv("REQUEST_ANYTHING_EXTRA_JSON"); raw != "" {
		var extra struct {
			Extra      map[string]string `+"`json:\"extra\"`"+`
			ExtraOrder []string          `+"`json:\"extra_order\"`"+`
		}
		if err := json.Unmarshal([]byte(raw), &extra); err != nil {
			t.Fatal(err)
		}
		input.Extra = extra.Extra
		input.ExtraOrder = extra.ExtraOrder
	}
	state := &SessionState{
		DeviceID:  os.Getenv("REQUEST_ANYTHING_DID"),
		InstallID: os.Getenv("REQUEST_ANYTHING_IID"),
	}
	if _, _, err := runner.Execute(ctx, state, "capture-req-1", input); err != nil {
		t.Fatal(err)
	}
	if orc != nil {
		hInfo, err := orc.Health(ctx, handle)
		if err != nil {
			t.Fatal(err)
		}
		if !hInfo.Healthy || hInfo.WorkerExceptions > 0 {
			t.Fatalf("native oracle unhealthy: %%+v", hInfo)
		}
	}
}
`, pkg, useOracle)
}
