package wiretraps

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
	{RawName: "Host", Value: "api.example.com"},
	{RawName: "x-client-ver", Value: "4.2.0"},
	{RawName: "content-md5", Value: "978374847C396EDF00960086D2C20D42"},
	{RawName: "Content-Type", Value: "application/json"},
	{RawName: "Content-Length", Value: "68"},
}

var defaultPseudoOrder = []string(nil)

func BuildRequest(ctx context.Context, state *SessionState, in Input) (*wireclient.OrderedRequest, error) {
	q := wireclient.ParseRawQuery("iid=&resolution=1080*2400&tag=a&tag=b&")
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
		Method:         "POST",
		Scheme:         "https",
		Authority:      "api.example.com",
		RawPath:        "/v2/checkout",
		Query:          q,
		Headers:        hdrs,
		CookieWireMode: "single_header",
		PseudoOrder:    defaultPseudoOrder,
		Body:           []byte("{\"callback\":\"https:\\/\\/pay.example.com\\/ok\",\"amount\":19.0,\"retry\":0}"),
		ForceHTTP1Raw:  true,
	}, nil
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
