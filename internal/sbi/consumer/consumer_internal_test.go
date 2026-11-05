package consumer

import (
	"testing"

	"github.com/free5gc/openapi"
	scp_context "github.com/free5gc/scp/internal/context"
	"github.com/free5gc/scp/pkg/factory"
	"github.com/h2non/gock"
)

const (
	testNrfUri   = "http://127.0.0.10:8000"
	testNfId     = "6ba7b810-9dad-41d1-80b4-00c04fd430c8"
	testNfIdPath = "/nnrf-nfm/v1/nf-instances/" + testNfId
)

type testScp struct {
	cfg *factory.Config
	ctx *scp_context.ScpContext
}

func (s *testScp) Config() *factory.Config          { return s.cfg }
func (s *testScp) Context() *scp_context.ScpContext { return s.ctx }

// newNrfTestConsumer builds a Consumer over a private SCP context pointed at the test NRF and intercepts the openapi
// cleartext HTTP/2 client with gock.
func newNrfTestConsumer(t *testing.T) *Consumer {
	t.Helper()

	scp := &testScp{cfg: &factory.Config{Configuration: &factory.Configuration{
		Sbi:         &factory.Sbi{Scheme: "http", RegisterIPv4: "127.0.0.113", BindingIPv4: "127.0.0.113"},
		NrfUri:      testNrfUri,
		ServiceList: []factory.Service{{ServiceName: factory.ServiceNausfAuth}},
	}}}
	var err error
	if scp.ctx, err = scp_context.NewContext(scp); err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	scp.ctx.SetNfInstID(testNfId)

	c, err := NewConsumer(scp)
	if err != nil {
		t.Fatalf("NewConsumer: %v", err)
	}

	openapi.InterceptInnerHttp2Client(t, false)
	t.Cleanup(gock.OffAll)
	return c
}

// nfProfileJSON is an NRF NF profile reply body. It omits heartBeatTimer when timer is 0.
func nfProfileJSON(timer int32) map[string]any {
	body := map[string]any{
		"nfInstanceId": testNfId,
		"nfType":       "SCP",
		"nfStatus":     "REGISTERED",
	}
	if timer > 0 {
		body["heartBeatTimer"] = timer
	}
	return body
}

func problemBody(status int, cause string) map[string]any {
	return map[string]any{"status": status, "cause": cause}
}
