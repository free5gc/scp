package processor

import (
	"errors"
	"net/http"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	scp_context "github.com/free5gc/scp/internal/context"
	"github.com/free5gc/scp/internal/sbi/consumer"
	"github.com/free5gc/scp/pkg/factory"
)

type scp interface {
	Context() *scp_context.ScpContext
	Config() *factory.Config
	Consumer() *consumer.Consumer
}

type Processor struct {
	scp
	authenticationStatusStore AuthenticationStatusStore
}

type HandlerResponse struct {
	Status      int
	Headers     map[string][]string
	ContentType string
	Body        interface{}
}

func NewProcessor(scp scp) (*Processor, error) {
	return &Processor{scp: scp, authenticationStatusStore: mongoAuthenticationStatusStore{}}, nil
}

func (p *Processor) SetAuthenticationStatusStore(store AuthenticationStatusStore) {
	if store != nil {
		p.authenticationStatusStore = store
	}
}

func response(status int, body interface{}) *HandlerResponse {
	contentType := "application/json"
	if _, ok := body.(*models.ProblemDetails); ok {
		contentType = "application/problem+json"
	}
	return &HandlerResponse{Status: status, ContentType: contentType, Body: body}
}

func responseFromError(err error) *HandlerResponse {
	var downstream *consumer.DownstreamError
	if errors.As(err, &downstream) {
		if len(downstream.Body) > 0 {
			return &HandlerResponse{
				Status: downstream.Status, ContentType: downstream.ContentType, Body: downstream.Body,
			}
		}
		problem := openapi.ProblemDetailsSystemFailure(err.Error())
		problem.Status = int32(downstream.Status)
		return response(downstream.Status, problem)
	}
	problem := openapi.ProblemDetailsSystemFailure(err.Error())
	problem.Status = http.StatusBadGateway
	return response(http.StatusBadGateway, problem)
}
