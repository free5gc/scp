package processor

import (
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
}

type HandlerResponse struct {
	Status  int
	Headers map[string][]string
	Body    interface{}
}

func NewProcessor(scp scp) (*Processor, error) {
	handler := &Processor{
		scp: scp,
	}

	return handler, nil
}

func addLocationheader(header map[string][]string, location string) {
	locations := header["Location"]
	if locations == nil {
		header["Location"] = []string{location}
	} else {
		header["Location"] = append(locations, location)
	}
}
