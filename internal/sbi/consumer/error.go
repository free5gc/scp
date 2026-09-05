package consumer

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/free5gc/openapi"
)

const problemJSON = "application/problem+json"

// DownstreamError preserves an NF's status and response body without relying on
// operation-specific generated error wrapper types.
type DownstreamError struct {
	Status      int
	ContentType string
	Body        []byte
	Cause       error
}

func (e *DownstreamError) Error() string {
	if e.Cause != nil {
		return e.Cause.Error()
	}
	return fmt.Sprintf("downstream returned HTTP %d", e.Status)
}

func normalizeError(err error) error {
	if err == nil {
		return nil
	}
	var apiErr openapi.GenericOpenAPIError
	if errors.As(err, &apiErr) {
		status := apiErr.ErrorStatus
		if status == 0 {
			status = http.StatusBadGateway
		}
		return &DownstreamError{
			Status:      status,
			ContentType: problemJSON,
			Body:        append([]byte(nil), apiErr.RawBody...),
			Cause:       err,
		}
	}
	return fmt.Errorf("downstream request failed: %w", err)
}

func nilResponse(operation string) error {
	return fmt.Errorf("%s: downstream returned an empty response", operation)
}
