package consumer

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/free5gc/openapi"
	"github.com/free5gc/util/nfheartbeat"
	"github.com/h2non/gock"
)

func TestSendUpdateNFInstance(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		body      map[string]any
		wantTimer int32
		wantErr   bool
	}{
		{
			name:      "200 returns the updated profile",
			status:    http.StatusOK,
			body:      nfProfileJSON(20),
			wantTimer: 20,
		},
		{
			name:   "204 returns an empty profile",
			status: http.StatusNoContent,
		},
		{
			name:    "404 reports the unknown profile",
			status:  http.StatusNotFound,
			body:    problemBody(http.StatusNotFound, "RESOURCE_URI_STRUCTURE_NOT_FOUND"),
			wantErr: true,
		},
		{
			name:    "500 reports the NRF failure",
			status:  http.StatusInternalServerError,
			body:    problemBody(http.StatusInternalServerError, "SYSTEM_FAILURE"),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newNrfTestConsumer(t)

			reply := gock.New(testNrfUri).
				Patch(testNfIdPath).
				MatchHeader("Content-Type", "application/json-patch+json").
				JSON([]map[string]any{
					{"op": "replace", "path": "/nfStatus", "value": "REGISTERED"},
				}).
				Reply(tt.status)
			if tt.body != nil {
				reply.JSON(tt.body)
			}

			nf, pd, err := c.SendUpdateNFInstance(t.Context(), nfheartbeat.PatchItems())

			if !gock.IsDone() {
				t.Fatal("the heartbeat PATCH was not sent as expected")
			}
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("SendUpdateNFInstance: pd=%+v err=%v", pd, err)
				}
				if nf.HeartBeatTimer != tt.wantTimer {
					t.Errorf("HeartBeatTimer = %d, want %d", nf.HeartBeatTimer, tt.wantTimer)
				}
				return
			}

			var apiErr openapi.GenericOpenAPIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("err = %T (%v), want openapi.GenericOpenAPIError", err, err)
			}
			if apiErr.ErrorStatus != tt.status {
				t.Errorf("ErrorStatus = %d, want %d", apiErr.ErrorStatus, tt.status)
			}
			if pd == nil || pd.Status != int32(tt.status) {
				t.Errorf("ProblemDetails = %+v, want status %d", pd, tt.status)
			}
		})
	}
}

func TestRegisterNFInstanceKeepsHeartbeatTimer(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		timer     int32
		wantTimer int32
	}{
		{name: "201 adopts the returned timer", status: http.StatusCreated, timer: 15, wantTimer: 15},
		{name: "200 adopts the returned timer", status: http.StatusOK, timer: 15, wantTimer: 15},
		{name: "no timer clears a stale one", status: http.StatusOK, timer: 0, wantTimer: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newNrfTestConsumer(t)
			c.heartbeatTimer = 99

			gock.New(testNrfUri).
				Put(testNfIdPath).
				Reply(tt.status).
				JSON(nfProfileJSON(tt.timer))

			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			if err := c.RegisterNFInstance(ctx); err != nil {
				t.Fatalf("RegisterNFInstance: %v", err)
			}
			if !gock.IsDone() {
				t.Fatal("the registration PUT was not sent as expected")
			}
			if c.heartbeatTimer != tt.wantTimer {
				t.Errorf("heartbeatTimer = %d, want %d", c.heartbeatTimer, tt.wantTimer)
			}
		})
	}
}

func TestRegisterNFInstanceRejectsInvalidOAuthSetup(t *testing.T) {
	c := newNrfTestConsumer(t)
	body := nfProfileJSON(15)
	body["customInfo"] = map[string]any{"oauth2": true}
	gock.New(testNrfUri).Put(testNfIdPath).Reply(http.StatusCreated).JSON(body)
	if err := c.RegisterNFInstance(t.Context()); err == nil {
		t.Fatal("OAuth-enabled registration without an NRF certificate must fail")
	}
	if c.Context().OAuth2Required() {
		t.Fatal("invalid OAuth setup must not enable OAuth")
	}
	if !gock.IsDone() {
		t.Fatal("registration request was not sent")
	}
}

// TestRegisterNFInstanceRetriesUntilSuccess drives the retry loop: the first PUT fails on the NRF, the retry
// one interval later succeeds.
func TestRegisterNFInstanceRetriesUntilSuccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newNrfTestConsumer(t)

		gock.New(testNrfUri).
			Put(testNfIdPath).
			Reply(http.StatusInternalServerError).
			JSON(problemBody(http.StatusInternalServerError, "SYSTEM_FAILURE"))
		gock.New(testNrfUri).
			Put(testNfIdPath).
			Reply(http.StatusCreated).
			JSON(nfProfileJSON(15))

		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		if err := c.RegisterNFInstance(ctx); err != nil {
			t.Fatalf("RegisterNFInstance: %v", err)
		}
		if !gock.IsDone() {
			t.Fatal("expected a failed PUT followed by a successful retry")
		}
		if c.heartbeatTimer != 15 {
			t.Errorf("heartbeatTimer = %d, want 15 from the retry", c.heartbeatTimer)
		}
	})
}

// TestRegisterNFInstanceStopsOnCancel proves the retry loop gives up once the context is done instead of
// retrying forever, which lets shutdown wait for it before deregistering.
func TestRegisterNFInstanceStopsOnCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newNrfTestConsumer(t)

		gock.New(testNrfUri).
			Put(testNfIdPath).
			Persist().
			Reply(http.StatusInternalServerError).
			JSON(problemBody(http.StatusInternalServerError, "SYSTEM_FAILURE"))

		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()

		if err := c.RegisterNFInstance(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want context.DeadlineExceeded", err)
		}
	})
}
