package theauth_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/glincker/theauth-go"
)

func TestApprovals_QuorumOpenAndProgress(t *testing.T) {
	srv, rec := newRecorder(t, map[string]reply{
		"POST /approvals": {201, data(map[string]interface{}{
			"id": "apr_2", "status": "pending", "action": "admin:rotate", "resource": "agent:a1",
			"expiresAt": "t", "requiredApprovals": 2,
		})},
		"POST /approvals/apr_2/approve": {200, data(map[string]interface{}{
			"id": "apr_2", "status": "pending", "respondedAt": "r", "requiredApprovals": 2, "approvalsReceived": 1,
		})},
		"GET /approvals/apr_2": {200, data(map[string]interface{}{
			"id": "apr_2", "status": "pending", "action": "admin:rotate", "resource": "agent:a1", "expiresAt": "e",
			"requiredApprovals": 2, "approvalsReceived": 1, "approvers": []string{"alice"},
		})},
	})
	ctx := context.Background()
	c := theauth.NewClient(srv.URL, theauth.WithToken("admin_token"))

	opened, err := c.Approvals.Open(ctx, theauth.OpenApprovalInput{
		Action: "admin:rotate", Resource: "agent:a1", RequiredApprovals: 2,
	})
	if err != nil || opened.RequiredApprovals != 2 {
		t.Fatalf("open: %v %+v", err, opened)
	}
	var body map[string]interface{}
	if err := json.Unmarshal([]byte(rec.last(t).Body), &body); err != nil {
		t.Fatal(err)
	}
	if body["requiredApprovals"] != float64(2) {
		t.Fatalf("body %v", body)
	}

	dec, err := c.Approvals.Approve(ctx, "apr_2")
	if err != nil || dec.Status != theauth.ApprovalPending || dec.ApprovalsReceived != 1 || dec.RequiredApprovals != 2 {
		t.Fatalf("approve: %v %+v", err, dec)
	}
	state, err := c.Approvals.Get(ctx, "apr_2")
	if err != nil || state == nil || len(state.Approvers) != 1 || state.Approvers[0] != "alice" {
		t.Fatalf("get: %v %+v", err, state)
	}
}

func TestApprovals_OpenOmitsQuorumWhenZero(t *testing.T) {
	srv, rec := newRecorder(t, map[string]reply{
		"POST /approvals": {201, data(map[string]interface{}{"id": "apr_3", "status": "pending", "action": "admin:x", "resource": "r", "expiresAt": "t", "requiredApprovals": 1})},
	})
	c := theauth.NewClient(srv.URL, theauth.WithToken("t"))
	if _, err := c.Approvals.Open(context.Background(), theauth.OpenApprovalInput{Action: "admin:x", Resource: "r"}); err != nil {
		t.Fatal(err)
	}
	var body map[string]interface{}
	_ = json.Unmarshal([]byte(rec.last(t).Body), &body)
	if _, ok := body["requiredApprovals"]; ok {
		t.Fatalf("body %v", body)
	}
}
