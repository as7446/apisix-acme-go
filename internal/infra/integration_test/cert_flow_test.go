package integration_test

import (
	"sync"
	"testing"

	"github.com/as7446/apisix-acme-go/internal/domain/cert"
)

type memoryCertState struct {
	mu    sync.Mutex
	certs map[string]*cert.Certificate
}

func newMemoryCertState() *memoryCertState {
	return &memoryCertState{certs: make(map[string]*cert.Certificate)}
}

func (s *memoryCertState) put(c *cert.Certificate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *c
	s.certs[c.Domain] = &cp
}

func (s *memoryCertState) claimIssue(domain string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.certs[domain]
	if !ok || c.Deleted {
		return false
	}
	if c.IssueStatus != cert.IssuePending && c.IssueStatus != cert.IssueFailed {
		return false
	}
	c.IssueStatus = cert.IssueIssuing
	return true
}

func TestIssueClaimUsesIssueStatusAsSingleLock(t *testing.T) {
	state := newMemoryCertState()
	state.put(&cert.Certificate{
		Domain:          "test.example.com",
		LifecycleStatus: cert.LifecycleActive,
		IssueStatus:     cert.IssuePending,
		SyncStatus:      cert.SyncDrifted,
	})

	if !state.claimIssue("test.example.com") {
		t.Fatal("first claim should succeed")
	}
	if state.claimIssue("test.example.com") {
		t.Fatal("second claim should fail while issue_status=issuing")
	}

	state.put(&cert.Certificate{
		Domain:          "test.example.com",
		LifecycleStatus: cert.LifecycleActive,
		IssueStatus:     cert.IssueFailed,
		SyncStatus:      cert.SyncFailed,
	})
	if !state.claimIssue("test.example.com") {
		t.Fatal("failed cert should be claimable for retry")
	}
}

func TestRoutingPruneSetDifference(t *testing.T) {
	oldAgents := []string{"agent-hk-1", "agent-sg-1", "agent-us-1"}
	newAgents := []string{"agent-hk-1", "agent-sg-1"}

	pruned := diffAgents(oldAgents, newAgents)
	if len(pruned) != 1 || pruned[0] != "agent-us-1" {
		t.Fatalf("unexpected prune target: %#v", pruned)
	}
}

func diffAgents(oldAgents, newAgents []string) []string {
	newSet := make(map[string]struct{}, len(newAgents))
	for _, id := range newAgents {
		newSet[id] = struct{}{}
	}

	var pruned []string
	for _, id := range oldAgents {
		if _, ok := newSet[id]; !ok {
			pruned = append(pruned, id)
		}
	}
	return pruned
}
