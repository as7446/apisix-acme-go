package application

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/as7446/apisix-acme-go/internal/domain/agent"
	"github.com/as7446/apisix-acme-go/internal/domain/agenttask"
	"github.com/as7446/apisix-acme-go/internal/domain/cert"
	"github.com/as7446/apisix-acme-go/internal/infra/metrics"
)

// ErrCertNotFound 证书未找到
var ErrCertNotFound = errors.New("certificate not found")

// ErrCertExists 证书已存在
var ErrCertExists = errors.New("certificate already exists")

// CertInfoResult 证书信息结果
type CertInfoResult struct {
	Domain       string `json:"domain"`
	NotBefore    int64  `json:"not_before"`
	NotAfter     int64  `json:"not_after"`
	APISIXID     string `json:"apisix_id"`
	Fingerprint  string `json:"fingerprint"`
	SerialNumber string `json:"serial_number"`
	Deleted      bool   `json:"deleted"`
	CreatedAt    int64  `json:"created_at"`
	UpdatedAt    int64  `json:"updated_at"`
}

// CertStatusResult 证书状态结果（基于新状态机）
type CertStatusResult struct {
	Domain          string               `json:"domain"`
	LifecycleStatus cert.LifecycleStatus `json:"lifecycle_status"`
	IssueStatus     cert.IssueStatus     `json:"issue_status"`
	SyncStatus      cert.SyncStatus      `json:"sync_status"`
	NotBefore       int64                `json:"not_before"`
	NotAfter        int64                `json:"not_after"`
	Revision        int64                `json:"revision"`
	Fingerprint     string               `json:"fingerprint"`
	SerialNumber    string               `json:"serial_number"`
	ErrorMessage    string               `json:"error_message"`
	RetryCount      int                  `json:"retry_count"`
	NextRetryAt     int64                `json:"next_retry_at"`
	ChallengeZone   string               `json:"challenge_zone"`
	SyncZones       []string             `json:"sync_zones"`
	CreatedAt       int64                `json:"created_at"`
	UpdatedAt       int64                `json:"updated_at"`
}

// CertService 证书应用服务
type CertService struct {
	certRepo    cert.CertRepository
	dispatcher  CertTaskDispatcher
	taskTimeout time.Duration
}

// CertTaskDispatcher 是证书服务需要的 Agent 任务调度能力。
type CertTaskDispatcher interface {
	ListAgentsForSync(syncZones []string) ([]*agent.Agent, error)
	DispatchAndWait(task *agenttask.AgentTask, timeout time.Duration) (*agenttask.TaskReportRequest, error)
}

// NewCertService 创建 CertService
func NewCertService(certRepo cert.CertRepository, dispatcher CertTaskDispatcher, taskTimeout time.Duration) *CertService {
	if taskTimeout <= 0 {
		taskTimeout = 5 * time.Minute
	}
	return &CertService{
		certRepo:    certRepo,
		dispatcher:  dispatcher,
		taskTimeout: taskTimeout,
	}
}

// GetInfo 获取证书基本信息
func (s *CertService) GetInfo(ctx context.Context, domain string) (*CertInfoResult, error) {
	c, ok := s.certRepo.GetWithDeleted(domain)
	if !ok {
		return nil, ErrCertNotFound
	}
	return &CertInfoResult{
		Domain:       c.Domain,
		NotBefore:    c.NotBefore,
		NotAfter:     c.NotAfter,
		APISIXID:     c.APISIXID,
		Fingerprint:  c.Fingerprint,
		SerialNumber: c.SerialNumber,
		Deleted:      c.Deleted,
		CreatedAt:    c.CreatedAt,
		UpdatedAt:    c.UpdatedAt,
	}, nil
}

// GetStatus 获取证书状态（基于新状态机）
func (s *CertService) GetStatus(ctx context.Context, domain string) (*CertStatusResult, error) {
	c, ok := s.certRepo.Get(domain)
	if !ok {
		return nil, ErrCertNotFound
	}
	return &CertStatusResult{
		Domain:          c.Domain,
		LifecycleStatus: c.LifecycleStatus,
		IssueStatus:     c.IssueStatus,
		SyncStatus:      c.SyncStatus,
		NotBefore:       c.NotBefore,
		NotAfter:        c.NotAfter,
		Revision:        c.Revision,
		Fingerprint:     c.Fingerprint,
		SerialNumber:    c.SerialNumber,
		ErrorMessage:    c.ErrorMessage,
		RetryCount:      c.RetryCount,
		NextRetryAt:     c.NextRetryAt,
		ChallengeZone:   c.ChallengeZone,
		SyncZones:       c.SyncZones,
		CreatedAt:       c.CreatedAt,
		UpdatedAt:       c.UpdatedAt,
	}, nil
}

// List 获取所有证书
func (s *CertService) List(ctx context.Context) ([]*CertStatusResult, error) {
	certs, err := s.certRepo.All()
	if err != nil {
		return nil, err
	}

	results := make([]*CertStatusResult, 0, len(certs))
	for _, c := range certs {
		if c.Deleted {
			continue
		}
		results = append(results, &CertStatusResult{
			Domain:          c.Domain,
			LifecycleStatus: c.LifecycleStatus,
			IssueStatus:     c.IssueStatus,
			SyncStatus:      c.SyncStatus,
			NotBefore:       c.NotBefore,
			NotAfter:        c.NotAfter,
			Revision:        c.Revision,
			Fingerprint:     c.Fingerprint,
			SerialNumber:    c.SerialNumber,
			ErrorMessage:    c.ErrorMessage,
			RetryCount:      c.RetryCount,
			NextRetryAt:     c.NextRetryAt,
			ChallengeZone:   c.ChallengeZone,
			SyncZones:       c.SyncZones,
			CreatedAt:       c.CreatedAt,
			UpdatedAt:       c.UpdatedAt,
		})
	}
	return results, nil
}

// UpdateRouting 更新证书的 Agent 路由策略。
func (s *CertService) UpdateRouting(ctx context.Context, domain string, challengeZone string, syncZones []string) (*CertStatusResult, error) {
	c, ok := s.certRepo.Get(domain)
	if !ok {
		return nil, ErrCertNotFound
	}
	if c.Deleted {
		return nil, ErrCertNotFound
	}

	pruneAgentIDs, err := s.findPruneAgentIDs(c, syncZones)
	if err != nil {
		return nil, err
	}

	if err := s.certRepo.UpdateRouting(domain, challengeZone, syncZones); err != nil {
		return nil, err
	}

	if err := s.pruneRemovedSyncTargets(c, pruneAgentIDs); err != nil {
		metrics.CertRoutingPruneFailure.Add(1)
		_ = s.certRepo.UpdateCertSyncState(domain, cert.SyncFailed, err.Error())
		return nil, err
	}

	// 路由策略变化后，标记为 drifted，下一轮 drift 检测会按新的 sync_zones 修复目标 Agent。
	_ = s.certRepo.UpdateCertSyncState(domain, cert.SyncDrifted, "routing policy updated")

	return s.GetStatus(ctx, domain)
}

func (s *CertService) findPruneAgentIDs(c *cert.Certificate, newSyncZones []string) ([]string, error) {
	if s.dispatcher == nil {
		return nil, nil
	}

	oldAgents, err := s.dispatcher.ListAgentsForSync(c.SyncZones)
	if err != nil {
		return nil, fmt.Errorf("查询旧同步 Agent 失败: %w", err)
	}
	newAgents, err := s.dispatcher.ListAgentsForSync(newSyncZones)
	if err != nil {
		return nil, fmt.Errorf("查询新同步 Agent 失败: %w", err)
	}
	if len(newSyncZones) > 0 && len(newAgents) == 0 {
		return nil, fmt.Errorf("sync_zones=%v 没有在线 Agent，拒绝更新以避免误清理证书", newSyncZones)
	}

	newSet := make(map[string]struct{}, len(newAgents))
	for _, a := range newAgents {
		newSet[a.AgentID] = struct{}{}
	}

	pruneAgentIDs := make([]string, 0)
	for _, a := range oldAgents {
		if _, ok := newSet[a.AgentID]; !ok {
			pruneAgentIDs = append(pruneAgentIDs, a.AgentID)
		}
	}
	return pruneAgentIDs, nil
}

func (s *CertService) pruneRemovedSyncTargets(c *cert.Certificate, agentIDs []string) error {
	if len(agentIDs) == 0 {
		return nil
	}
	metrics.CertRoutingPruneTotal.Add(int64(len(agentIDs)))

	apisixID := c.APISIXID
	if apisixID == "" {
		apisixID = cert.NormalizeAPISIXID(c.Domain)
	}

	var failed int
	var lastErr string
	for _, agentID := range agentIDs {
		task := &agenttask.AgentTask{
			AgentID: agentID,
			Type:    agenttask.TaskDeleteCert,
			Domain:  c.Domain,
			Payload: map[string]interface{}{
				"apisix_id": apisixID,
			},
		}
		report, err := s.dispatcher.DispatchAndWait(task, s.taskTimeout)
		if err != nil {
			failed++
			lastErr = err.Error()
			continue
		}
		if report == nil || report.Status != agenttask.StatusSuccess {
			failed++
			if report != nil {
				lastErr = report.ErrorMessage
			}
		}
	}
	if failed > 0 {
		return fmt.Errorf("清理旧 sync_zones Agent 证书失败: %d/%d failed, last_error=%s", failed, len(agentIDs), lastErr)
	}
	return nil
}

// Delete 删除证书
func (s *CertService) Delete(ctx context.Context, domain string) error {
	c, ok := s.certRepo.GetWithDeleted(domain)
	if !ok {
		return ErrCertNotFound
	}
	if c.Deleted {
		return nil
	}

	if s.dispatcher == nil {
		return errors.New("agent dispatcher not configured")
	}

	if err := s.certRepo.MarkDeleting(domain); err != nil {
		return err
	}

	agents, err := s.dispatcher.ListAgentsForSync(c.SyncZones)
	if err != nil {
		_ = s.certRepo.UpdateCertSyncState(domain, cert.SyncFailed, err.Error())
		return fmt.Errorf("查询同步 Agent 失败: %w", err)
	}
	if len(agents) == 0 {
		_ = s.certRepo.UpdateCertSyncState(domain, cert.SyncFailed, "没有可执行删除任务的在线 Agent")
		return errors.New("没有可执行删除任务的在线 Agent")
	}

	apisixID := c.APISIXID
	if apisixID == "" {
		apisixID = cert.NormalizeAPISIXID(domain)
	}
	agentIDs := make([]string, 0, len(agents))
	for _, a := range agents {
		agentIDs = append(agentIDs, a.AgentID)
	}

	var failed int
	var lastErr string
	for _, agentID := range agentIDs {
		task := &agenttask.AgentTask{
			AgentID: agentID,
			Type:    agenttask.TaskDeleteCert,
			Domain:  domain,
			Payload: map[string]interface{}{
				"apisix_id": apisixID,
			},
		}
		report, err := s.dispatcher.DispatchAndWait(task, s.taskTimeout)
		if err != nil {
			failed++
			lastErr = err.Error()
			continue
		}
		if report == nil {
			failed++
			lastErr = "agent returned empty report"
			continue
		}
		if report.Status != agenttask.StatusSuccess {
			failed++
			lastErr = report.ErrorMessage
		}
	}
	if failed > 0 {
		err := fmt.Errorf("Agent 删除证书失败: %d/%d failed, last_error=%s", failed, len(agentIDs), lastErr)
		_ = s.certRepo.UpdateCertSyncState(domain, cert.SyncFailed, err.Error())
		return err
	}

	return s.certRepo.MarkDeleted(domain)
}
