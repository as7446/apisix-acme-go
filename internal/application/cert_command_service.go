package application

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/as7446/apisix-acme-go/internal/domain/cert"
	"github.com/as7446/apisix-acme-go/internal/infra/queue"
)

// CertCommandService 负责证书写操作和签发队列入队。
type CertCommandService struct {
	certRepo   cert.CertRepository
	issueQueue queue.Queue
}

// NewCertCommandService 创建 CertCommandService。
func NewCertCommandService(certRepo cert.CertRepository, issueQueue queue.Queue) *CertCommandService {
	return &CertCommandService{
		certRepo:   certRepo,
		issueQueue: issueQueue,
	}
}

// CreateCert 创建证书申请（只写 desired state + 入队）
func (s *CertCommandService) CreateCert(ctx context.Context, domain, email string, force bool, challengeZone string, syncZones []string) (*CertStatusResult, error) {
	// 检查证书是否已存在且有效
	if existing, ok := s.certRepo.Get(domain); ok {
		if !force && existing.IssueStatus != cert.IssueIdle && existing.IssueStatus != cert.IssueFailed {
			return &CertStatusResult{
				Domain:          existing.Domain,
				LifecycleStatus: existing.LifecycleStatus,
				IssueStatus:     existing.IssueStatus,
				SyncStatus:      existing.SyncStatus,
				NotBefore:       existing.NotBefore,
				NotAfter:        existing.NotAfter,
				ErrorMessage:    existing.ErrorMessage,
			}, nil
		}
		if !force && existing.NotAfter > time.Now().Unix() {
			return &CertStatusResult{
				Domain:          existing.Domain,
				LifecycleStatus: existing.LifecycleStatus,
				IssueStatus:     existing.IssueStatus,
				SyncStatus:      existing.SyncStatus,
				NotBefore:       existing.NotBefore,
				NotAfter:        existing.NotAfter,
				ErrorMessage:    existing.ErrorMessage,
			}, ErrCertExists
		}
	}

	// 创建或更新 desired state
	now := time.Now().Unix()
	if _, ok := s.certRepo.Get(domain); !ok {
		// 新证书
		newCert := &cert.Certificate{
			Domain:          domain,
			APISIXID:        cert.NormalizeAPISIXID(domain),
			Source:          cert.CertSourceManaged,
			LifecycleStatus: cert.LifecycleActive,
			IssueStatus:     cert.IssuePending,
			SyncStatus:      cert.SyncDrifted,
			ChallengeZone:   challengeZone,
			SyncZones:       syncZones,
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		if err := s.certRepo.Upsert(newCert); err != nil {
			return nil, err
		}
	} else {
		// 已存在，更新 desired routing + pending（force renew 场景）
		_ = s.certRepo.UpdateRouting(domain, challengeZone, syncZones)
		_ = s.certRepo.UpdateIssueStatus(domain, cert.IssuePending)
	}

	// 入队签发任务
	task := &queue.Task{
		ID:        uuid.New().String(),
		Type:      queue.TaskIssue,
		Domain:    domain,
		Priority:  0,
		CreatedAt: now,
		Payload:   map[string]interface{}{"action": "issue"},
	}
	if err := s.issueQueue.Enqueue(task); err != nil {
		return nil, err
	}

	return &CertStatusResult{
		Domain:          domain,
		LifecycleStatus: cert.LifecycleActive,
		IssueStatus:     cert.IssuePending,
		SyncStatus:      cert.SyncDrifted,
	}, nil
}

// RetryCert 手动重试失败的证书
func (s *CertCommandService) RetryCert(ctx context.Context, domain string) (*CertStatusResult, error) {
	c, ok := s.certRepo.Get(domain)
	if !ok {
		return nil, ErrCertNotFound
	}
	if c.IssueStatus != cert.IssueFailed {
		return &CertStatusResult{
			Domain:      c.Domain,
			IssueStatus: c.IssueStatus,
		}, fmt.Errorf("证书状态非 failed，无需重试：当前状态=%s", c.IssueStatus)
	}

	// 重置重试状态
	_ = s.certRepo.UpdateRetryState(domain, 0, 0, cert.IssuePending, "")

	// 入队
	now := time.Now().Unix()
	task := &queue.Task{
		ID:        uuid.New().String(),
		Type:      queue.TaskIssue,
		Domain:    domain,
		Priority:  0,
		CreatedAt: now,
		Payload:   map[string]interface{}{"action": "issue"},
	}
	if err := s.issueQueue.Enqueue(task); err != nil {
		return nil, err
	}

	return &CertStatusResult{
		Domain:      domain,
		IssueStatus: cert.IssuePending,
	}, nil
}

// GetCertStatus 获取证书状态。
func (s *CertCommandService) GetCertStatus(ctx context.Context, domain string) (*CertStatusResult, error) {
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
		ErrorMessage:    c.ErrorMessage,
	}, nil
}
