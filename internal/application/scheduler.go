package application

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/as7446/apisix-acme-go/internal/domain/cert"
	"github.com/as7446/apisix-acme-go/internal/infra/config"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
	"github.com/as7446/apisix-acme-go/internal/infra/queue"
)

// Scheduler 调度器：扫描需要签发的证书，决定是否续期，入队签发任务
// 职责边界：
//   - 扫描待签发证书
//   - 判断是否需要续期
//   - 设置 issue_status=pending 并入队到 IssueQueue
//   - 不执行 ACME 操作
//   - 不操作 APISIX
type Scheduler struct {
	certRepo   cert.CertRepository
	certCache  cert.CertCache
	cfg        *config.Config
	issueQueue queue.Queue
}

// NewScheduler 创建调度器
func NewScheduler(certRepo cert.CertRepository, certCache cert.CertCache, cfg *config.Config, issueQueue queue.Queue) *Scheduler {
	return &Scheduler{
		certRepo:   certRepo,
		certCache:  certCache,
		cfg:        cfg,
		issueQueue: issueQueue,
	}
}

// ScanPending 扫描需要签发的证书
// 返回即将过期或已过期的证书列表
func (s *Scheduler) ScanPending() ([]*cert.Certificate, error) {
	certs, err := s.certRepo.FindNeedRenew(s.cfg.RenewBeforeDays)
	if err != nil {
		return nil, fmt.Errorf("扫描待签发证书失败：%w", err)
	}

	result := make([]*cert.Certificate, 0, len(certs))
	for _, c := range certs {
		if s.ShouldRenew(c) {
			result = append(result, c)
		}
	}

	if len(result) > 0 {
		domains := make([]string, 0, len(result))
		for _, c := range result {
			domains = append(domains, c.Domain)
		}
		logger.Log.Info("扫描到待签发证书", "count", len(result), "domains", domains)
	}

	return result, nil
}

// ShouldRenew 判断证书是否需要续期
func (s *Scheduler) ShouldRenew(c *cert.Certificate) bool {
	if c == nil {
		return false
	}

	// 跳过删除中的证书
	if c.LifecycleStatus == cert.LifecycleDeleting || c.Deleted {
		return false
	}

	// 跳过任何正在签发 FSM 中的证书
	if c.IssueStatus != cert.IssueIdle && c.IssueStatus != cert.IssueFailed {
		return false
	}

	now := time.Now().Unix()
	if c.IssueStatus == cert.IssueFailed && c.NextRetryAt > 0 {
		logger.Log.Info("证书处于失败重试计划中，跳过本轮续期扫描",
			"domain", c.Domain, "next_retry_at", c.NextRetryAt)
		return false
	}

	// 已过期证书必须续期
	if c.NotAfter <= now {
		logger.Log.Info("证书已过期，需要续期", "domain", c.Domain,
			"not_after", time.Unix(c.NotAfter, 0).Format("2006-01-02"))
		return true
	}

	// 计算续期窗口
	renewWindow := int64(s.cfg.RenewBeforeDays * 24 * 3600)
	renewThreshold := now + renewWindow

	if c.NotAfter <= renewThreshold {
		logger.Log.Info("证书在续期窗口内，需要续期", "domain", c.Domain,
			"not_after", time.Unix(c.NotAfter, 0).Format("2006-01-02"),
			"renew_before_days", s.cfg.RenewBeforeDays)
		return true
	}

	return false
}

// ScanAndSchedule 扫描并调度所有需要续期的证书
// 由 cron 触发，将需要续期的证书设置为 pending 并入队
func (s *Scheduler) ScanAndSchedule() ([]string, error) {
	certs, err := s.ScanPending()
	if err != nil {
		return nil, err
	}

	scheduled := make([]string, 0, len(certs))
	for _, c := range certs {
		// 设置 issue_status = pending
		if err := s.certRepo.UpdateIssueStatus(c.Domain, cert.IssuePending); err != nil {
			logger.Log.Error("设置 pending 状态失败", "domain", c.Domain, "error", err)
			continue
		}

		// 入队签发任务
		task := &queue.Task{
			ID:        uuid.New().String(),
			Type:      queue.TaskIssue,
			Domain:    c.Domain,
			Priority:  0,
			CreatedAt: time.Now().Unix(),
			Payload:   map[string]interface{}{"action": "renew"},
		}
		if err := s.issueQueue.Enqueue(task); err != nil {
			logger.Log.Error("入队签发任务失败", "domain", c.Domain, "error", err)
			continue
		}

		scheduled = append(scheduled, c.Domain)
	}

	if len(scheduled) > 0 {
		logger.Log.Info("调度完成", "scheduled", len(scheduled), "domains", scheduled)
	}

	return scheduled, nil
}
