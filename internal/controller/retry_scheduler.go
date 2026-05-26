package controller

import (
	"context"
	"sync"
	"time"

	"github.com/as7446/apisix-acme-go/internal/domain/cert"
	"github.com/as7446/apisix-acme-go/internal/infra/config"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
)

// RetryScheduler 基于 Timer 的精确重试调度器
// 当证书签发失败后，根据 nextRetryAt 精确触发重试入队，
// 而非依赖 RecoveryCron 的粗粒度轮询。
type RetryScheduler struct {
	mu       sync.Mutex
	timers   map[string]*time.Timer // domain -> timer
	certRepo cert.CertRepository
	cfg      *config.Config
	enqueue  func(domain, action string) error // 回调：入队签发任务
}

// NewRetryScheduler 创建重试调度器
func NewRetryScheduler(
	certRepo cert.CertRepository,
	cfg *config.Config,
	enqueue func(domain, action string) error,
) *RetryScheduler {
	return &RetryScheduler{
		timers:   make(map[string]*time.Timer),
		certRepo: certRepo,
		cfg:      cfg,
		enqueue:  enqueue,
	}
}

// Schedule 注册或更新某个 domain 的重试定时器
func (s *RetryScheduler) Schedule(domain string, nextRetryAt int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delay := time.Duration(nextRetryAt-time.Now().Unix()) * time.Second
	if delay <= 0 {
		// 已到期，立即入队
		go s.fireRetry(domain)
		return
	}

	// 如果已有定时器，先取消
	if t, ok := s.timers[domain]; ok {
		t.Stop()
	}

	s.timers[domain] = time.AfterFunc(delay, func() {
		s.fireRetry(domain)
	})
	logger.Log.Info("重试定时器已注册",
		"domain", domain,
		"delay_seconds", delay.Seconds())
}

// Start 启动调度器，从 DB 加载所有待重试证书并注册定时器
func (s *RetryScheduler) Start(ctx context.Context) {
	pendingCerts, err := s.certRepo.FindRetryPending()
	if err != nil {
		logger.Log.Error("RetryScheduler 启动加载失败", "error", err)
		return
	}

	now := time.Now().Unix()
	for _, c := range pendingCerts {
		if c.NextRetryAt <= now {
			// 已到期，直接入队
			_ = s.certRepo.UpdateIssueStatus(c.Domain, cert.IssuePending)
			if err := s.enqueue(c.Domain, "issue"); err != nil {
				logger.Log.Error("RetryScheduler 立即入队失败", "domain", c.Domain, "error", err)
			}
		} else {
			s.Schedule(c.Domain, c.NextRetryAt)
		}
	}

	if len(pendingCerts) > 0 {
		logger.Log.Info("RetryScheduler 启动完成", "pending_retries", len(pendingCerts))
	}
}

// Stop 停止所有定时器
func (s *RetryScheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for domain, t := range s.timers {
		t.Stop()
		delete(s.timers, domain)
	}
	logger.Log.Info("RetryScheduler 已停止")
}

// fireRetry 定时器触发时的回调，将证书重新入队
func (s *RetryScheduler) fireRetry(domain string) {
	s.mu.Lock()
	delete(s.timers, domain)
	s.mu.Unlock()

	_ = s.certRepo.UpdateIssueStatus(domain, cert.IssuePending)
	if err := s.enqueue(domain, "issue"); err != nil {
		logger.Log.Error("RetryScheduler 重试入队失败", "domain", domain, "error", err)
		return
	}
	logger.Log.Info("RetryScheduler 触发重试", "domain", domain)
}
