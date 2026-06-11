package controller

import (
	"time"

	"github.com/as7446/apisix-acme-go/internal/domain/cert"
	"github.com/as7446/apisix-acme-go/internal/infra/config"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
)

// handleRetryState 处理签发失败的重试状态
// 指数退避 + 冷却期策略：
//   - 每次失败 retryCount++，延迟 = baseDelay * 2^(retryCount-1)，封顶 3600s
//   - 达到 maxRetries 后进入冷却期（默认 24h），重置 retryCount=0
//   - RetryScheduler 负责在 nextRetryAt 到达时精确触发重试
func handleRetryState(certRepo cert.CertRepository, cfg *config.Config, scheduler *RetryScheduler, domain string, issueErr error) {
	c, ok := certRepo.Get(domain)
	if !ok {
		logger.Log.Error("重试状态更新：证书不存在", "domain", domain)
		return
	}

	retryCount := c.RetryCount + 1
	now := time.Now().Unix()
	errMsg := issueErr.Error()

	var nextRetryAt int64

	if retryCount >= cfg.CertRetryMax {
		// 达到最大重试次数，进入冷却期
		cooldownSeconds := int64(cfg.CertCooldownHours) * 3600
		nextRetryAt = now + cooldownSeconds
		_ = certRepo.UpdateRetryState(domain, 0, nextRetryAt, cert.IssueFailed, errMsg)
		logger.Log.Warn("证书签发达到最大重试，进入冷却期",
			"domain", domain,
			"error", errMsg,
			"cooldown_hours", cfg.CertCooldownHours,
			"next_retry_at", nextRetryAt)
	} else {
		// 指数退避：delay = baseDelay * 2^(retryCount-1)，封顶 3600s
		delay := int64(cfg.CertRetryDelay)
		for i := 1; i < retryCount; i++ {
			delay *= 2
		}
		if delay > 3600 {
			delay = 3600
		}
		nextRetryAt = now + delay
		_ = certRepo.UpdateRetryState(domain, retryCount, nextRetryAt, cert.IssueFailed, errMsg)
		logger.Log.Info("证书签发失败，指数退避重试",
			"domain", domain,
			"error", errMsg,
			"retry_count", retryCount,
			"delay_seconds", delay,
			"next_retry_at", nextRetryAt)
	}

	// 注册精确重试定时器
	if scheduler != nil {
		scheduler.Schedule(domain, nextRetryAt)
	}
}
