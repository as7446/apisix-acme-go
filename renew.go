package main

import (
	"fmt"
	"log"

	"github.com/robfig/cron/v3"
)

// StartRenewCron 启动定时任务，定期扫描并续期证书
func StartRenewCron(cfg *Config, store *StormCertStore, acme *AcmeManager, logger *log.Logger) error {
	if cfg.RenewCron == "" {
		return nil
	}

	c := cron.New(cron.WithSeconds())
	_, err := c.AddFunc(cfg.RenewCron, func() {
		logger.Printf("开始执行证书续期定时任务")
		acme.RenewAll()
	})
	if err != nil {
		return fmt.Errorf("添加定时任务失败：%w", err)
	}
	c.Start()
	logger.Printf("证书续期定时任务已启动：cron=%s", cfg.RenewCron)
	return nil
}
