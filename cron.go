package main

import (
	"fmt"

	"github.com/robfig/cron/v3"
)

// StartAllCrons 统一启动所有定时任务
func StartAllCrons(cfg *Config, store *StormCertStore, acme *AcmeManager, syncMgr *SyncManager) error {
	c := cron.New(cron.WithSeconds())

	if cfg.TaskCleanupCron != "" {
		if _, err := c.AddFunc(cfg.TaskCleanupCron, func() {
			if err := store.CleanupTasks(cfg.TaskRetentionHrs); err != nil {
				Log.Printf("任务清理失败：%v", err)
			}
		}); err != nil {
			return fmt.Errorf("添加任务清理定时任务失败：%w", err)
		}
		Log.Printf("任务清理定时任务已启动：cron=%s, retention_hours=%d", cfg.TaskCleanupCron, cfg.TaskRetentionHrs)
	}

	if cfg.RenewCron != "" {
		if _, err := c.AddFunc(cfg.RenewCron, func() {
			Log.Printf("开始执行证书续期定时任务")
			acme.RenewAll()
		}); err != nil {
			return fmt.Errorf("添加续期定时任务失败：%w", err)
		}
		Log.Printf("证书续期定时任务已启动：cron=%s", cfg.RenewCron)
	}

	if cfg.SyncCron != "" {
		if _, err := c.AddFunc(cfg.SyncCron, func() {
			if err := syncMgr.Sync(); err != nil {
				Log.Printf("证书同步失败：%v", err)
			}
		}); err != nil {
			return fmt.Errorf("添加同步定时任务失败：%w", err)
		}
		Log.Printf("证书同步定时任务已启动：cron=%s, mode=%s", cfg.SyncCron, cfg.SyncMode)
	}

	c.Start()
	return nil
}
