package main

import (
	"fmt"
	"github.com/robfig/cron/v3"
)

// StartAllCrons 统一启动所有定时任务
func StartAllCrons(cfg *Config, store *StormCertStore, acme *AcmeManager, syncMgr *SyncManager) error {
	if err := StartRenewCron(cfg, acme); err != nil {
		return err
	}
	if err := StartTaskCleanupCron(cfg, store); err != nil {
		return err
	}
	if err := StartSyncCron(cfg, syncMgr); err != nil {
		return err
	}
	return nil
}

// StartTaskCleanupCron 启动任务清理定时任务
func StartTaskCleanupCron(cfg *Config, store *StormCertStore) error {
	if cfg.TaskCleanupCron == "" {
		return nil
	}
	c := cron.New(cron.WithSeconds())
	_, err := c.AddFunc(cfg.TaskCleanupCron, func() {
		if err := store.CleanupTasks(cfg.TaskRetentionHrs); err != nil {
			Log.Printf("任务清理失败：%v", err)
		}
	})
	if err != nil {
		return fmt.Errorf("添加任务清理定时任务失败：%w", err)
	}
	c.Start()
	Log.Printf("任务清理定时任务已启动：cron=%s, retention_hours=%d", cfg.TaskCleanupCron, cfg.TaskRetentionHrs)
	return nil
}

// StartRenewCron 启动续期定时任务
func StartRenewCron(cfg *Config, acme *AcmeManager) error {
	if cfg.RenewCron == "" {
		return nil
	}

	c := cron.New(cron.WithSeconds())
	_, err := c.AddFunc(cfg.RenewCron, func() {
		Log.Printf("开始执行证书续期定时任务")
		acme.RenewAll()
	})
	if err != nil {
		return fmt.Errorf("添加定时任务失败：%w", err)
	}
	c.Start()
	Log.Printf("证书续期定时任务已启动：cron=%s", cfg.RenewCron)
	return nil
}

// StartSyncCron 启动同步定时任务
func StartSyncCron(cfg *Config, m *SyncManager) error {
	if m.cfg.SyncCron == "" {
		return nil
	}

	c := cron.New(cron.WithSeconds())
	_, err := c.AddFunc(m.cfg.SyncCron, func() {
		if err := m.Sync(); err != nil {
			Log.Printf("证书同步失败：%v", err)
		}
	})
	if err != nil {
		return fmt.Errorf("添加同步定时任务失败：%w", err)
	}
	c.Start()
	Log.Printf("证书同步定时任务已启动：cron=%s, mode=%s", m.cfg.SyncCron, m.cfg.SyncMode)
	return nil
}
