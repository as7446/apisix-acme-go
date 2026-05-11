package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/as7446/apisix-acme-go/internal/domain/acme"
	"github.com/as7446/apisix-acme-go/internal/domain/sync"
	"github.com/as7446/apisix-acme-go/internal/domain/task"

	"github.com/as7446/apisix-acme-go/internal/infra/config"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
	"github.com/as7446/apisix-acme-go/internal/store/cache"
	"github.com/as7446/apisix-acme-go/internal/store/gorm"
)

func main() {
	// 加载配置
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "config.yml"
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		panic(err)
	}

	// 初始化日志
	if cfg.LogLevel != "" {
		logger.Init(cfg.LogLevel)
	}

	// 初始化数据库
	store, err := gorm.New(cfg)
	if err != nil {
		logger.Log.Error("初始化数据库失败", "error", err)
		os.Exit(1)
	}

	// 初始化 Repository
	certRepo := gorm.NewCertRepo(store.DB)
	taskRepo := gorm.NewTaskRepo(store.DB)
	syncRepo := gorm.NewSyncRepo(store.DB)
	accountRepo := gorm.NewAccountRepo(store.DB)

	// 初始化 APISIX 客户端
	apisixClient := acme.NewApisixClient(cfg)

	// 初始化缓存（使用 DBCache，优先从 DB 读，写时同时落 DB + 文件）
	certCache := cache.NewDBCache(cfg.StorageDir, certRepo)
	_ = certCache.Load()

	// 初始化 HTTP Challenge Store
	httpChallengeStore := acme.NewHTTPChallengeStore()

	// 初始化 ACME Manager
	acmeMgr := acme.NewManager(cfg, certRepo, accountRepo, certCache, httpChallengeStore, apisixClient)

	// 初始化 Task Manager
	taskMgr := task.NewManager(certRepo, taskRepo, acmeMgr, cfg)

	// 初始化 Sync Manager
	syncMgr := sync.NewManager(cfg, certRepo, syncRepo, certCache, apisixClient)

	// 启动所有定时任务
	cronScheduler, err := startAllCrons(cfg, taskRepo, acmeMgr, syncMgr)
	if err != nil {
		logger.Log.Error("启动定时任务失败", "error", err)
		os.Exit(1)
	}

	// 创建 HTTP Server
	router := newRouter(cfg, taskMgr, certRepo, apisixClient, certCache, httpChallengeStore)
	srv := &http.Server{
		Addr:         cfg.Listen,
		Handler:      router,
		ReadTimeout:  time.Duration(cfg.ServerReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.ServerWriteTimeout) * time.Second,
	}

	go func() {
		logger.Log.Info("服务启动中", "listen", cfg.Listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Log.Error("服务启动失败", "error", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	logger.Log.Info("正在关闭服务...")

	// 停止定时任务
	cronCtx := cronScheduler.Stop()
	<-cronCtx.Done()
	logger.Log.Info("定时任务已停止")

	// 关闭 HTTP Server
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Log.Error("服务关闭错误", "error", err)
	}

	// 关闭数据库
	if err := store.Close(); err != nil {
		logger.Log.Error("关闭数据库连接失败", "error", err)
	}

	logger.Log.Info("服务已停止")
}

func startAllCrons(cfg *config.Config, taskRepo task.TaskRepository, acmeMgr *acme.Manager, syncMgr *sync.Manager) (*cron.Cron, error) {
	c := cron.New(cron.WithSeconds())

	if cfg.TaskCleanupCron != "" {
		if _, err := c.AddFunc(cfg.TaskCleanupCron, func() {
			if err := taskRepo.CleanupTasks(cfg.TaskRetentionHrs); err != nil {
				logger.Log.Error("任务清理失败", "error", err)
			}
		}); err != nil {
			return nil, err
		}
		logger.Log.Info("任务清理定时任务已启动", "cron", cfg.TaskCleanupCron, "retention_hours", cfg.TaskRetentionHrs)
	}

	if cfg.RenewCron != "" {
		if _, err := c.AddFunc(cfg.RenewCron, func() {
			logger.Log.Info("开始执行证书续期定时任务")
			acmeMgr.RenewAll()
		}); err != nil {
			return nil, err
		}
		logger.Log.Info("证书续期定时任务已启动", "cron", cfg.RenewCron)
	}

	if cfg.SyncCron != "" {
		if _, err := c.AddFunc(cfg.SyncCron, func() {
			if err := syncMgr.Sync(); err != nil {
				logger.Log.Error("证书同步失败", "error", err)
			}
		}); err != nil {
			return nil, err
		}
		logger.Log.Info("证书同步定时任务已启动", "cron", cfg.SyncCron, "mode", cfg.SyncMode)
	}

	c.Start()
	return c, nil
}
