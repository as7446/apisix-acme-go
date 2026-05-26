package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/robfig/cron/v3"

	"github.com/as7446/apisix-acme-go/internal/api"
	"github.com/as7446/apisix-acme-go/internal/api/handler"
	"github.com/as7446/apisix-acme-go/internal/api/router"
	"github.com/as7446/apisix-acme-go/internal/application"
	"github.com/as7446/apisix-acme-go/internal/controller"
	"github.com/as7446/apisix-acme-go/internal/controller/dispatch"
	"github.com/as7446/apisix-acme-go/internal/domain/acme"
	"github.com/as7446/apisix-acme-go/internal/infra/cache"
	"github.com/as7446/apisix-acme-go/internal/infra/config"
	"github.com/as7446/apisix-acme-go/internal/infra/gorm"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
	"github.com/as7446/apisix-acme-go/internal/infra/queue"
	"github.com/as7446/apisix-acme-go/internal/infra/statestore"
)

func runController(cfg *config.Config) {
	logger.Log.Info("Controller 启动", "mode", "controller-agent")

	// 初始化数据库
	store, err := gorm.New(cfg)
	if err != nil {
		logger.Log.Error("初始化数据库失败", "error", err)
		os.Exit(1)
	}

	// 初始化 Repository
	certRepo := gorm.NewCertRepo(store.DB)
	accountRepo := gorm.NewAccountRepo(store.DB)
	agentRepo := gorm.NewAgentRepo(store.DB)

	if cfg.Redis.Addr == "" {
		logger.Log.Error("Controller+Agent 模式需要配置 Redis (redis.addr)，用于保存 Agent 在线状态和心跳数据")
		os.Exit(1)
	}

	// Agent 模式下 challenge_route 校验
	if cfg.ChallengeRoute.Enable && len(cfg.ChallengeRoute.UpstreamNodes) == 0 {
		logger.Log.Error("启用了 challenge_route 但未配置 upstream_nodes，" +
			"请设置 challenge_route.upstream_nodes 为 Controller 的可达地址（如 10.0.0.1:8080），" +
			"否则 HTTP-01 验证会因 APISIX 无法回连 Controller 而失败（502）")
		os.Exit(1)
	}

	stateStore, err := statestore.NewRedisAgentStateStore(&cfg.Redis)
	if err != nil {
		logger.Log.Error("初始化 Redis AgentStateStore 失败", "error", err)
		os.Exit(1)
	}

	agentTaskRepo := gorm.NewAgentTaskRepo(store.DB)
	agentSvc := application.NewAgentService(agentRepo, stateStore)
	dispatcher := dispatch.NewTaskDispatcher(agentTaskRepo, agentSvc, cfg)

	certCache := cache.NewDBCache(cfg.Storage.Local.BasePath, certRepo)
	_ = certCache.Load()

	httpChallengeStore := acme.NewHTTPChallengeStore()
	acmeMgr := acme.NewManager(cfg, accountRepo, httpChallengeStore)

	issueQueue, err := queue.NewQueue(cfg, "issue")
	if err != nil {
		logger.Log.Error("创建 IssueQueue 失败", "error", err)
		os.Exit(1)
	}
	if cfg.QueueType == "redis" {
		if rq, ok := issueQueue.(*queue.RedisQueue); ok {
			_ = rq.RecoverProcessing()
		}
	}

	issuer := application.NewIssuer(certRepo, certCache, certCache, acmeMgr, cfg)

	// 创建 RetryScheduler（精确重试调度），入队回调使用闭包捕获 issueQueue
	retryScheduler := controller.NewRetryScheduler(certRepo, cfg, func(domain, action string) error {
		return issueQueue.Enqueue(&queue.Task{
			ID:        uuid.New().String(),
			Type:      queue.TaskIssue,
			Domain:    domain,
			CreatedAt: time.Now().Unix(),
			Payload:   map[string]interface{}{"action": action},
		})
	})

	issuerFSM := controller.NewIssuerFSM(issueQueue, dispatcher, issuer, certRepo, certCache, certCache, cfg, retryScheduler)
	driftDetector := controller.NewDriftDetector(certRepo, certCache, stateStore, dispatcher, cfg)

	ctx, ctxCancel := context.WithCancel(context.Background())
	_ = issuerFSM.RecoverFromDB(ctx)
	retryScheduler.Start(ctx)
	issuerFSM.Start(ctx)

	offlineDetector := api.NewOfflineDetector(agentSvc)
	detectorCtx, detectorCancel := context.WithCancel(context.Background())
	go offlineDetector.Start(detectorCtx)

	scheduler := application.NewScheduler(certRepo, certCache, cfg, issueQueue)
	commandSvc := application.NewCertCommandService(certRepo, issueQueue)
	certSvc := application.NewCertService(certRepo, dispatcher, time.Duration(cfg.AgentTaskTimeout)*time.Second)

	h := handler.NewContainer(commandSvc, certSvc, agentSvc, dispatcher, cfg)

	cronScheduler, err := startCrons(cfg, scheduler, issuerFSM, driftDetector)
	if err != nil {
		logger.Log.Error("启动定时任务失败", "error", err)
		os.Exit(1)
	}

	deps := &router.Dependencies{
		Config:    cfg,
		H:         h,
		HTTPStore: httpChallengeStore,
	}
	r := router.New(deps)

	srv := &http.Server{
		Addr:         cfg.Listen,
		Handler:      r,
		ReadTimeout:  time.Duration(cfg.ServerReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.ServerWriteTimeout) * time.Second,
	}

	go func() {
		logger.Log.Info("服务启动中", "listen", cfg.Listen, "mode", "controller-agent")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Log.Error("服务启动失败", "error", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	logger.Log.Info("正在关闭服务...")
	cronCtx := cronScheduler.Stop()
	<-cronCtx.Done()
	retryScheduler.Stop()
	ctxCancel()
	issuerFSM.Stop()
	detectorCancel()
	_ = issueQueue.Close()
	_ = stateStore.Close()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
	_ = store.Close()
	logger.Log.Info("服务已停止")
}

func startCrons(
	cfg *config.Config,
	scheduler *application.Scheduler,
	issuerFSM *controller.IssuerFSM,
	driftDetector *controller.DriftDetector,
) (*cron.Cron, error) {
	c := cron.New(cron.WithSeconds())

	if cfg.RenewCron != "" {
		_, _ = c.AddFunc(cfg.RenewCron, func() {
			_, _ = scheduler.ScanAndSchedule()
		})
	}
	if cfg.DriftCron != "" {
		_, _ = c.AddFunc(cfg.DriftCron, func() {
			_ = driftDetector.Detect()
		})
	}
	if cfg.RecoveryCron != "" {
		_, _ = c.AddFunc(cfg.RecoveryCron, func() {
			_ = issuerFSM.RecoverFromDB(context.Background())
		})
	}

	c.Start()
	logger.Log.Info("Controller+Agent 定时任务已启动")
	return c, nil
}
