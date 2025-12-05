package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// 加载配置
	cfg, err := LoadConfig("config.yml")
	if err != nil {
		log.Fatalf("加载配置失败：%v", err)
	}

	logger := log.New(os.Stdout, "[apisix-acme-go] ", log.LstdFlags|log.Lshortfile)

	// APISIX 客户端
	apiClient := NewApisixClient(cfg, logger)

	// 证书元数据存储
	store := NewFileCertStore(cfg, logger)
	if err := store.Load(); err != nil {
		logger.Printf("加载证书元数据失败：%v", err)
	}

	// 证书缓存
	certCache := NewCertCache(cfg, logger)
	if err := certCache.Load(); err != nil {
		logger.Printf("加载证书缓存失败：%v", err)
	}

	// HTTP-01 验证存储
	httpChallengeStore := NewHTTPChallengeStore()

	// ACME 管理器
	acmeMgr, err := NewAcmeManager(cfg, store, certCache, httpChallengeStore, apiClient, logger)
	if err != nil {
		logger.Fatalf("初始化 ACME 管理器失败：%v", err)
	}

	// 任务管理器
	taskMgr := NewTaskManager(store, acmeMgr, logger)

	// 路由
	router := NewRouter(cfg, taskMgr, httpChallengeStore, logger)

	srv := &http.Server{
		Addr:         cfg.Listen,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// 启动证书续期定时任务
	if err := StartRenewCron(cfg, store, acmeMgr, logger); err != nil {
		logger.Fatalf("启动定时任务失败：%v", err)
	}

	go func() {
		logger.Printf("服务启动中，监听地址：%s", cfg.Listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("服务启动失败：%v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Printf("服务关闭错误：%v", err)
	}

	logger.Println("服务已停止")
}
