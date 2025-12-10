package main

import (
	"context"
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
		panic(err)
	}

	// APISIX 客户端
	apiClient := NewApisixClient(cfg)

	// 证书元数据存储
	store, err := NewStormCertStore(cfg)
	if err != nil {
		Log.Fatalf("初始化证书元数据存储失败：%v", err)
	}
	defer store.Close()

	// 证书缓存
	certCache := NewCertCache(cfg)
	if err := certCache.Load(); err != nil {
		Log.Printf("加载证书缓存失败：%v", err)
	}

	// HTTP-01 验证存储
	httpChallengeStore := NewHTTPChallengeStore()

	// ACME 管理器
	acmeMgr, err := NewAcmeManager(cfg, store, certCache, httpChallengeStore, apiClient)
	if err != nil {
		Log.Fatalf("初始化 ACME 管理器失败：%v", err)
	}

	// 任务管理器
	taskMgr := NewTaskManager(store, acmeMgr)

	// 路由
	router := NewRouter(cfg, taskMgr, store, apiClient, certCache, httpChallengeStore)

	srv := &http.Server{
		Addr:         cfg.Listen,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// 启动所有定时任务
	syncMgr := NewSyncManager(cfg, store, apiClient, certCache)
	if err := StartAllCrons(cfg, store, acmeMgr, syncMgr); err != nil {
		Log.Fatalf("启动定时任务失败：%v", err)
	}

	go func() {
		Log.Printf("服务启动中，监听地址：%s", cfg.Listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			Log.Fatalf("服务启动失败：%v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		Log.Printf("服务关闭错误：%v", err)
	}

	// 关闭数据库连接
	if err := store.Close(); err != nil {
		Log.Printf("关闭数据库连接失败：%v", err)
	}

	Log.Println("服务已停止")
}
