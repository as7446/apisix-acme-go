package api

import (
	"context"
	"time"

	"github.com/as7446/apisix-acme-go/internal/application"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
)

// OfflineDetector 离线检测器
type OfflineDetector struct {
	svc           *application.AgentService
	checkInterval time.Duration
	stopCh        chan struct{}
}

// NewOfflineDetector 创建离线检测器
func NewOfflineDetector(svc *application.AgentService) *OfflineDetector {
	return &OfflineDetector{
		svc:           svc,
		checkInterval: 30 * time.Second,
		stopCh:        make(chan struct{}),
	}
}

// Start 启动检测器
func (d *OfflineDetector) Start(ctx context.Context) {
	logger.Log.Info("离线检测器已启动", "check_interval", d.checkInterval.String())

	ticker := time.NewTicker(d.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Log.Info("离线检测器已停止")
			return
		case <-d.stopCh:
			logger.Log.Info("离线检测器已停止")
			return
		case <-ticker.C:
			d.check()
		}
	}
}

// Stop 停止检测器
func (d *OfflineDetector) Stop() {
	close(d.stopCh)
}

// check 检测离线 Agent
func (d *OfflineDetector) check() {
	staleAgents, err := d.svc.FindStaleAgents()
	if err != nil {
		logger.Log.Error("检测离线 Agent 失败", "error", err)
		return
	}

	for _, agent := range staleAgents {
		if err := d.svc.SetOffline(agent.AgentID); err != nil {
			logger.Log.Error("设置 Agent 离线失败", "agent_id", agent.AgentID, "error", err)
		} else {
			logger.Log.Info("Agent 已离线", "agent_id", agent.AgentID, "zone", agent.Zone)
		}
	}
}
