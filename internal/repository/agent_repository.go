package repository

import (
	"github.com/as7446/apisix-acme-go/internal/domain/agent"
)

// AgentRepositoryExt 扩展的 AgentRepository 接口（包含离线检测）
type AgentRepositoryExt interface {
	agent.AgentRepository
	// FindStaleAgents 查找超时的 Agent（离线检测用）
	FindStaleAgents(heartbeatInterval, offlineThreshold int) ([]*agent.Agent, error)
}
