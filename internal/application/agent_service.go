package application

import (
	"github.com/as7446/apisix-acme-go/internal/domain/agent"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
)

const (
	// DefaultHeartbeatInterval 默认心跳间隔（秒）
	DefaultHeartbeatInterval = 30
	// DefaultOfflineThreshold 默认离线阈值（秒）
	DefaultOfflineThreshold = 90
)

// AgentRepositoryExt 扩展的 AgentRepository 接口
type AgentRepositoryExt interface {
	agent.AgentRepository
	FindStaleAgents(heartbeatInterval, offlineThreshold int) ([]*agent.Agent, error)
}

// AgentService Agent 服务
type AgentService struct {
	repo              AgentRepositoryExt
	heartbeatInterval int
	offlineThreshold  int
}

// NewAgentService 创建 AgentService
func NewAgentService(repo agent.AgentRepository) *AgentService {
	extRepo, ok := repo.(AgentRepositoryExt)
	if !ok {
		panic("AgentRepository must implement AgentRepositoryExt")
	}
	return &AgentService{
		repo:              extRepo,
		heartbeatInterval: DefaultHeartbeatInterval,
		offlineThreshold:  DefaultOfflineThreshold,
	}
}

// Register 注册 Agent
func (s *AgentService) Register(req *agent.RegisterRequest) (*agent.RegisterResponse, error) {
	if err := s.repo.Register(req); err != nil {
		logger.Log.Error("Agent 注册失败", "agent_id", req.AgentID, "error", err)
		return nil, err
	}

	logger.Log.Info("Agent 注册成功", "agent_id", req.AgentID, "zone", req.Zone)
	return &agent.RegisterResponse{
		HeartbeatInterval: s.heartbeatInterval,
	}, nil
}

// Heartbeat 处理心跳
func (s *AgentService) Heartbeat(agentID string) (*agent.HeartbeatResponse, error) {
	if err := s.repo.Heartbeat(agentID); err != nil {
		logger.Log.Error("Agent 心跳失败", "agent_id", agentID, "error", err)
		return nil, err
	}
	return &agent.HeartbeatResponse{Status: "ok"}, nil
}

// SetOffline 设置 Agent 为离线
func (s *AgentService) SetOffline(agentID string) error {
	if err := s.repo.SetOffline(agentID); err != nil {
		return err
	}
	logger.Log.Info("Agent 已离线", "agent_id", agentID)
	return nil
}

// ListOnline 获取所有在线 Agent
func (s *AgentService) ListOnline() ([]*agent.Agent, error) {
	return s.repo.ListOnline()
}

// ListAll 获取所有 Agent
func (s *AgentService) ListAll() ([]*agent.Agent, error) {
	return s.repo.ListAll()
}

// Get 获取 Agent
func (s *AgentService) Get(agentID string) (*agent.Agent, bool) {
	return s.repo.Get(agentID)
}

// GetHeartbeatInterval 获取心跳间隔
func (s *AgentService) GetHeartbeatInterval() int {
	return s.heartbeatInterval
}

// GetOfflineThreshold 获取离线阈值
func (s *AgentService) GetOfflineThreshold() int {
	return s.offlineThreshold
}

// FindStaleAgents 查找超时的 Agent
func (s *AgentService) FindStaleAgents() ([]*agent.Agent, error) {
	return s.repo.FindStaleAgents(s.heartbeatInterval, s.offlineThreshold)
}
