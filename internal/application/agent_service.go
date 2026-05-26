package application

import (
	"time"

	"github.com/as7446/apisix-acme-go/internal/domain/agent"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
	"github.com/as7446/apisix-acme-go/internal/infra/metrics"
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

// AgentStateStore Agent 状态存储接口（SSL 指纹等）
type AgentStateStore interface {
	SaveSSLState(agentID string, state map[string]string) error
}

// AgentService Agent 服务
type AgentService struct {
	repo              AgentRepositoryExt
	stateStore        AgentStateStore
	heartbeatInterval int
	offlineThreshold  int
}

// NewAgentService 创建 AgentService
func NewAgentService(repo agent.AgentRepository, stateStore AgentStateStore) *AgentService {
	extRepo, ok := repo.(AgentRepositoryExt)
	if !ok {
		panic("AgentRepository must implement AgentRepositoryExt")
	}
	return &AgentService{
		repo:              extRepo,
		stateStore:        stateStore,
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
func (s *AgentService) Heartbeat(agentID string, sslState map[string]string) (*agent.HeartbeatResponse, error) {
	if err := s.repo.Heartbeat(agentID); err != nil {
		logger.Log.Error("Agent 心跳失败", "agent_id", agentID, "error", err)
		return nil, err
	}
	metrics.AgentHeartbeatTotal.Add(1)

	// 保存 SSL 状态到 Redis（如果有上报且 stateStore 已配置）
	if len(sslState) > 0 && s.stateStore != nil {
		if err := s.stateStore.SaveSSLState(agentID, sslState); err != nil {
			logger.Log.Error("保存 Agent SSL 状态失败", "agent_id", agentID, "error", err)
		}
	}

	return &agent.HeartbeatResponse{Status: "ok"}, nil
}

// SetOffline 设置 Agent 为离线
func (s *AgentService) SetOffline(agentID string) error {
	if err := s.repo.SetOffline(agentID); err != nil {
		return err
	}
	metrics.AgentOfflineTotal.Add(1)
	logger.Log.Info("Agent 已离线", "agent_id", agentID)
	return nil
}

// ListOnline 获取所有在线 Agent
func (s *AgentService) ListOnline() ([]*agent.Agent, error) {
	agents, err := s.repo.ListOnline()
	if err != nil {
		return nil, err
	}
	return s.filterFreshOnline(agents), nil
}

// ListOnlineByZone 获取指定 zone 的在线 Agent
func (s *AgentService) ListOnlineByZone(zone string) ([]*agent.Agent, error) {
	agents, err := s.repo.ListOnlineByZone(zone)
	if err != nil {
		return nil, err
	}
	return s.filterFreshOnline(agents), nil
}

// ListOnlineByZones 获取指定多个 zone 的在线 Agent
func (s *AgentService) ListOnlineByZones(zones []string) ([]*agent.Agent, error) {
	agents, err := s.repo.ListOnlineByZones(zones)
	if err != nil {
		return nil, err
	}
	return s.filterFreshOnline(agents), nil
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

func (s *AgentService) filterFreshOnline(agents []*agent.Agent) []*agent.Agent {
	if len(agents) == 0 {
		return agents
	}
	minHeartbeat := time.Now().Unix() - int64(s.heartbeatInterval+s.offlineThreshold)
	filtered := make([]*agent.Agent, 0, len(agents))
	for _, a := range agents {
		if a.LastHeartbeat >= minHeartbeat {
			filtered = append(filtered, a)
			continue
		}
		logger.Log.Warn("跳过心跳已超时但尚未标记离线的 Agent", "agent_id", a.AgentID, "zone", a.Zone, "last_heartbeat", a.LastHeartbeat)
	}
	return filtered
}
