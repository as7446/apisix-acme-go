package agent

import "time"

// AgentStatus Agent 状态
type AgentStatus string

const (
	AgentStatusOnline  AgentStatus = "online"
	AgentStatusOffline AgentStatus = "offline"
)

// Agent Agent 实体
type Agent struct {
	ID            int
	AgentID       string      `json:"agent_id"`
	Zone          string      `json:"zone"`
	Hostname      string      `json:"hostname"`
	IP            string      `json:"ip"`
	Version       string      `json:"version"`
	Capabilities  []string    `json:"capabilities"`
	Status        AgentStatus `json:"status"`
	LastHeartbeat int64       `json:"last_heartbeat"`
	CreatedAt     int64       `json:"created_at"`
	UpdatedAt     int64       `json:"updated_at"`
}

// RegisterRequest 注册请求
type RegisterRequest struct {
	AgentID      string   `json:"agent_id" binding:"required"`
	Zone         string   `json:"zone" binding:"required"`
	Hostname     string   `json:"hostname"`
	IP           string   `json:"ip"`
	Version      string   `json:"version"`
	Capabilities []string `json:"capabilities"`
}

// RegisterResponse 注册响应
type RegisterResponse struct {
	HeartbeatInterval int `json:"heartbeat_interval"`
}

// HeartbeatRequest 心跳请求
type HeartbeatRequest struct {
	AgentID  string            `json:"agent_id" binding:"required"`
	SSLState map[string]string `json:"ssl_state"` // domain -> fingerprint（Agent 上报的网关实际 SSL 状态）
}

// HeartbeatResponse 心跳响应
type HeartbeatResponse struct {
	Status string `json:"status"`
}

// AgentRepository Agent 存储接口
type AgentRepository interface {
	// Register 注册或更新 Agent
	Register(req *RegisterRequest) error
	// Heartbeat 更新心跳
	Heartbeat(agentID string) error
	// SetOffline 设置为离线
	SetOffline(agentID string) error
	// ListOnline 获取所有在线 Agent
	ListOnline() ([]*Agent, error)
	// ListOnlineByZone 获取指定 zone 的在线 Agent
	ListOnlineByZone(zone string) ([]*Agent, error)
	// ListOnlineByZones 获取指定多个 zone 的在线 Agent
	ListOnlineByZones(zones []string) ([]*Agent, error)
	// Get 获取 Agent
	Get(agentID string) (*Agent, bool)
	// ListAll 获取所有 Agent
	ListAll() ([]*Agent, error)
}

// TimeNow 当前时间戳
func TimeNow() int64 {
	return time.Now().Unix()
}
