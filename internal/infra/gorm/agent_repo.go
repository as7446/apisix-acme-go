package gorm

import (
	"encoding/json"
	"fmt"

	"gorm.io/gorm"

	"github.com/as7446/apisix-acme-go/internal/domain/agent"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
)

// AgentModel Agent 数据库模型
type AgentModel struct {
	ID            uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	AgentID       string `gorm:"type:varchar(128);uniqueIndex;not null" json:"agent_id"`
	Zone          string `gorm:"type:varchar(64);index" json:"zone"`
	Hostname      string `gorm:"type:varchar(255);default:''" json:"hostname"`
	IP            string `gorm:"type:varchar(64);default:''" json:"ip"`
	Version       string `gorm:"type:varchar(32);default:''" json:"version"`
	Capabilities  string `gorm:"type:json" json:"capabilities"` // JSON array
	Status        string `gorm:"type:varchar(32);default:'online';index" json:"status"`
	LastHeartbeat uint64 `gorm:"type:bigint unsigned;default:0" json:"last_heartbeat"`
	CreatedAt     uint64 `gorm:"type:bigint unsigned;default:0" json:"created_at"`
	UpdatedAt     uint64 `gorm:"type:bigint unsigned;default:0" json:"updated_at"`
}

func (AgentModel) TableName() string {
	return "cert_agents"
}

// ToDomain 转换为领域模型
func (m *AgentModel) ToDomain() *agent.Agent {
	var caps []string
	if m.Capabilities != "" && m.Capabilities != "[]" {
		json.Unmarshal([]byte(m.Capabilities), &caps)
	}

	return &agent.Agent{
		ID:            int(m.ID),
		AgentID:       m.AgentID,
		Zone:          m.Zone,
		Hostname:      m.Hostname,
		IP:            m.IP,
		Version:       m.Version,
		Capabilities:  caps,
		Status:        agent.AgentStatus(m.Status),
		LastHeartbeat: int64(m.LastHeartbeat),
		CreatedAt:     int64(m.CreatedAt),
		UpdatedAt:     int64(m.UpdatedAt),
	}
}

// FromDomain 从领域模型转换
func (m *AgentModel) FromDomain(a *agent.Agent) {
	m.AgentID = a.AgentID
	m.Zone = a.Zone
	m.Hostname = a.Hostname
	m.IP = a.IP
	m.Version = a.Version
	if len(a.Capabilities) > 0 {
		capsJSON, _ := json.Marshal(a.Capabilities)
		m.Capabilities = string(capsJSON)
	}
	m.Status = string(a.Status)
	m.LastHeartbeat = uint64(a.LastHeartbeat)
	m.CreatedAt = uint64(a.CreatedAt)
	m.UpdatedAt = uint64(a.UpdatedAt)
}

// AgentRepo GORM 实现的 AgentRepository
type AgentRepo struct {
	db *gorm.DB
}

// NewAgentRepo 创建 AgentRepo
func NewAgentRepo(db *gorm.DB) *AgentRepo {
	return &AgentRepo{db: db}
}

// Register 注册或更新 Agent
func (r *AgentRepo) Register(req *agent.RegisterRequest) error {
	now := TimeNow()

	var existing AgentModel
	err := r.db.Where("agent_id = ?", req.AgentID).First(&existing).Error

	if err == gorm.ErrRecordNotFound {
		// 不存在，创建
		model := AgentModel{
			AgentID:       req.AgentID,
			Zone:          req.Zone,
			Hostname:      req.Hostname,
			IP:            req.IP,
			Version:       req.Version,
			Status:        string(agent.AgentStatusOnline),
			LastHeartbeat: uint64(now),
			CreatedAt:     uint64(now),
			UpdatedAt:     uint64(now),
		}
		if len(req.Capabilities) > 0 {
			capsJSON, _ := json.Marshal(req.Capabilities)
			model.Capabilities = string(capsJSON)
		}
		return r.db.Create(&model).Error
	} else if err != nil {
		return fmt.Errorf("查询 Agent 失败: %w", err)
	}

	// 存在，更新
	updates := map[string]interface{}{
		"zone":           req.Zone,
		"hostname":       req.Hostname,
		"ip":             req.IP,
		"version":        req.Version,
		"status":         string(agent.AgentStatusOnline),
		"last_heartbeat": now,
		"updated_at":     now,
	}
	if len(req.Capabilities) > 0 {
		capsJSON, _ := json.Marshal(req.Capabilities)
		updates["capabilities"] = string(capsJSON)
	}

	return r.db.Model(&AgentModel{}).Where("agent_id = ?", req.AgentID).Updates(updates).Error
}

// Heartbeat 更新心跳
func (r *AgentRepo) Heartbeat(agentID string) error {
	now := TimeNow()
	return r.db.Model(&AgentModel{}).Where("agent_id = ?", agentID).Updates(map[string]interface{}{
		"last_heartbeat": now,
		"status":         string(agent.AgentStatusOnline),
		"updated_at":     now,
	}).Error
}

// SetOffline 设置为离线
func (r *AgentRepo) SetOffline(agentID string) error {
	now := TimeNow()
	return r.db.Model(&AgentModel{}).Where("agent_id = ?", agentID).Updates(map[string]interface{}{
		"status":     string(agent.AgentStatusOffline),
		"updated_at": now,
	}).Error
}

// ListOnline 获取所有在线 Agent
func (r *AgentRepo) ListOnline() ([]*agent.Agent, error) {
	var models []AgentModel
	err := r.db.Where("status = ?", string(agent.AgentStatusOnline)).Find(&models).Error
	if err != nil {
		return nil, err
	}
	result := make([]*agent.Agent, 0, len(models))
	for i := range models {
		result = append(result, models[i].ToDomain())
	}
	return result, nil
}

// Get 获取 Agent
func (r *AgentRepo) Get(agentID string) (*agent.Agent, bool) {
	var model AgentModel
	err := r.db.Where("agent_id = ?", agentID).First(&model).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, false
		}
		logger.Log.Error("查询 Agent 失败", "agent_id", agentID, "error", err)
		return nil, false
	}
	return model.ToDomain(), true
}

// ListAll 获取所有 Agent
func (r *AgentRepo) ListAll() ([]*agent.Agent, error) {
	var models []AgentModel
	err := r.db.Find(&models).Error
	if err != nil {
		return nil, err
	}
	result := make([]*agent.Agent, 0, len(models))
	for i := range models {
		result = append(result, models[i].ToDomain())
	}
	return result, nil
}

// FindStaleAgents 查找超时的 Agent（离线检测用）
func (r *AgentRepo) FindStaleAgents(heartbeatInterval, offlineThreshold int) ([]*agent.Agent, error) {
	threshold := TimeNow() - uint64(heartbeatInterval+offlineThreshold)
	var models []AgentModel
	err := r.db.Where("status = ? AND last_heartbeat < ?", string(agent.AgentStatusOnline), threshold).Find(&models).Error
	if err != nil {
		return nil, err
	}
	result := make([]*agent.Agent, 0, len(models))
	for i := range models {
		result = append(result, models[i].ToDomain())
	}
	return result, nil
}
