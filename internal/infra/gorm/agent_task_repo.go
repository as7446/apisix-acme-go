package gorm

import (
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/as7446/apisix-acme-go/internal/domain/agenttask"
)

// AgentTaskModel Agent 任务数据库模型
type AgentTaskModel struct {
	ID           string `gorm:"type:varchar(36);primaryKey" json:"id"`
	AgentID      string `gorm:"type:varchar(128);index" json:"agent_id"`
	Type         string `gorm:"type:varchar(32);not null" json:"type"`
	Domain       string `gorm:"type:varchar(255);index" json:"domain"`
	Status       string `gorm:"type:varchar(32);index;default:'pending'" json:"status"`
	Payload      string `gorm:"type:text" json:"payload"` // JSON
	Result       string `gorm:"type:text" json:"result"`  // JSON, nullable
	ErrorMessage string `gorm:"type:text" json:"error_message"`
	CreatedAt    uint64 `gorm:"type:bigint unsigned;default:0" json:"created_at"`
	DispatchedAt uint64 `gorm:"type:bigint unsigned;default:0" json:"dispatched_at"`
	CompletedAt  uint64 `gorm:"type:bigint unsigned;default:0" json:"completed_at"`
	TimeoutAt    uint64 `gorm:"type:bigint unsigned;default:0;index" json:"timeout_at"`
	RetryCount   int    `gorm:"type:int;default:0" json:"retry_count"`
}

func (AgentTaskModel) TableName() string {
	return "cert_agent_tasks"
}

// ToDomain 转换为领域模型
func (m *AgentTaskModel) ToDomain() *agenttask.AgentTask {
	task := &agenttask.AgentTask{
		ID:           m.ID,
		AgentID:      m.AgentID,
		Type:         agenttask.TaskType(m.Type),
		Domain:       m.Domain,
		Status:       agenttask.TaskStatus(m.Status),
		ErrorMessage: m.ErrorMessage,
		CreatedAt:    int64(m.CreatedAt),
		DispatchedAt: int64(m.DispatchedAt),
		CompletedAt:  int64(m.CompletedAt),
		TimeoutAt:    int64(m.TimeoutAt),
		RetryCount:   m.RetryCount,
	}
	if m.Payload != "" {
		_ = json.Unmarshal([]byte(m.Payload), &task.Payload)
	}
	if m.Result != "" {
		_ = json.Unmarshal([]byte(m.Result), &task.Result)
	}
	return task
}

// FromDomain 从领域模型转换
func (m *AgentTaskModel) FromDomain(t *agenttask.AgentTask) {
	m.ID = t.ID
	m.AgentID = t.AgentID
	m.Type = string(t.Type)
	m.Domain = t.Domain
	m.Status = string(t.Status)
	m.ErrorMessage = t.ErrorMessage
	m.CreatedAt = uint64(t.CreatedAt)
	m.DispatchedAt = uint64(t.DispatchedAt)
	m.CompletedAt = uint64(t.CompletedAt)
	m.TimeoutAt = uint64(t.TimeoutAt)
	m.RetryCount = t.RetryCount
	if t.Payload != nil {
		data, _ := json.Marshal(t.Payload)
		m.Payload = string(data)
	}
	if t.Result != nil {
		data, _ := json.Marshal(t.Result)
		m.Result = string(data)
	}
}

// AgentTaskRepo GORM 实现的 AgentTaskRepository
type AgentTaskRepo struct {
	db *gorm.DB
}

// NewAgentTaskRepo 创建 AgentTaskRepo
func NewAgentTaskRepo(db *gorm.DB) *AgentTaskRepo {
	return &AgentTaskRepo{db: db}
}

// Create 创建任务
func (r *AgentTaskRepo) Create(task *agenttask.AgentTask) error {
	var model AgentTaskModel
	model.FromDomain(task)
	return r.db.Create(&model).Error
}

// Get 根据 ID 获取任务
func (r *AgentTaskRepo) Get(taskID string) (*agenttask.AgentTask, error) {
	var model AgentTaskModel
	err := r.db.Where("id = ?", taskID).First(&model).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("任务不存在: %s", taskID)
		}
		return nil, fmt.Errorf("查询任务失败: %w", err)
	}
	return model.ToDomain(), nil
}

// UpdateStatus 更新任务状态和结果
func (r *AgentTaskRepo) UpdateStatus(taskID string, status agenttask.TaskStatus, result map[string]interface{}, errMsg string) error {
	now := uint64(time.Now().Unix())
	updates := map[string]interface{}{
		"status":        string(status),
		"error_message": errMsg,
	}
	switch status {
	case agenttask.StatusSuccess, agenttask.StatusFailed, agenttask.StatusTimeout:
		updates["completed_at"] = now
	}
	if result != nil {
		data, _ := json.Marshal(result)
		updates["result"] = string(data)
	}
	return r.db.Model(&AgentTaskModel{}).Where("id = ?", taskID).Updates(updates).Error
}

// ClaimPending 原子领取 pending 任务
func (r *AgentTaskRepo) ClaimPending(taskID string, agentID string) (bool, error) {
	now := uint64(time.Now().Unix())
	result := r.db.Model(&AgentTaskModel{}).
		Where("id = ? AND agent_id = ? AND status = ?", taskID, agentID, string(agenttask.StatusPending)).
		Updates(map[string]interface{}{
			"status":        string(agenttask.StatusDispatched),
			"dispatched_at": now,
		})
	if result.Error != nil {
		return false, result.Error
	}
	return result.RowsAffected > 0, nil
}

// FindPendingByAgent 查找指定 Agent 的待执行任务
func (r *AgentTaskRepo) FindPendingByAgent(agentID string) ([]*agenttask.AgentTask, error) {
	var models []AgentTaskModel
	err := r.db.Where("agent_id = ? AND status = ?", agentID, string(agenttask.StatusPending)).
		Order("created_at ASC").Find(&models).Error
	if err != nil {
		return nil, err
	}
	result := make([]*agenttask.AgentTask, 0, len(models))
	for i := range models {
		result = append(result, models[i].ToDomain())
	}
	return result, nil
}

// FindTimedOut 查找超时任务
func (r *AgentTaskRepo) FindTimedOut() ([]*agenttask.AgentTask, error) {
	now := uint64(time.Now().Unix())
	var models []AgentTaskModel
	err := r.db.Where("status IN ? AND timeout_at > 0 AND timeout_at < ?",
		[]string{string(agenttask.StatusPending), string(agenttask.StatusDispatched)}, now).
		Find(&models).Error
	if err != nil {
		return nil, err
	}
	result := make([]*agenttask.AgentTask, 0, len(models))
	for i := range models {
		result = append(result, models[i].ToDomain())
	}
	return result, nil
}

// FindByDomainAndStatus 按域名和状态查找任务
func (r *AgentTaskRepo) FindByDomainAndStatus(domain string, statuses []agenttask.TaskStatus) ([]*agenttask.AgentTask, error) {
	statusStrs := make([]string, len(statuses))
	for i, s := range statuses {
		statusStrs[i] = string(s)
	}
	var models []AgentTaskModel
	err := r.db.Where("domain = ? AND status IN ?", domain, statusStrs).
		Order("created_at DESC").Find(&models).Error
	if err != nil {
		return nil, err
	}
	result := make([]*agenttask.AgentTask, 0, len(models))
	for i := range models {
		result = append(result, models[i].ToDomain())
	}
	return result, nil
}

func (r *AgentTaskRepo) List(query agenttask.TaskListQuery) (*agenttask.TaskListResult, error) {
	if query.Page <= 0 {
		query.Page = 1
	}
	if query.Size <= 0 {
		query.Size = 20
	}
	if query.Size > 500 {
		query.Size = 500
	}

	db := r.db.Model(&AgentTaskModel{})
	if query.Domain != "" {
		db = db.Where("domain = ?", query.Domain)
	}
	if query.AgentID != "" {
		db = db.Where("agent_id = ?", query.AgentID)
	}
	if query.Type != "" && query.Type != "all" {
		db = db.Where("type = ?", query.Type)
	}
	if query.Status != "" && query.Status != "all" {
		db = db.Where("status = ?", query.Status)
	}

	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, err
	}

	var models []AgentTaskModel
	offset := (query.Page - 1) * query.Size
	if err := db.Order("created_at DESC").Offset(offset).Limit(query.Size).Find(&models).Error; err != nil {
		return nil, err
	}
	items := make([]*agenttask.AgentTask, 0, len(models))
	for i := range models {
		items = append(items, models[i].ToDomain())
	}
	return &agenttask.TaskListResult{
		Total: total,
		Page:  query.Page,
		Size:  query.Size,
		Items: items,
	}, nil
}
