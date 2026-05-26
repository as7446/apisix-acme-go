package agenttask

// AgentTaskRepository Agent 任务持久化接口
type AgentTaskRepository interface {
	// Create 创建任务
	Create(task *AgentTask) error
	// Get 根据 ID 获取任务
	Get(taskID string) (*AgentTask, error)
	// UpdateStatus 更新任务状态和结果
	UpdateStatus(taskID string, status TaskStatus, result map[string]interface{}, errMsg string) error
	// ClaimPending 原子领取 pending 任务，成功后状态变为 dispatched
	ClaimPending(taskID string, agentID string) (bool, error)
	// FindPendingByAgent 查找指定 Agent 的待执行任务
	FindPendingByAgent(agentID string) ([]*AgentTask, error)
	// FindTimedOut 查找超时任务
	FindTimedOut() ([]*AgentTask, error)
	// FindByDomainAndStatus 按域名和状态查找任务
	FindByDomainAndStatus(domain string, statuses []TaskStatus) ([]*AgentTask, error)
}
