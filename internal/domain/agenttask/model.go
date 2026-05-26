package agenttask

// TaskType Agent 任务类型
type TaskType string

const (
	// TaskInjectChallenge 注入 HTTP-01 验证路由到网关
	TaskInjectChallenge TaskType = "inject_challenge"
	// TaskRemoveChallenge 移除验证路由
	TaskRemoveChallenge TaskType = "remove_challenge"
	// TaskSyncCert 同步证书到网关
	TaskSyncCert TaskType = "sync_cert"
	// TaskDeleteCert 从网关删除证书
	TaskDeleteCert TaskType = "delete_cert"
)

// TaskStatus Agent 任务状态
type TaskStatus string

const (
	StatusPending    TaskStatus = "pending"
	StatusDispatched TaskStatus = "dispatched"
	StatusSuccess    TaskStatus = "success"
	StatusFailed     TaskStatus = "failed"
	StatusTimeout    TaskStatus = "timeout"
)

// AgentTask Agent 任务领域模型
type AgentTask struct {
	ID           string
	AgentID      string
	Type         TaskType
	Domain       string
	Status       TaskStatus
	Payload      map[string]interface{}
	Result       map[string]interface{}
	ErrorMessage string
	CreatedAt    int64
	DispatchedAt int64
	CompletedAt  int64
	TimeoutAt    int64
	RetryCount   int
}

// TaskReportRequest Agent 任务回报请求
type TaskReportRequest struct {
	AgentID      string                 `json:"agent_id" binding:"required"`
	TaskID       string                 `json:"task_id" binding:"required"`
	Status       TaskStatus             `json:"status" binding:"required"`
	Result       map[string]interface{} `json:"result"`
	ErrorMessage string                 `json:"error_message"`
}

// TaskResponse 长轮询返回的任务结构
type TaskResponse struct {
	ID        string                 `json:"id"`
	Type      TaskType               `json:"type"`
	Domain    string                 `json:"domain"`
	Payload   map[string]interface{} `json:"payload"`
	CreatedAt int64                  `json:"created_at"`
}

// ToResponse 转换为 API 响应
func (t *AgentTask) ToResponse() *TaskResponse {
	return &TaskResponse{
		ID:        t.ID,
		Type:      t.Type,
		Domain:    t.Domain,
		Payload:   t.Payload,
		CreatedAt: t.CreatedAt,
	}
}
