package task

// TaskStatus 任务状态
type TaskStatus string

const (
	TaskStatusCreated TaskStatus = "created"
	TaskStatusRunning TaskStatus = "running"
	TaskStatusSuccess TaskStatus = "success"
	TaskStatusError   TaskStatus = "error"
	TaskStatusSkip    TaskStatus = "skip"
)

// Task 证书申请任务
type Task struct {
	Domain string     `json:"domain"`
	Status TaskStatus `json:"status"`
	Error  string     `json:"error,omitempty"`
}

// TaskRecord 任务持久化记录
type TaskRecord struct {
	ID        int
	Domain    string
	Status    string
	Error     string
	CreatedAt int64
	UpdatedAt int64
}

// TaskRepository 任务存储接口
type TaskRepository interface {
	// SaveTask 保存任务记录
	SaveTask(domain string, status string, errMsg string) error
	// GetTaskRecord 获取任务记录
	GetTaskRecord(domain string) (*TaskRecord, bool)
	// CleanupTasks 清理过期任务记录
	CleanupTasks(retentionHours int) error
}