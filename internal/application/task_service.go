package application

import (
	"context"

	"github.com/as7446/apisix-acme-go/internal/domain/task"
)

// TaskResult 任务结果
type TaskResult struct {
	Domain string `json:"domain"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// TaskService Task 应用服务
type TaskService struct {
	taskManager *task.Manager
}

// NewTaskService 创建 TaskService
func NewTaskService(taskManager *task.Manager) *TaskService {
	return &TaskService{taskManager: taskManager}
}

// CreateTask 创建任务
func (s *TaskService) CreateTask(ctx context.Context, domain, email string, force bool) (*TaskResult, error) {
	t := s.taskManager.CreateOrUpdateTask(domain, email, force)
	return &TaskResult{
		Domain: t.Domain,
		Status: string(t.Status),
	}, nil
}

// GetTask 获取任务
func (s *TaskService) GetTask(ctx context.Context, domain string) (*TaskResult, error) {
	t := s.taskManager.GetTask(domain)
	if t == nil {
		return nil, nil
	}
	return &TaskResult{
		Domain: t.Domain,
		Status: string(t.Status),
		Error:  t.Error,
	}, nil
}
