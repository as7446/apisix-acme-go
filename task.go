package main

import (
	"sync"
	"time"
)

// TaskStatus 任务状态
type TaskStatus string

const (
	TaskStatusCreated TaskStatus = "created" // 已创建
	TaskStatusRunning TaskStatus = "running" // 运行中
	TaskStatusSuccess TaskStatus = "success" // 成功
	TaskStatusError   TaskStatus = "error"   // 失败
	TaskStatusSkip    TaskStatus = "skip"    // 跳过
)

// Task 证书申请任务
type Task struct {
	Domain string     `json:"domain"`          // 域名
	Status TaskStatus `json:"status"`          // 任务状态
	Error  string     `json:"error,omitempty"` // 错误信息（仅当 status=error 时存在）
}

// TaskManager 任务管理器（内存存储）
type TaskManager struct {
	store *FileCertStore
	acme  *AcmeManager
	log   Logger

	mu    sync.RWMutex
	tasks map[string]*Task
}

// NewTaskManager 创建任务管理器
func NewTaskManager(store *FileCertStore, acme *AcmeManager, logger Logger) *TaskManager {
	return &TaskManager{
		store: store,
		acme:  acme,
		log:   logger,
		tasks: make(map[string]*Task),
	}
}

// CreateOrUpdateTask 创建或更新证书任务
// 行为说明：
// - 如果证书存在且未过期 => status=skip
// - 如果任务正在运行 => status=running
// - 否则创建新任务并异步执行 => status=created
func (m *TaskManager) CreateOrUpdateTask(domain string, email string, force bool) *Task {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 1. 检查已有证书
	if !force {
		if meta, ok := m.store.Get(domain); ok {
			now := time.Now().Unix()
			if meta.NotAfter > now {
				t := &Task{Domain: domain, Status: TaskStatusSkip}
				m.tasks[domain] = t
				return t
			}
		}
	}

	// 2. 如果已有任务在运行，返回运行状态
	// 如果任务失败（error），允许重新执行（使用缓存的证书重试上传 APISIX）
	if t, ok := m.tasks[domain]; ok {
		if t.Status == TaskStatusRunning {
			return t
		}
		// 如果之前失败，清除旧任务状态，允许重新执行
		if t.Status == TaskStatusError {
			m.log.Printf("域名 %s 的上次任务失败，将使用缓存的证书重试", domain)
		}
	}

	// 3. 创建新任务并异步执行
	task := &Task{
		Domain: domain,
		Status: TaskStatusCreated,
	}
	m.tasks[domain] = task

	go m.runTask(domain, email)

	return task
}

// runTask 异步执行证书申请任务
func (m *TaskManager) runTask(domain string, email string) {
	m.updateTaskStatus(domain, TaskStatusRunning, "")
	if _, err := m.acme.RequestCertificate(domain, email); err != nil {
		m.log.Printf("域名 %s 的证书申请任务失败：%v", domain, err)
		m.updateTaskStatus(domain, TaskStatusError, err.Error())
		return
	}
	m.updateTaskStatus(domain, TaskStatusSuccess, "")
}

// updateTaskStatus 更新任务状态
func (m *TaskManager) updateTaskStatus(domain string, status TaskStatus, errMsg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.tasks[domain]; ok {
		t.Status = status
		t.Error = errMsg
	} else {
		m.tasks[domain] = &Task{
			Domain: domain,
			Status: status,
			Error:  errMsg,
		}
	}
}

// GetTask 获取任务状态
func (m *TaskManager) GetTask(domain string) *Task {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if t, ok := m.tasks[domain]; ok {
		return &Task{
			Domain: t.Domain,
			Status: t.Status,
			Error:  t.Error,
		}
	}
	return nil
}
