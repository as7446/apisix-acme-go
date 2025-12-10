package main

import (
	"fmt"
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

// TaskManager 任务管理器
type TaskManager struct {
	store      *StormCertStore
	acme       *AcmeManager
	mu         sync.RWMutex
	tasks      map[string]*Task
	runningMu  sync.Mutex // 用于防止同一域名的多个请求同时处理
	runningSet map[string]bool
}

// NewTaskManager 创建任务管理器
func NewTaskManager(store *StormCertStore, acme *AcmeManager) *TaskManager {
	return &TaskManager{
		store:      store,
		acme:       acme,
		tasks:      make(map[string]*Task),
		runningSet: make(map[string]bool),
	}
}

// CreateOrUpdateTask 创建或更新任务
func (m *TaskManager) CreateOrUpdateTask(domain string, email string, force bool) *Task {
	Log.Printf("收到任务请求：domain=%s, email=%s, force=%v", domain, email, force)
	m.mu.Lock()

	// 1. 检查是否已有任务正在运行
	m.runningMu.Lock()
	if m.runningSet[domain] {
		m.runningMu.Unlock()
		// 检查任务状态
		if t, ok := m.tasks[domain]; ok && t.Status == TaskStatusRunning {
			m.mu.Unlock()
			Log.Printf("域名 %s 的任务正在运行中，返回运行状态", domain)
			return t
		}
		// 如果任务状态不是 running，清除运行标记
		Log.Printf("域名 %s 的任务运行标记存在但状态非 running，清理标记后继续", domain)
		delete(m.runningSet, domain)
	}
	m.runningMu.Unlock()

	// 2. 检查已有证书
	if !force {
		if meta, ok := m.store.Get(domain); ok {
			now := time.Now().Unix()
			// 检查本地证书是否有效
			if meta.NotAfter > now {
				// 还需要检查 APISIX 中的证书状态
				apisixExists, apisixNotAfter, err := m.acme.CheckAPISIXCertificate(domain)
				if err == nil {
					if apisixExists && apisixNotAfter > 0 && apisixNotAfter > now {
						// APISIX 中证书也存在且有效，跳过
						t := &Task{Domain: domain, Status: TaskStatusSkip}
						m.tasks[domain] = t
						m.mu.Unlock()
						Log.Printf("证书已存在且有效（本地和 APISIX），跳过操作：域名=%s", domain)
						return t
					}
				}
			}
		}
	}

	// 3. 如果已有任务但状态不是 running，清除旧状态
	if t, ok := m.tasks[domain]; ok {
		if t.Status == TaskStatusError {
			Log.Printf("域名 %s 的上次任务失败，将重新执行", domain)
		}
	}

	// 4. 创建新任务并标记为运行中
	task := &Task{
		Domain: domain,
		Status: TaskStatusCreated,
	}
	m.tasks[domain] = task
	_ = m.store.SaveTask(domain, string(TaskStatusCreated), "")
	_ = m.store.CleanupTasks(m.acme.cfg.TaskRetentionHrs)

	// 标记为运行中
	m.runningMu.Lock()
	m.runningSet[domain] = true
	m.runningMu.Unlock()

	m.mu.Unlock()
	Log.Printf("任务进入运行队列：domain=%s", domain)

	// 5. 异步执行任务
	go m.runTask(domain, email, force)

	return task
}

// runTask 异步执行证书申请任务
func (m *TaskManager) runTask(domain string, email string, force bool) {
	defer func() {
		// 任务完成后清除运行标记
		m.runningMu.Lock()
		delete(m.runningSet, domain)
		m.runningMu.Unlock()
		Log.Printf("任务运行标记已释放：domain=%s", domain)
	}()

	// 添加 panic 恢复，确保状态总是被更新
	defer func() {
		if r := recover(); r != nil {
			Log.Printf("域名 %s 的证书申请任务发生 panic：%v", domain, r)
			m.updateTaskStatus(domain, TaskStatusError, fmt.Sprintf("任务执行发生 panic: %v", r))
		}
	}()

	Log.Printf("任务开始执行：domain=%s", domain)
	m.updateTaskStatus(domain, TaskStatusRunning, "")
	meta, err := m.acme.RequestCertificate(domain, email, force)
	if err != nil {
		Log.Printf("域名 %s 的证书申请任务失败：%v", domain, err)
		m.updateTaskStatus(domain, TaskStatusError, err.Error())
		return
	}
	// 确保证书申请和上传都成功
	if meta == nil {
		Log.Printf("域名 %s 的证书申请任务失败：返回的元数据为空", domain)
		m.updateTaskStatus(domain, TaskStatusError, "证书申请返回的元数据为空")
		return
	}
	Log.Printf("域名 %s 的证书申请任务成功完成：not_after=%d", domain, meta.NotAfter)
	m.updateTaskStatus(domain, TaskStatusSuccess, "")
}

// updateTaskStatus 更新任务状态
func (m *TaskManager) updateTaskStatus(domain string, status TaskStatus, errMsg string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	prevStatus := TaskStatus("")
	prevErr := ""

	if t, ok := m.tasks[domain]; ok {
		prevStatus = t.Status
		prevErr = t.Error
		t.Status = status
		t.Error = errMsg
	} else {
		m.tasks[domain] = &Task{
			Domain: domain,
			Status: status,
			Error:  errMsg,
		}
	}
	_ = m.store.SaveTask(domain, string(status), errMsg)
	_ = m.store.CleanupTasks(m.acme.cfg.TaskRetentionHrs)
	Log.Printf("任务状态更新：domain=%s, %s -> %s, err_prev=%s, err_now=%s", domain, prevStatus, status, prevErr, errMsg)
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
	if rec, ok := m.store.GetTaskRecord(domain); ok {
		return &Task{
			Domain: rec.Domain,
			Status: TaskStatus(rec.Status),
			Error:  rec.Error,
		}
	}
	return nil
}
