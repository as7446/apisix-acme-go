package task

import (
	"fmt"
	"sync"
	"time"

	"github.com/as7446/apisix-acme-go/internal/domain/acme"
	"github.com/as7446/apisix-acme-go/internal/domain/cert"
	"github.com/as7446/apisix-acme-go/internal/infra/config"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
)

// Manager 任务管理器
type Manager struct {
	certRepo cert.CertRepository
	taskRepo TaskRepository
	acme     *acme.Manager
	cfg      *config.Config
	mu       sync.RWMutex
	tasks    map[string]*Task
	runningMu sync.Mutex
	runningSet map[string]bool
	sem        chan struct{}
}

// NewManager 创建任务管理器
func NewManager(certRepo cert.CertRepository, taskRepo TaskRepository, acmeMgr *acme.Manager, cfg *config.Config) *Manager {
	return &Manager{
		certRepo:   certRepo,
		taskRepo:   taskRepo,
		acme:       acmeMgr,
		cfg:        cfg,
		tasks:      make(map[string]*Task),
		runningSet: make(map[string]bool),
		sem:        make(chan struct{}, 5),
	}
}

// CreateOrUpdateTask 创建或更新任务
func (m *Manager) CreateOrUpdateTask(domain string, email string, force bool) *Task {
	logger.Log.Info("收到任务请求", "domain", domain, "email", email, "force", force)
	m.mu.Lock()

	m.runningMu.Lock()
	if m.runningSet[domain] {
		m.runningMu.Unlock()
		if t, ok := m.tasks[domain]; ok && t.Status == TaskStatusRunning {
			m.mu.Unlock()
			logger.Log.Info("任务正在运行中，返回运行状态", "domain", domain)
			return t
		}
		logger.Log.Info("任务运行标记存在但状态非 running，清理标记后继续", "domain", domain)
		delete(m.runningSet, domain)
	}
	m.runningMu.Unlock()

	if !force {
		if meta, ok := m.certRepo.Get(domain); ok {
			now := time.Now().Unix()
			if meta.NotAfter > now {
				apisixExists, apisixNotAfter, err := m.acme.CheckAPISIXCertificate(domain)
				if err == nil {
					if apisixExists && apisixNotAfter > 0 && apisixNotAfter > now {
						t := &Task{Domain: domain, Status: TaskStatusSkip}
						m.tasks[domain] = t
						m.mu.Unlock()
						logger.Log.Info("证书已存在且有效（本地和 APISIX），跳过操作", "domain", domain)
						return t
					}
				}
			}
		}
	}

	if t, ok := m.tasks[domain]; ok {
		if t.Status == TaskStatusError {
			logger.Log.Info("上次任务失败，将重新执行", "domain", domain)
		}
	}

	task := &Task{
		Domain: domain,
		Status: TaskStatusCreated,
	}
	m.tasks[domain] = task
	_ = m.taskRepo.SaveTask(domain, string(TaskStatusCreated), "")
	_ = m.taskRepo.CleanupTasks(m.cfg.TaskRetentionHrs)

	m.runningMu.Lock()
	m.runningSet[domain] = true
	m.runningMu.Unlock()

	m.mu.Unlock()
	logger.Log.Info("任务进入运行队列", "domain", domain)

	go m.runTask(domain, email, force)

	return task
}

func (m *Manager) runTask(domain string, email string, force bool) {
	m.sem <- struct{}{}
	defer func() { <-m.sem }()

	defer func() {
		m.runningMu.Lock()
		delete(m.runningSet, domain)
		m.runningMu.Unlock()
		logger.Log.Info("任务运行标记已释放", "domain", domain)
	}()

	defer func() {
		if r := recover(); r != nil {
			logger.Log.Error("证书申请任务发生 panic", "domain", domain, "panic", r)
			m.updateTaskStatus(domain, TaskStatusError, fmt.Sprintf("任务执行发生 panic: %v", r))
		}
	}()

	logger.Log.Info("任务开始执行", "domain", domain)
	m.updateTaskStatus(domain, TaskStatusRunning, "")

	maxRetries := m.cfg.CertRetryMax
	baseDelay := time.Duration(m.cfg.CertRetryDelay) * time.Second

	var meta *cert.Certificate
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			delay := baseDelay * (1 << (attempt - 1))
			logger.Log.Warn("证书申请失败，准备重试",
				"domain", domain, "attempt", attempt, "max", maxRetries,
				"delay", delay, "error", lastErr)
			time.Sleep(delay)
		}
		meta, lastErr = m.acme.RequestCertificate(domain, email, force)
		if lastErr == nil {
			break
		}
	}
	if lastErr != nil {
		logger.Log.Error("证书申请任务失败",
			"domain", domain, "retries", maxRetries, "error", lastErr)
		m.updateTaskStatus(domain, TaskStatusError, lastErr.Error())
		return
	}
	if meta == nil {
		logger.Log.Error("证书申请任务失败：返回的元数据为空", "domain", domain)
		m.updateTaskStatus(domain, TaskStatusError, "证书申请返回的元数据为空")
		return
	}
	logger.Log.Info("证书申请任务成功完成", "domain", domain, "not_after", meta.NotAfter)
	m.updateTaskStatus(domain, TaskStatusSuccess, "")
}

func (m *Manager) updateTaskStatus(domain string, status TaskStatus, errMsg string) {
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
	_ = m.taskRepo.SaveTask(domain, string(status), errMsg)
	_ = m.taskRepo.CleanupTasks(m.cfg.TaskRetentionHrs)
	logger.Log.Info("任务状态更新", "domain", domain, "prev_status", prevStatus, "status", status, "prev_err", prevErr, "err", errMsg)
}

// GetTask 获取任务状态
func (m *Manager) GetTask(domain string) *Task {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if t, ok := m.tasks[domain]; ok {
		return &Task{
			Domain: t.Domain,
			Status: t.Status,
			Error:  t.Error,
		}
	}
	if rec, ok := m.taskRepo.GetTaskRecord(domain); ok {
		return &Task{
			Domain: rec.Domain,
			Status: TaskStatus(rec.Status),
			Error:  rec.Error,
		}
	}
	return nil
}