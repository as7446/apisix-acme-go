package dispatch

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/as7446/apisix-acme-go/internal/domain/agent"
	"github.com/as7446/apisix-acme-go/internal/domain/agenttask"
	"github.com/as7446/apisix-acme-go/internal/infra/config"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
)

const (
	channelBufferSize = 32
)

// AgentLister 查询在线 Agent 的接口
type AgentLister interface {
	ListOnline() ([]*agent.Agent, error)
	ListOnlineByZone(zone string) ([]*agent.Agent, error)
	ListOnlineByZones(zones []string) ([]*agent.Agent, error)
}

// TaskDispatcher 任务分发器
type TaskDispatcher struct {
	mu       sync.RWMutex
	channels map[string]chan *agenttask.AgentTask
	repo     agenttask.AgentTaskRepository
	agentSvc AgentLister
	cfg      *config.Config

	subMu       sync.RWMutex
	subscribers map[string][]chan *agenttask.TaskReportRequest
}

// NewTaskDispatcher 创建任务分发器
func NewTaskDispatcher(repo agenttask.AgentTaskRepository, agentSvc AgentLister, cfg *config.Config) *TaskDispatcher {
	return &TaskDispatcher{
		channels:    make(map[string]chan *agenttask.AgentTask),
		repo:        repo,
		agentSvc:    agentSvc,
		cfg:         cfg,
		subscribers: make(map[string][]chan *agenttask.TaskReportRequest),
	}
}

// Dispatch 派发任务给指定 Agent
func (d *TaskDispatcher) Dispatch(task *agenttask.AgentTask) error {
	if task.ID == "" {
		task.ID = uuid.New().String()
	}
	if task.CreatedAt == 0 {
		task.CreatedAt = time.Now().Unix()
	}
	if task.TimeoutAt == 0 {
		task.TimeoutAt = time.Now().Unix() + int64(d.cfg.AgentTaskTimeout)
	}

	if task.AgentID == "" {
		agentID, err := d.SelectAgent(nil)
		if err != nil {
			return fmt.Errorf("选择 Agent 失败: %w", err)
		}
		task.AgentID = agentID
	}

	task.Status = agenttask.StatusPending

	if err := d.repo.Create(task); err != nil {
		return fmt.Errorf("保存任务失败: %w", err)
	}

	ch := d.getOrCreateChannel(task.AgentID)
	select {
	case ch <- task:
		logger.Log.Debug("任务已派发到 Agent channel",
			"task_id", task.ID, "agent_id", task.AgentID, "type", task.Type)
	default:
		logger.Log.Warn("Agent channel 已满，任务将通过 DB 轮询获取",
			"task_id", task.ID, "agent_id", task.AgentID)
	}

	return nil
}

// DispatchAndWait 派发任务并等待结果
func (d *TaskDispatcher) DispatchAndWait(task *agenttask.AgentTask, timeout time.Duration) (*agenttask.TaskReportRequest, error) {
	reportCh := make(chan *agenttask.TaskReportRequest, 1)
	if task.ID == "" {
		task.ID = uuid.New().String()
	}

	d.subscribe(task.Domain, task.ID, reportCh)
	defer d.unsubscribe(task.Domain, task.ID, reportCh)

	if err := d.Dispatch(task); err != nil {
		return nil, err
	}

	select {
	case report := <-reportCh:
		return report, nil
	case <-time.After(timeout):
		_ = d.repo.UpdateStatus(task.ID, agenttask.StatusTimeout, nil, "等待 Agent 回报超时")
		return nil, fmt.Errorf("任务超时: task_id=%s, domain=%s, type=%s", task.ID, task.Domain, task.Type)
	}
}

// WaitForTask Agent 长轮询等待任务
func (d *TaskDispatcher) WaitForTask(agentID string, timeout time.Duration) (*agenttask.AgentTask, error) {
	pending, err := d.repo.FindPendingByAgent(agentID)
	if err != nil {
		return nil, fmt.Errorf("查询 pending 任务失败: %w", err)
	}
	if len(pending) > 0 {
		task := pending[0]
		claimed, err := d.repo.ClaimPending(task.ID, agentID)
		if err != nil {
			return nil, fmt.Errorf("领取 pending 任务失败: %w", err)
		}
		if claimed {
			task.Status = agenttask.StatusDispatched
			task.DispatchedAt = time.Now().Unix()
			return task, nil
		}
	}

	ch := d.getOrCreateChannel(agentID)
	select {
	case task := <-ch:
		claimed, err := d.repo.ClaimPending(task.ID, agentID)
		if err != nil {
			return nil, fmt.Errorf("领取 channel 任务失败: %w", err)
		}
		if !claimed {
			return d.WaitForTask(agentID, 0)
		}
		task.Status = agenttask.StatusDispatched
		task.DispatchedAt = time.Now().Unix()
		return task, nil
	case <-time.After(timeout):
		return nil, nil
	}
}

// HandleReport 处理 Agent 任务回报
func (d *TaskDispatcher) HandleReport(report *agenttask.TaskReportRequest) error {
	if err := d.repo.UpdateStatus(report.TaskID, report.Status, report.Result, report.ErrorMessage); err != nil {
		return fmt.Errorf("更新任务状态失败: %w", err)
	}

	task, err := d.repo.Get(report.TaskID)
	if err != nil {
		return fmt.Errorf("获取任务信息失败: %w", err)
	}

	d.notifySubscribers(task.Domain, report)

	logger.Log.Info("Agent 任务回报已处理",
		"task_id", report.TaskID, "agent_id", report.AgentID,
		"status", report.Status, "domain", task.Domain)
	return nil
}

// SelectAgent 选择一个在线 Agent
func (d *TaskDispatcher) SelectAgent(capabilities []string) (string, error) {
	agents, err := d.agentSvc.ListOnline()
	if err != nil {
		return "", fmt.Errorf("查询在线 Agent 失败: %w", err)
	}
	if len(agents) == 0 {
		return "", fmt.Errorf("没有在线的 Agent")
	}

	if len(capabilities) > 0 {
		for _, a := range agents {
			if hasCapabilities(a.Capabilities, capabilities) {
				return a.AgentID, nil
			}
		}
		return "", fmt.Errorf("没有满足 capabilities %v 的在线 Agent", capabilities)
	}

	return agents[0].AgentID, nil
}

// RemoveChannel 移除 Agent channel
func (d *TaskDispatcher) RemoveChannel(agentID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if ch, ok := d.channels[agentID]; ok {
		close(ch)
		delete(d.channels, agentID)
	}
}

func (d *TaskDispatcher) getOrCreateChannel(agentID string) chan *agenttask.AgentTask {
	d.mu.RLock()
	ch, ok := d.channels[agentID]
	d.mu.RUnlock()
	if ok {
		return ch
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if ch, ok := d.channels[agentID]; ok {
		return ch
	}
	ch = make(chan *agenttask.AgentTask, channelBufferSize)
	d.channels[agentID] = ch
	return ch
}

func (d *TaskDispatcher) subscribe(domain, taskID string, ch chan *agenttask.TaskReportRequest) {
	key := domain + ":" + taskID
	d.subMu.Lock()
	defer d.subMu.Unlock()
	d.subscribers[key] = append(d.subscribers[key], ch)
}

func (d *TaskDispatcher) unsubscribe(domain, taskID string, ch chan *agenttask.TaskReportRequest) {
	key := domain + ":" + taskID
	d.subMu.Lock()
	defer d.subMu.Unlock()
	subs := d.subscribers[key]
	for i, sub := range subs {
		if sub == ch {
			d.subscribers[key] = append(subs[:i], subs[i+1:]...)
			break
		}
	}
	if len(d.subscribers[key]) == 0 {
		delete(d.subscribers, key)
	}
}

func (d *TaskDispatcher) notifySubscribers(domain string, report *agenttask.TaskReportRequest) {
	key := domain + ":" + report.TaskID
	d.subMu.RLock()
	subs := d.subscribers[key]
	d.subMu.RUnlock()

	for _, ch := range subs {
		select {
		case ch <- report:
		default:
		}
	}
}

func hasCapabilities(agentCaps, required []string) bool {
	capSet := make(map[string]struct{}, len(agentCaps))
	for _, c := range agentCaps {
		capSet[c] = struct{}{}
	}
	for _, r := range required {
		if _, ok := capSet[r]; !ok {
			return false
		}
	}
	return true
}

// SelectAgentForChallenge 选择负责 HTTP challenge 的 Agent
// 从指定 zone 中选择具有 http_challenge capability 的 Agent
func (d *TaskDispatcher) SelectAgentForChallenge(zone string) (string, error) {
	if zone == "" {
		return d.SelectAgent([]string{"http_challenge"})
	}

	agents, err := d.agentSvc.ListOnlineByZone(zone)
	if err != nil {
		return "", fmt.Errorf("查询 zone=%s 在线 Agent 失败: %w", zone, err)
	}

	for _, a := range agents {
		if hasCapabilities(a.Capabilities, []string{"http_challenge"}) {
			return a.AgentID, nil
		}
	}

	return "", fmt.Errorf("zone=%s 中没有具备 http_challenge 能力的在线 Agent", zone)
}

// ListAgentsForSync 获取需要同步证书的所有 Agent
// syncZones 为空时返回所有在线 Agent，否则返回指定 zones 的 Agent
func (d *TaskDispatcher) ListAgentsForSync(syncZones []string) ([]*agent.Agent, error) {
	if len(syncZones) == 0 {
		return d.agentSvc.ListOnline()
	}
	return d.agentSvc.ListOnlineByZones(syncZones)
}

// BroadcastResult 广播任务的单个结果
type BroadcastResult struct {
	AgentID string
	Report  *agenttask.TaskReportRequest
	Err     error
}

// BroadcastAndWait 广播任务到多个 Agent 并等待所有结果
func (d *TaskDispatcher) BroadcastAndWait(taskTemplate *agenttask.AgentTask, agentIDs []string, timeout time.Duration) []BroadcastResult {
	results := make([]BroadcastResult, len(agentIDs))
	var wg sync.WaitGroup

	for i, agentID := range agentIDs {
		wg.Add(1)
		go func(idx int, aid string) {
			defer wg.Done()
			// 为每个 Agent 创建独立任务副本
			task := &agenttask.AgentTask{
				ID:      uuid.New().String(),
				AgentID: aid,
				Type:    taskTemplate.Type,
				Domain:  taskTemplate.Domain,
				Payload: taskTemplate.Payload,
			}
			report, err := d.DispatchAndWait(task, timeout)
			results[idx] = BroadcastResult{
				AgentID: aid,
				Report:  report,
				Err:     err,
			}
		}(i, agentID)
	}

	wg.Wait()
	return results
}
