package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/as7446/apisix-acme-go/internal/application"
	"github.com/as7446/apisix-acme-go/internal/controller/dispatch"
	"github.com/as7446/apisix-acme-go/internal/controller/worker"
	"github.com/as7446/apisix-acme-go/internal/domain/agenttask"
	"github.com/as7446/apisix-acme-go/internal/domain/cert"
	"github.com/as7446/apisix-acme-go/internal/infra/config"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
	"github.com/as7446/apisix-acme-go/internal/infra/queue"
)

// IssuerFSM 基于 FSM 的签发控制器
// 流程：
//  1. inject_challenge → Agent 创建验证路由
//  2. ACME 签发证书
//  3. remove_challenge → Agent 删除验证路由
//  4. sync_cert → Agent 推送证书到网关
type IssuerFSM struct {
	issueQueue     queue.Queue
	dispatcher     *dispatch.TaskDispatcher
	issuer         *application.Issuer
	certRepo       cert.CertRepository
	certCache      cert.CertCache
	storage        cert.CertStorage
	cfg            *config.Config
	pool           *worker.Pool
	retryScheduler *RetryScheduler
}

// NewIssuerFSM 创建 FSM 签发控制器
func NewIssuerFSM(
	issueQueue queue.Queue,
	dispatcher *dispatch.TaskDispatcher,
	issuer *application.Issuer,
	certRepo cert.CertRepository,
	certCache cert.CertCache,
	storage cert.CertStorage,
	cfg *config.Config,
	retryScheduler *RetryScheduler,
) *IssuerFSM {
	return &IssuerFSM{
		issueQueue:     issueQueue,
		dispatcher:     dispatcher,
		issuer:         issuer,
		certRepo:       certRepo,
		certCache:      certCache,
		storage:        storage,
		cfg:            cfg,
		retryScheduler: retryScheduler,
	}
}

// Start 启动 FSM worker pool
func (f *IssuerFSM) Start(ctx context.Context) {
	f.pool = worker.NewPool("issuer-fsm", f.issueQueue, f.handleTask, f.cfg.IssueWorkers, f.cfg.WorkerDequeueTimeout)
	f.pool.Start(ctx)
}

// Stop 停止
func (f *IssuerFSM) Stop() {
	if f.pool != nil {
		f.pool.Stop()
	}
}

// RecoverFromDB 恢复被中断的 FSM 任务
func (f *IssuerFSM) RecoverFromDB(ctx context.Context) error {
	// 找到 FSM 中间状态的证书，重新入队
	statuses := []cert.IssueStatus{
		cert.IssuePending,
		cert.IssueChallengeInjecting,
		cert.IssueChallengeReady,
		cert.IssueAcmeVerifying,
		cert.IssueIssued,
		cert.IssueSyncDispatched,
	}
	certs, err := f.certRepo.FindByIssueStatus(statuses)
	if err != nil {
		return fmt.Errorf("恢复扫描 FSM 状态失败：%w", err)
	}

	for _, cc := range certs {
		if time.Now().Unix()-cc.UpdatedAt < int64(f.cfg.AgentTaskTimeout) {
			logger.Log.Debug("FSM 恢复跳过未超时任务", "domain", cc.Domain, "status", cc.IssueStatus)
			continue
		}
		// 重置为 pending 并入队
		_ = f.certRepo.UpdateIssueStatus(cc.Domain, cert.IssuePending)
		if err := f.enqueueIssueTask(cc.Domain, "issue"); err != nil {
			logger.Log.Error("FSM 恢复入队失败", "domain", cc.Domain, "error", err)
		}
	}

	if len(certs) > 0 {
		logger.Log.Info("IssuerFSM 恢复完成", "count", len(certs))
	}

	return nil
}

// handleTask FSM 主流程
func (f *IssuerFSM) handleTask(ctx context.Context, task *queue.Task) error {
	domain := task.Domain
	if domain == "" {
		return fmt.Errorf("task domain 为空")
	}

	// 原子领取签发任务，避免多个 worker 同时处理同一域名。
	claimed, err := f.certRepo.ClaimIssue(domain)
	if err != nil {
		return err
	}
	if !claimed {
		logger.Log.Debug("证书签发任务已被其他 worker 领取或状态无需处理，跳过", "domain", domain)
		return nil
	}

	// 获取证书元数据（ChallengeZone / SyncZones）
	localCert, ok := f.certRepo.Get(domain)
	if !ok {
		return fmt.Errorf("证书元数据不存在：%s", domain)
	}

	action := "issue"
	if v, ok := task.Payload["action"]; ok {
		if s, ok := v.(string); ok {
			action = s
		}
	}

	if action == "issue" {
		if localCert.NotAfter > time.Now().Unix() {
			logger.Log.Info("证书已签发且未过期，跳过重复 issue 任务", "domain", domain, "not_after", localCert.NotAfter)
			_ = f.certRepo.ClearRetryState(domain)
			_ = f.certRepo.UpdateIssueStatus(domain, cert.IssueIdle)
			return nil
		}
	}

	taskTimeout := time.Duration(f.cfg.AgentTaskTimeout) * time.Second

	// === Phase 1: inject_challenge ===
	if f.cfg.ChallengeRoute.Enable {
		_ = f.certRepo.UpdateIssueStatus(domain, cert.IssueChallengeInjecting)

		// 选择 ChallengeZone 中具备 http_challenge 能力的 Agent
		challengeAgentID, err := f.dispatcher.SelectAgentForChallenge(localCert.ChallengeZone)
		if err != nil {
			handleRetryState(f.certRepo, f.cfg, f.retryScheduler, domain, fmt.Errorf("选择 challenge Agent 失败 (zone=%s)：%w", localCert.ChallengeZone, err))
			return nil
		}

		injectTask := &agenttask.AgentTask{
			AgentID: challengeAgentID,
			Type:    agenttask.TaskInjectChallenge,
			Domain:  domain,
			Payload: map[string]interface{}{
				"route_name":      f.cfg.ChallengeRoute.RouteName,
				"upstream_nodes":  f.cfg.ChallengeRoute.UpstreamNodes,
				"upstream_scheme": f.cfg.ChallengeRoute.UpstreamScheme,
			},
		}

		injectReport, err := f.dispatcher.DispatchAndWait(injectTask, taskTimeout)
		if err != nil {
			handleRetryState(f.certRepo, f.cfg, f.retryScheduler, domain, fmt.Errorf("inject_challenge 失败：%w", err))
			return nil
		}
		if injectReport.Status != agenttask.StatusSuccess {
			handleRetryState(f.certRepo, f.cfg, f.retryScheduler, domain, fmt.Errorf("inject_challenge Agent 执行失败：%s", injectReport.ErrorMessage))
			return nil
		}

		_ = f.certRepo.UpdateIssueStatus(domain, cert.IssueChallengeReady)

		// 保存 route_id 用于后续清理
		var routeID string
		if injectReport.Result != nil {
			if rid, ok := injectReport.Result["route_id"].(string); ok {
				routeID = rid
			}
		}

		// defer 清理 challenge route（使用同一个 Agent）
		defer func() {
			if routeID == "" {
				return
			}
			removeTask := &agenttask.AgentTask{
				AgentID: challengeAgentID,
				Type:    agenttask.TaskRemoveChallenge,
				Domain:  domain,
				Payload: map[string]interface{}{
					"route_id": routeID,
				},
			}
			if _, err := f.dispatcher.DispatchAndWait(removeTask, taskTimeout); err != nil {
				logger.Log.Error("remove_challenge 失败", "domain", domain, "error", err)
			}
		}()
	}

	// === Phase 2: ACME 签发 ===
	_ = f.certRepo.UpdateIssueStatus(domain, cert.IssueAcmeVerifying)

	var issueErr error
	switch action {
	case "renew":
		issueErr = f.issuer.Renew(domain)
	default:
		issueErr = f.issuer.Issue(domain)
	}

	if issueErr != nil {
		handleRetryState(f.certRepo, f.cfg, f.retryScheduler, domain, fmt.Errorf("ACME 签发失败：%w", issueErr))
		return nil
	}

	_ = f.certRepo.ClearRetryState(domain)
	_ = f.certRepo.UpdateIssueStatus(domain, cert.IssueIssued)

	// === Phase 3: sync_cert → 广播到所有目标 Zone 的 Agent ===
	_ = f.certRepo.UpdateIssueStatus(domain, cert.IssueSyncDispatched)

	// 获取签发后的证书内容
	cached, hasCache := f.certCache.Get(domain)
	if !hasCache {
		handleRetryState(f.certRepo, f.cfg, f.retryScheduler, domain, fmt.Errorf("签发后无法获取证书缓存：%s", domain))
		return nil
	}

	// 重新获取最新的证书元数据（签发后 Revision 可能已更新）
	localCert, ok = f.certRepo.Get(domain)
	if !ok {
		handleRetryState(f.certRepo, f.cfg, f.retryScheduler, domain, fmt.Errorf("签发后证书元数据不存在：%s", domain))
		return nil
	}

	labels := map[string]string{
		"managed-by":      f.cfg.ManagedByLabel,
		"x-acme-revision": fmt.Sprintf("%d", localCert.Revision),
	}

	syncTaskTemplate := &agenttask.AgentTask{
		Type:   agenttask.TaskSyncCert,
		Domain: domain,
		Payload: map[string]interface{}{
			"apisix_id":  localCert.APISIXID,
			"cert_pem":   cached.CertPEM,
			"key_pem":    cached.KeyPEM,
			"snis":       []string{domain},
			"expires_at": localCert.NotAfter,
			"labels":     labels,
		},
	}

	// 获取所有需要同步的 Agent（根据 SyncZones 过滤）
	syncAgents, err := f.dispatcher.ListAgentsForSync(localCert.SyncZones)
	if err != nil {
		_ = f.certRepo.UpdateCertSyncState(domain, cert.SyncDrifted, err.Error())
		_ = f.certRepo.UpdateIssueStatus(domain, cert.IssueIdle)
		logger.Log.Error("获取 sync Agent 列表失败", "domain", domain, "error", err)
		return nil
	}
	if len(syncAgents) == 0 {
		_ = f.certRepo.UpdateCertSyncState(domain, cert.SyncDrifted, "没有可同步的在线 Agent")
		_ = f.certRepo.UpdateIssueStatus(domain, cert.IssueIdle)
		logger.Log.Warn("没有可同步的在线 Agent", "domain", domain, "sync_zones", localCert.SyncZones)
		return nil
	}

	// 提取 Agent ID 列表
	agentIDs := make([]string, 0, len(syncAgents))
	for _, a := range syncAgents {
		agentIDs = append(agentIDs, a.AgentID)
	}

	// 广播同步到所有目标 Agent
	results := f.dispatcher.BroadcastAndWait(syncTaskTemplate, agentIDs, taskTimeout)

	// 统计广播结果
	var failCount int
	var lastErr string
	for _, r := range results {
		if r.Err != nil {
			failCount++
			lastErr = r.Err.Error()
			logger.Log.Error("sync_cert Agent 超时", "domain", domain, "agent_id", r.AgentID, "error", r.Err)
		} else if r.Report != nil && r.Report.Status != agenttask.StatusSuccess {
			failCount++
			lastErr = r.Report.ErrorMessage
			logger.Log.Error("sync_cert Agent 执行失败", "domain", domain, "agent_id", r.AgentID, "error", r.Report.ErrorMessage)
		}
	}

	if failCount > 0 {
		msg := fmt.Sprintf("广播同步部分失败: %d/%d agents failed, last_error: %s", failCount, len(agentIDs), lastErr)
		_ = f.certRepo.UpdateCertSyncState(domain, cert.SyncDrifted, msg)
		_ = f.certRepo.UpdateIssueStatus(domain, cert.IssueIdle)
		logger.Log.Warn("sync_cert 广播部分失败", "domain", domain, "fail_count", failCount, "total", len(agentIDs))
		return nil
	}

	// 全部成功
	_ = f.certRepo.UpdateCertSyncState(domain, cert.SyncSynced, "")
	_ = f.certRepo.UpdateIssueStatus(domain, cert.IssueIdle)
	logger.Log.Info("FSM 签发流程完成", "domain", domain, "synced_agents", len(agentIDs))

	return nil
}

// enqueueIssueTask 入队签发任务
func (f *IssuerFSM) enqueueIssueTask(domain, action string) error {
	task := &queue.Task{
		ID:        uuid.New().String(),
		Type:      queue.TaskIssue,
		Domain:    domain,
		Priority:  0,
		CreatedAt: time.Now().Unix(),
		Payload:   map[string]interface{}{"action": action},
	}
	return f.issueQueue.Enqueue(task)
}
