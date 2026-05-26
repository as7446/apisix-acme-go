package controller

import (
	"fmt"
	"time"

	"github.com/as7446/apisix-acme-go/internal/controller/dispatch"
	"github.com/as7446/apisix-acme-go/internal/domain/agent"
	"github.com/as7446/apisix-acme-go/internal/domain/agenttask"
	"github.com/as7446/apisix-acme-go/internal/domain/cert"
	"github.com/as7446/apisix-acme-go/internal/infra/config"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
	"github.com/as7446/apisix-acme-go/internal/infra/metrics"
	"github.com/as7446/apisix-acme-go/internal/infra/statestore"
)

// DriftDetector 漂移检测器
// 对比 DB 期望状态与 Agent 上报的实际状态，发现不一致时派发 sync_cert 任务
// 支持多 Zone：只检查 cert 的 SyncZones 中的 Agent，精确广播修复
type DriftDetector struct {
	certRepo   cert.CertRepository
	certCache  cert.CertCache
	stateStore *statestore.RedisAgentStateStore
	dispatcher *dispatch.TaskDispatcher
	cfg        *config.Config
}

// NewDriftDetector 创建漂移检测器
func NewDriftDetector(
	certRepo cert.CertRepository,
	certCache cert.CertCache,
	stateStore *statestore.RedisAgentStateStore,
	dispatcher *dispatch.TaskDispatcher,
	cfg *config.Config,
) *DriftDetector {
	return &DriftDetector{
		certRepo:   certRepo,
		certCache:  certCache,
		stateStore: stateStore,
		dispatcher: dispatcher,
		cfg:        cfg,
	}
}

// Detect 执行一次漂移检测（多 Zone 感知）
func (d *DriftDetector) Detect() error {
	// 1. 获取每个 Agent 的 SSL 状态（按 Agent 维度）
	agentStates, err := d.stateStore.GetAllSSLStateByAgent()
	if err != nil {
		return fmt.Errorf("获取 Agent SSL 状态失败: %w", err)
	}

	// 2. 获取 DB 中所有活跃证书
	allCerts, err := d.certRepo.All()
	if err != nil {
		return fmt.Errorf("获取证书列表失败: %w", err)
	}

	// 3. 获取需要同步的 Agent 列表
	driftCount := 0
	for _, c := range allCerts {
		// 跳过非 managed、已删除、正在签发中的证书
		if c.Source != cert.CertSourceManaged {
			continue
		}
		if c.Deleted {
			continue
		}
		if c.IssueStatus != cert.IssueIdle {
			continue
		}
		// syncing 表示已有修复任务在执行；drifted/failed 仍允许下一轮重试修复。
		if c.SyncStatus == cert.SyncSyncing {
			continue
		}
		if c.Fingerprint == "" {
			continue
		}

		// 获取该 cert 需要同步的 Agent 列表
		syncAgents, err := d.dispatcher.ListAgentsForSync(c.SyncZones)
		if err != nil {
			logger.Log.Error("获取 sync Agent 列表失败", "domain", c.Domain, "error", err)
			continue
		}
		if len(syncAgents) == 0 {
			continue
		}

		// 检查每个 Agent 的指纹，收集漂移的 Agent
		driftedAgentIDs := d.findDriftedAgents(c, syncAgents, agentStates)
		if len(driftedAgentIDs) > 0 {
			driftCount++
			metrics.CertDriftDetectedTotal.Add(1)
			d.handleDrift(c, driftedAgentIDs)
		}
	}

	if driftCount > 0 {
		logger.Log.Info("漂移检测完成", "drift_count", driftCount)
	}
	return nil
}

// findDriftedAgents 找出指纹不匹配的 Agent
func (d *DriftDetector) findDriftedAgents(c *cert.Certificate, syncAgents []*agent.Agent, agentStates map[string]map[string]string) []string {
	expectedFingerprint := "sha256:" + c.Fingerprint
	var drifted []string

	for _, a := range syncAgents {
		agentState, hasState := agentStates[a.AgentID]
		if !hasState {
			// Agent 没有上报任何状态 → 视为漂移
			drifted = append(drifted, a.AgentID)
			continue
		}

		fingerprint, hasDomain := agentState[c.Domain]
		if !hasDomain || fingerprint != expectedFingerprint {
			drifted = append(drifted, a.AgentID)
		}
	}

	return drifted
}

// handleDrift 处理漂移的证书：广播 sync_cert 到漂移的 Agent
func (d *DriftDetector) handleDrift(c *cert.Certificate, driftedAgentIDs []string) {
	// 更新状态为 syncing，避免下一轮漂移检测重复派发相同修复任务。
	_ = d.certRepo.UpdateCertSyncState(c.Domain, cert.SyncSyncing, fmt.Sprintf("drift detected on %d agents", len(driftedAgentIDs)))

	// 获取证书内容
	cached, hasCache := d.certCache.Get(c.Domain)
	if !hasCache {
		logger.Log.Warn("漂移检测：证书缓存不存在，跳过派发", "domain", c.Domain)
		_ = d.certRepo.UpdateCertSyncState(c.Domain, cert.SyncFailed, "certificate cache missing during drift repair")
		return
	}

	labels := map[string]string{
		"managed-by":      d.cfg.ManagedByLabel,
		"x-acme-revision": fmt.Sprintf("%d", c.Revision),
	}

	syncTaskTemplate := &agenttask.AgentTask{
		Type:   agenttask.TaskSyncCert,
		Domain: c.Domain,
		Payload: map[string]interface{}{
			"apisix_id":  c.APISIXID,
			"cert_pem":   cached.CertPEM,
			"key_pem":    cached.KeyPEM,
			"snis":       []string{c.Domain},
			"expires_at": c.NotAfter,
			"labels":     labels,
		},
	}

	taskTimeout := time.Duration(d.cfg.AgentTaskTimeout) * time.Second

	// 异步广播到所有漂移的 Agent
	go func(domain string, agentIDs []string) {
		results := d.dispatcher.BroadcastAndWait(syncTaskTemplate, agentIDs, taskTimeout)

		var failCount int
		for _, r := range results {
			if r.Err != nil {
				failCount++
				logger.Log.Error("漂移修复失败", "domain", domain, "agent_id", r.AgentID, "error", r.Err)
			} else if r.Report != nil && r.Report.Status != agenttask.StatusSuccess {
				failCount++
				logger.Log.Error("漂移修复 Agent 执行失败", "domain", domain, "agent_id", r.AgentID, "error", r.Report.ErrorMessage)
			}
		}

		if failCount > 0 {
			metrics.CertDriftRepairFailure.Add(1)
			msg := fmt.Sprintf("drift repair partial fail: %d/%d agents", failCount, len(agentIDs))
			_ = d.certRepo.UpdateCertSyncState(domain, cert.SyncFailed, msg)
		} else {
			metrics.CertDriftRepairTotal.Add(1)
			_ = d.certRepo.UpdateCertSyncState(domain, cert.SyncSynced, "")
			logger.Log.Info("漂移修复成功", "domain", domain, "agents", len(agentIDs))
		}
	}(c.Domain, driftedAgentIDs)
}
