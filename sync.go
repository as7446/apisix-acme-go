package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// SyncMode 同步模式
type SyncMode string

const (
	SyncModeStrict SyncMode = "strict"
	SyncModeCompat SyncMode = "compat"
)

// SyncManager 同步管理器
type SyncManager struct {
	cfg       *Config
	store     *StormCertStore
	apisix    *ApisixClient
	certCache *CertCache
}

// NewSyncManager 创建同步管理器
func NewSyncManager(cfg *Config, store *StormCertStore, apisix *ApisixClient, certCache *CertCache) *SyncManager {
	return &SyncManager{
		cfg:       cfg,
		store:     store,
		apisix:    apisix,
		certCache: certCache,
	}
}

// buildManagedLabels 返回本次推送到 APISIX 的 label map（含版本号）
func (m *SyncManager) buildManagedLabels(revision int) map[string]string {
	return map[string]string{
		"managed-by":      m.cfg.ManagedByLabel,
		"x-acme-revision": fmt.Sprintf("%d", revision),
	}
}

// needRenew 判断证书是否进入续期窗口（notAfter - now <= renewWindow）
func (m *SyncManager) needRenew(cert *Certificate) bool {
	now := time.Now().Unix()
	renewWindow := int64(m.cfg.RenewBeforeDays * 24 * 3600)
	return cert.NotAfter-now <= renewWindow
}

// Sync 执行全量同步（三阶段：build map → per-cert reconcile → 孤儿处理）
func (m *SyncManager) Sync() error {
	_, firstSyncDone := m.store.GetLastSyncTime()
	now := time.Now().Unix()

	// ── 获取 APISIX 证书全量列表 ──────────────────────────────────────────
	allAPISIXSSLs, err := m.apisix.ListSSLs()
	if err != nil {
		return fmt.Errorf("获取 APISIX 证书列表失败：%w", err)
	}

	// 只保留本服务负责的 SSL，并建立 SNI→ID 反向索引
	managedSSLs := make(map[string]*ApisixSSLObject) // key = ssl.ID (normalized)
	sniToID := make(map[string]string)               // sni → ssl.ID（辅助索引）
	for id, ssl := range allAPISIXSSLs {
		if m.apisix.IsManagedByUs(ssl, m.cfg.ManagedByLabel) {
			managedSSLs[id] = ssl
			for _, sni := range ssl.SNIs {
				sniToID[sni] = id
			}
		}
	}

	// ── 首次同步：选择性导入 ───────────────────────────────────────────────
	if !firstSyncDone {
		if err := m.firstSync(allAPISIXSSLs); err != nil {
			return fmt.Errorf("首次同步失败：%w", err)
		}
		if err := m.store.SetLastSyncTime(now, true); err != nil {
			return fmt.Errorf("更新同步状态失败：%w", err)
		}
		Log.Info("首次同步完成", "total_apisix", len(allAPISIXSSLs), "managed", len(managedSSLs))
		return nil
	}

	// ── 获取本地全量记录（含 Deleting 状态的软删除记录） ──────────────────
	localCerts, err := m.store.All()
	if err != nil {
		return fmt.Errorf("获取本地证书列表失败：%w", err)
	}

	// 构建本地 APISIX-ID → cert 索引（供孤儿处理阶段快速查找）
	localByAPISIXID := make(map[string]*Certificate)
	for _, cert := range localCerts {
		if cert.APISIXID != "" {
			localByAPISIXID[cert.APISIXID] = cert
		}
	}

	// ── Phase 2：per-cert reconcile ──────────────────────────────────────
	stats := struct{ updated, restored, syncFailed, skipped, warned int }{}

	for _, localCert := range localCerts {
		result := m.reconcileCert(localCert, managedSSLs, allAPISIXSSLs)
		switch result {
		case "updated", "restored":
			stats.updated++
		case "sync_failed":
			stats.syncFailed++
		case "skipped":
			stats.skipped++
		case "warned":
			stats.warned++
		}
	}

	// ── Phase 3：APISIX → DB（处理孤儿 / 待删除） ─────────────────────────
	deletedCount := 0
	importedCount := 0
	orphanCount := 0

	for id, apisixSSL := range managedSSLs {
		// 先用 APISIX ID 直接查（最快）
		localCert, foundLocal := localByAPISIXID[id]
		if !foundLocal {
			// 兜底：从 SNI 列表查 DB
			if c, ok := m.store.GetByAPISIXID(id); ok {
				localCert = c
				foundLocal = true
			}
		}
		if !foundLocal {
			for _, sni := range apisixSSL.SNIs {
				if c, ok := m.store.GetWithDeleted(sni); ok {
					localCert = c
					foundLocal = true
					break
				}
			}
		}

		if foundLocal {
			status := localCert.effectiveStatus()
			if status != CertStatusDeleting {
				// Phase 2 已处理，跳过
				continue
			}
			// 待删除：执行 APISIX 侧删除
			// 边界场景：用户主动删除了 DB 记录但 APISIX 侧还存在
			Log.Info("执行 APISIX 侧证书删除", "id", id, "domain", localCert.Domain)
			if err := m.apisix.DeleteCertificate(id); err != nil {
				Log.Error("删除 APISIX 证书失败", "id", id, "error", err)
			} else {
				deletedCount++
				_ = m.store.UpdateCertSyncState(localCert.Domain, CertStatusDeleting, "apisix cert deleted")
			}
			continue
		}

		// DB 中无记录——孤儿证书处理
		// 边界场景：DB 数据丢失 / 多实例同时管理
		switch SyncMode(m.cfg.SyncMode) {
		case SyncModeStrict:
			// 严格模式：仅告警，不立即删除（避免误删人工维护的备份证书）
			Log.Warn("检测到孤儿证书（DB 无记录），严格模式下暂不删除",
				"apisix_id", id, "snis", apisixSSL.SNIs)
			orphanCount++
		default: // compat
			// 兼容模式：导入为 external，通过 SNI[0] 作为域名
			domain := id
			if len(apisixSSL.SNIs) > 0 {
				d := apisixSSL.SNIs[0]
				if strings.HasPrefix(d, "wildcard.") {
					d = strings.Replace(d, "wildcard.", "*.", 1)
				}
				domain = d
			}
			Log.Info("兼容模式：导入孤儿证书", "domain", domain)
			if err := m.importFromAPISIX(domain, apisixSSL, CertSourceExternal); err != nil {
				Log.Error("导入孤儿证书失败", "domain", domain, "error", err)
			} else {
				importedCount++
			}
		}
	}

	// 更新全局同步时间（监控指标用）
	if err := m.store.SetLastSyncTime(now, true); err != nil {
		return fmt.Errorf("更新同步状态失败：%w", err)
	}

	Log.Info("证书同步完成",
		"apisix_total", len(allAPISIXSSLs),
		"apisix_managed", len(managedSSLs),
		"db_certs", len(localCerts),
		"updated", stats.updated,
		"sync_failed", stats.syncFailed,
		"skipped", stats.skipped,
		"warned", stats.warned,
		"deleted", deletedCount,
		"imported", importedCount,
		"orphan_warned", orphanCount,
	)
	return nil
}

// reconcileCert 对单个证书执行状态机转换和 reconcile 操作。
// 这是核心 reconcile 单元，可被 Sync() 批量调用，也可被事件触发的单证书 reconcile 调用。
// 返回值描述本次操作结果：updated / restored / sync_failed / skipped / warned / ""
func (m *SyncManager) reconcileCert(
	localCert *Certificate,
	managedSSLs map[string]*ApisixSSLObject,
	allSSLs map[string]*ApisixSSLObject,
) string {

	status := localCert.effectiveStatus()
	domain := localCert.Domain

	// ── 状态机处理 ────────────────────────────────────────────────────────

	// Deleting：交给 Phase 3 处理，此处跳过
	if status == CertStatusDeleting {
		return "skipped"
	}

	// Renewing：检查锁是否超时（1 小时），超时则重置为 SyncFailed 以便重试
	// 边界场景：ACME 申请过程中进程崩溃，Renewing 锁永远不释放
	if status == CertStatusRenewing {
		lockTimeout := int64(3600)
		if time.Now().Unix()-localCert.UpdatedAt > lockTimeout {
			Log.Warn("续期锁超时，重置为 sync_failed 以便下次重试", "domain", domain,
				"locked_at", localCert.UpdatedAt)
			_ = m.store.UpdateCertSyncState(domain, CertStatusSyncFailed, "renewing lock timeout")
			_ = m.store.SetRenewing(domain, false, "")
			status = CertStatusSyncFailed
		} else {
			Log.Debug("证书正在续期中，跳过本轮 reconcile", "domain", domain)
			return "skipped"
		}
	}

	// ── 查找 APISIX 侧对应记录 ────────────────────────────────────────────
	apisixKey := localCert.APISIXID
	if apisixKey == "" {
		apisixKey = normalizeAPISIXID(domain)
	}
	apisixSSL, existsInAPISIX := managedSSLs[apisixKey]
	if !existsInAPISIX {
		// 兼容旧数据：在完整列表中查一次（无 label 的旧 SSL）
		if ssl, ok := allSSLs[domain]; ok && m.apisix.IsManagedByUs(ssl, m.cfg.ManagedByLabel) {
			apisixSSL = ssl
			existsInAPISIX = true
		}
	}

	// ── Case A：APISIX 不存在该证书 ─────────────────────────────────────
	if !existsInAPISIX {
		switch status {
		case CertStatusIssued, CertStatusPending, CertStatusSyncFailed:
			// 边界场景：APISIX 侧证书被手动删除 → 幂等恢复，不触发新签发
			Log.Info("APISIX 侧证书不存在，尝试恢复", "domain", domain, "status", status)
			if err := m.pushToAPISIX(localCert); err != nil {
				Log.Error("恢复证书到 APISIX 失败", "domain", domain, "error", err)
				_ = m.store.UpdateCertSyncState(domain, CertStatusSyncFailed, err.Error())
				return "sync_failed"
			}
			_ = m.store.UpdateCertSyncState(domain, CertStatusIssued, "")
			return "restored"
		}
		return "skipped"
	}

	// ── Case B：APISIX 存在，比较指纹 ─────────────────────────────────────
	apisixFingerprint, err := CalculateFingerprint(apisixSSL.Cert)
	if err != nil {
		Log.Error("计算 APISIX 证书指纹失败", "domain", domain, "error", err)
		return "sync_failed"
	}

	if localCert.Fingerprint == apisixFingerprint {
		// 指纹一致：仅更新同步时间，检查是否需要续期
		_ = m.store.UpdateCertSyncState(domain, CertStatusIssued, "")

		// 续期判断（needRenew = notAfter - now <= renewWindow）
		if m.needRenew(localCert) {
			m.handleRenew(localCert)
		}
		return ""
	}

	// ── Case C：指纹不一致，冲突解决 ─────────────────────────────────────
	// 优先使用 revision 比较（更精确），若 revision 相同则回退到 UpdatedAt vs UpdateTime
	apisixRevision := m.apisix.GetRevisionFromSSL(apisixSSL)

	var resolveToLocal bool
	if localCert.Revision != 0 && apisixRevision != 0 {
		// 有明确版本：revision 决定胜负
		resolveToLocal = localCert.Revision > apisixRevision
		Log.Info("证书冲突：按 revision 决策",
			"domain", domain,
			"local_revision", localCert.Revision,
			"apisix_revision", apisixRevision,
			"resolve_to_local", resolveToLocal)
	} else {
		// 版本信息缺失（旧记录兼容）：回退到时间戳比较
		resolveToLocal = localCert.UpdatedAt > apisixSSL.UpdateTime
		Log.Info("证书冲突：revision 缺失，按 update_time 决策",
			"domain", domain,
			"local_updated_at", localCert.UpdatedAt,
			"apisix_update_time", apisixSSL.UpdateTime,
			"resolve_to_local", resolveToLocal)
	}

	if resolveToLocal {
		// 本地版本更新 → 推送到 APISIX
		if SyncMode(m.cfg.SyncMode) == SyncModeStrict && localCert.Source == CertSourceExternal {
			// 严格模式下 external 证书不覆盖 APISIX（只读不写）
			Log.Warn("严格模式：external 证书冲突，跳过推送", "domain", domain)
			return "warned"
		}
		if err := m.pushToAPISIX(localCert); err != nil {
			Log.Error("推送证书到 APISIX 失败", "domain", domain, "error", err)
			_ = m.store.UpdateCertSyncState(domain, CertStatusSyncFailed, err.Error())
			return "sync_failed"
		}
		_ = m.store.UpdateCertSyncState(domain, CertStatusIssued, "")
		return "updated"
	}

	// APISIX 版本更新 → 拉取到本地
	// 严格模式：仅告警，不盲目覆盖本地数据
	if SyncMode(m.cfg.SyncMode) == SyncModeStrict {
		Log.Warn("严格模式：APISIX 版本较新，记录冲突但不自动覆盖本地",
			"domain", domain, "local_revision", localCert.Revision, "apisix_revision", apisixRevision)
		_ = m.store.UpdateCertSyncState(domain, CertStatusSyncFailed, "conflict: apisix is newer, strict mode skipped pull")
		return "warned"
	}
	// 兼容模式：从 APISIX 拉取
	if err := m.importFromAPISIX(domain, apisixSSL, localCert.Source); err != nil {
		Log.Error("从 APISIX 拉取证书失败", "domain", domain, "error", err)
		_ = m.store.UpdateCertSyncState(domain, CertStatusSyncFailed, err.Error())
		return "sync_failed"
	}
	return "updated"
}

// handleRenew 处理单张证书的续期逻辑（被 reconcileCert 调用）
func (m *SyncManager) handleRenew(cert *Certificate) {
	domain := cert.Domain

	// external 证书：尝试 ACME 续期（兼容模式）或告警（严格 / 不可签发）
	if cert.Source == CertSourceExternal {
		if SyncMode(m.cfg.SyncMode) == SyncModeCompat {
			Log.Info("外部证书即将到期，尝试 ACME 自动续期", "domain", domain,
				"not_after", time.Unix(cert.NotAfter, 0).Format("2006-01-02"))
			// 实际续期走 acme.RenewAll / RequestCertificate，此处只标记 pending
			// 以触发下次 reconcile 时 pushToAPISIX
			_ = m.store.UpdateCertSyncState(domain, CertStatusPending, "external cert approaching expiry, queued for renewal")
		} else {
			// 严格模式：只告警，不写操作
			Log.Warn("外部证书即将到期但严格模式下无法自动续期，请手动处理",
				"domain", domain,
				"not_after", time.Unix(cert.NotAfter, 0).Format("2006-01-02"))
		}
		return
	}

	// managed 证书：标记状态，等待 acme.RenewAll 触发实际续期
	// 避免在 sync goroutine 内执行 ACME（避免超时、阻塞全局 sync）
	if !cert.Renewing {
		Log.Info("证书进入续期窗口，标记待续期", "domain", domain,
			"not_after", time.Unix(cert.NotAfter, 0).Format("2006-01-02"))
		// 不直接调用 ACME，由 cron renew 任务负责（分离关注点）
	}
}

// firstSync 首次同步：选择性导入 APISIX 证书
//   - 有 managed-by label → source=managed
//   - 无 label 但 SNI 匹配 cfg.SNIPattern → source=external
//   - 其余跳过
func (m *SyncManager) firstSync(allSSLs map[string]*ApisixSSLObject) error {
	managedCount, externalCount, skippedCount := 0, 0, 0

	for id, ssl := range allSSLs {
		domain := id
		if len(ssl.SNIs) > 0 {
			d := ssl.SNIs[0]
			if strings.HasPrefix(d, "wildcard.") {
				d = strings.Replace(d, "wildcard.", "*.", 1)
			}
			domain = d
		}

		if m.apisix.IsManagedByUs(ssl, m.cfg.ManagedByLabel) {
			if err := m.importFromAPISIX(domain, ssl, CertSourceManaged); err != nil {
				Log.Error("首次同步：导入 managed 证书失败", "domain", domain, "error", err)
				continue
			}
			managedCount++
		} else if m.cfg.SNIPattern != "" && matchSNIPattern(ssl.SNIs, m.cfg.SNIPattern) {
			if err := m.importFromAPISIX(domain, ssl, CertSourceExternal); err != nil {
				Log.Error("首次同步：导入 external 证书失败", "domain", domain, "error", err)
				continue
			}
			externalCount++
		} else {
			Log.Debug("首次同步：跳过非托管证书", "domain", domain, "snis", ssl.SNIs)
			skippedCount++
		}
	}

	Log.Info("首次同步导入完成", "managed", managedCount, "external", externalCount, "skipped", skippedCount)
	return nil
}

// matchSNIPattern 判断 SNI 列表中是否有任意一个匹配给定的 glob 模式
func matchSNIPattern(snis []string, pattern string) bool {
	for _, sni := range snis {
		if matched, _ := filepath.Match(pattern, sni); matched {
			return true
		}
	}
	return false
}

// importFromAPISIX 将 APISIX 证书记录导入本地 DB 和文件缓存
func (m *SyncManager) importFromAPISIX(domain string, apisixSSL *ApisixSSLObject, source CertSource) error {
	block, _ := pem.Decode([]byte(apisixSSL.Cert))
	if block == nil {
		return fmt.Errorf("解析 APISIX 证书 PEM 失败")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("解析证书失败：%w", err)
	}

	fingerprint, _ := CalculateFingerprint(apisixSSL.Cert)
	serialNumber, _ := CalculateSerialNumber(apisixSSL.Cert)

	now := time.Now().Unix()
	apisixID := apisixSSL.ID
	if apisixID == "" {
		apisixID = normalizeAPISIXID(domain)
	}

	// 保留现有记录的 Revision（导入不计为本地写操作）
	existingRevision := 0
	if existing, ok := m.store.GetByAPISIXID(apisixID); ok {
		existingRevision = existing.Revision
	}

	localCert := &Certificate{
		Domain:       domain,
		SNIs:         apisixSSL.SNIs,
		NotBefore:    cert.NotBefore.Unix(),
		NotAfter:     cert.NotAfter.Unix(),
		APISIXID:     apisixID,
		Fingerprint:  fingerprint,
		SerialNumber: serialNumber,
		CreatedAt:    now,
		UpdatedAt:    now,
		Deleted:      false,
		Status:       CertStatusIssued,
		Source:       source,
		LastSyncedAt: now,
		Revision:     existingRevision, // Upsert 会自动 +1
	}

	if err := m.store.Upsert(localCert); err != nil {
		return fmt.Errorf("保存证书到本地失败：%w", err)
	}

	// 同步写入文件缓存（key 文件可能为空时记录日志即可）
	if apisixSSL.Key != "" {
		if err := m.certCache.Put(domain, apisixSSL.Cert, apisixSSL.Key, cert.NotBefore.Unix(), cert.NotAfter.Unix()); err != nil {
			Log.Error("保存证书到文件缓存失败", "domain", domain, "error", err)
		}
	}

	return nil
}

// pushToAPISIX 将本地证书推送到 APISIX（优先用文件缓存，携带 revision label）
// 边界场景：缓存不存在（DB 有记录但文件被删除）→ 返回明确错误，由 acme.RenewAll 重新签发
func (m *SyncManager) pushToAPISIX(localCert *Certificate) error {
	domain := localCert.Domain
	snis := localCert.SNIs
	if len(snis) == 0 {
		snis = []string{domain}
	}

	cached, ok := m.certCache.Get(domain)
	if !ok {
		// 边界场景：文件缓存丢失，本地证书无法推送
		// 不触发 ACME（避免 sync 中隐式长时间阻塞），标记让 renew 任务处理
		return fmt.Errorf("文件缓存不存在（domain=%s），已标记 pending 等待 renew 任务重新签发", domain)
	}

	labels := m.buildManagedLabels(localCert.Revision)
	if err := m.apisix.UpsertCertificate(domain, snis, cached.CertPEM, cached.KeyPEM, cached.NotAfter, labels); err != nil {
		return fmt.Errorf("上传证书到 APISIX 失败：%w", err)
	}

	Log.Info("证书已推送到 APISIX", "domain", domain, "snis", snis, "revision", localCert.Revision)
	return nil
}
