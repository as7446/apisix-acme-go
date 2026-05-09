package sync

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/as7446/apisix-acme-go/internal/domain/cert"
	"github.com/as7446/apisix-acme-go/internal/infra/config"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
)

// ApisixClient APISIX 客户端接口（由 acme 包实现）
type ApisixClient interface {
	ListSSLs() (map[string]*cert.ApisixSSLObject, error)
	IsManagedByUs(ssl *cert.ApisixSSLObject, label string) bool
	GetRevisionFromSSL(ssl *cert.ApisixSSLObject) int
	DeleteCertificate(id string) error
	UpsertCertificate(id string, snis []string, certPEM, keyPEM string, expiresAt int64, labels map[string]string) error
}

// Manager 同步管理器
type Manager struct {
	cfg       *config.Config
	certRepo  cert.CertRepository
	syncRepo  cert.SyncStateRepository
	certCache cert.CertCache
	apisix    ApisixClient
}

// NewManager 创建同步管理器
func NewManager(cfg *config.Config, certRepo cert.CertRepository, syncRepo cert.SyncStateRepository, certCache cert.CertCache, apisix ApisixClient) *Manager {
	return &Manager{
		cfg:       cfg,
		certRepo:  certRepo,
		syncRepo:  syncRepo,
		certCache: certCache,
		apisix:    apisix,
	}
}

func (m *Manager) buildManagedLabels(revision int) map[string]string {
	return map[string]string{
		"managed-by":      m.cfg.ManagedByLabel,
		"x-acme-revision": fmt.Sprintf("%d", revision),
	}
}

func (m *Manager) needRenew(c *cert.Certificate) bool {
	now := time.Now().Unix()
	renewWindow := int64(m.cfg.RenewBeforeDays * 24 * 3600)
	return c.NotAfter-now <= renewWindow
}

// Sync 执行全量同步
func (m *Manager) Sync() error {
	_, firstSyncDone := m.syncRepo.GetLastSyncTime()
	now := time.Now().Unix()

	allAPISIXSSLs, err := m.apisix.ListSSLs()
	if err != nil {
		return fmt.Errorf("获取 APISIX 证书列表失败：%w", err)
	}

	managedSSLs := make(map[string]*cert.ApisixSSLObject)
	sniToID := make(map[string]string)
	for id, ssl := range allAPISIXSSLs {
		if m.apisix.IsManagedByUs(ssl, m.cfg.ManagedByLabel) {
			managedSSLs[id] = ssl
			for _, sni := range ssl.SNIs {
				sniToID[sni] = id
			}
		}
	}

	if !firstSyncDone {
		if err := m.firstSync(allAPISIXSSLs); err != nil {
			return fmt.Errorf("首次同步失败：%w", err)
		}
		if err := m.syncRepo.SetLastSyncTime(now, true); err != nil {
			return fmt.Errorf("更新同步状态失败：%w", err)
		}
		logger.Log.Info("首次同步完成", "total_apisix", len(allAPISIXSSLs), "managed", len(managedSSLs))
		return nil
	}

	localCerts, err := m.certRepo.All()
	if err != nil {
		return fmt.Errorf("获取本地证书列表失败：%w", err)
	}

	localByAPISIXID := make(map[string]*cert.Certificate)
	for _, c := range localCerts {
		if c.APISIXID != "" {
			localByAPISIXID[c.APISIXID] = c
		}
	}

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

	deletedCount := 0
	importedCount := 0
	orphanCount := 0

	for id, apisixSSL := range managedSSLs {
		localCert, foundLocal := localByAPISIXID[id]
		if !foundLocal {
			if c, ok := m.certRepo.GetByAPISIXID(id); ok {
				localCert = c
				foundLocal = true
			}
		}
		if !foundLocal {
			for _, sni := range apisixSSL.SNIs {
				if c, ok := m.certRepo.GetWithDeleted(sni); ok {
					localCert = c
					foundLocal = true
					break
				}
			}
		}

		if foundLocal {
			status := localCert.EffectiveStatus()
			if status != cert.CertStatusDeleting {
				continue
			}
			logger.Log.Info("执行 APISIX 侧证书删除", "id", id, "domain", localCert.Domain)
			if err := m.apisix.DeleteCertificate(id); err != nil {
				logger.Log.Error("删除 APISIX 证书失败", "id", id, "error", err)
			} else {
				deletedCount++
				_ = m.certRepo.UpdateCertSyncState(localCert.Domain, cert.CertStatusDeleting, "apisix cert deleted")
			}
			continue
		}

		switch SyncMode(m.cfg.SyncMode) {
		case SyncModeStrict:
			logger.Log.Warn("检测到孤儿证书（DB 无记录），严格模式下暂不删除",
				"apisix_id", id, "snis", apisixSSL.SNIs)
			orphanCount++
		default:
			domain := id
			if len(apisixSSL.SNIs) > 0 {
				d := apisixSSL.SNIs[0]
				if strings.HasPrefix(d, "wildcard.") {
					d = strings.Replace(d, "wildcard.", "*.", 1)
				}
				domain = d
			}
			logger.Log.Info("兼容模式：导入孤儿证书", "domain", domain)
			if err := m.importFromAPISIX(domain, apisixSSL, cert.CertSourceExternal); err != nil {
				logger.Log.Error("导入孤儿证书失败", "domain", domain, "error", err)
			} else {
				importedCount++
			}
		}
	}

	if err := m.syncRepo.SetLastSyncTime(now, true); err != nil {
		return fmt.Errorf("更新同步状态失败：%w", err)
	}

	logger.Log.Info("证书同步完成",
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

func (m *Manager) reconcileCert(localCert *cert.Certificate, managedSSLs map[string]*cert.ApisixSSLObject, allSSLs map[string]*cert.ApisixSSLObject) string {
	status := localCert.EffectiveStatus()
	domain := localCert.Domain

	if status == cert.CertStatusDeleting {
		return "skipped"
	}

	if status == cert.CertStatusRenewing {
		if time.Now().Unix()-localCert.UpdatedAt > config.RenewLockTimeout {
			logger.Log.Warn("续期锁超时，重置为 sync_failed 以便下次重试", "domain", domain,
				"locked_at", localCert.UpdatedAt)
			_ = m.certRepo.UpdateCertSyncState(domain, cert.CertStatusSyncFailed, "renewing lock timeout")
			_ = m.certRepo.SetRenewing(domain, false, "")
			status = cert.CertStatusSyncFailed
		} else {
			logger.Log.Debug("证书正在续期中，跳过本轮 reconcile", "domain", domain)
			return "skipped"
		}
	}

	apisixKey := localCert.APISIXID
	if apisixKey == "" {
		apisixKey = cert.NormalizeAPISIXID(domain)
	}
	apisixSSL, existsInAPISIX := managedSSLs[apisixKey]
	if !existsInAPISIX {
		if ssl, ok := allSSLs[domain]; ok && m.apisix.IsManagedByUs(ssl, m.cfg.ManagedByLabel) {
			apisixSSL = ssl
			existsInAPISIX = true
		}
	}

	if !existsInAPISIX {
		switch status {
		case cert.CertStatusIssued, cert.CertStatusPending, cert.CertStatusSyncFailed:
			logger.Log.Info("APISIX 侧证书不存在，尝试恢复", "domain", domain, "status", status)
			if err := m.pushToAPISIX(localCert); err != nil {
				logger.Log.Error("恢复证书到 APISIX 失败", "domain", domain, "error", err)
				_ = m.certRepo.UpdateCertSyncState(domain, cert.CertStatusSyncFailed, err.Error())
				return "sync_failed"
			}
			_ = m.certRepo.UpdateCertSyncState(domain, cert.CertStatusIssued, "")
			return "restored"
		}
		return "skipped"
	}

	apisixFingerprint, err := cert.CalculateFingerprint(apisixSSL.Cert)
	if err != nil {
		logger.Log.Error("计算 APISIX 证书指纹失败", "domain", domain, "error", err)
		return "sync_failed"
	}

	if localCert.Fingerprint == apisixFingerprint {
		_ = m.certRepo.UpdateCertSyncState(domain, cert.CertStatusIssued, "")
		if m.needRenew(localCert) {
			m.handleRenew(localCert)
		}
		return ""
	}

	apisixRevision := m.apisix.GetRevisionFromSSL(apisixSSL)

	var resolveToLocal bool
	if localCert.Revision != 0 && apisixRevision != 0 {
		resolveToLocal = localCert.Revision > apisixRevision
		logger.Log.Info("证书冲突：按 revision 决策",
			"domain", domain,
			"local_revision", localCert.Revision,
			"apisix_revision", apisixRevision,
			"resolve_to_local", resolveToLocal)
	} else {
		resolveToLocal = localCert.UpdatedAt > apisixSSL.UpdateTime
		logger.Log.Info("证书冲突：revision 缺失，按 update_time 决策",
			"domain", domain,
			"local_updated_at", localCert.UpdatedAt,
			"apisix_update_time", apisixSSL.UpdateTime,
			"resolve_to_local", resolveToLocal)
	}

	if resolveToLocal {
		if SyncMode(m.cfg.SyncMode) == SyncModeStrict && localCert.Source == cert.CertSourceExternal {
			logger.Log.Warn("严格模式：external 证书冲突，跳过推送", "domain", domain)
			return "warned"
		}
		if err := m.pushToAPISIX(localCert); err != nil {
			logger.Log.Error("推送证书到 APISIX 失败", "domain", domain, "error", err)
			_ = m.certRepo.UpdateCertSyncState(domain, cert.CertStatusSyncFailed, err.Error())
			return "sync_failed"
		}
		_ = m.certRepo.UpdateCertSyncState(domain, cert.CertStatusIssued, "")
		return "updated"
	}

	if SyncMode(m.cfg.SyncMode) == SyncModeStrict {
		logger.Log.Warn("严格模式：APISIX 版本较新，记录冲突但不自动覆盖本地",
			"domain", domain, "local_revision", localCert.Revision, "apisix_revision", apisixRevision)
		_ = m.certRepo.UpdateCertSyncState(domain, cert.CertStatusSyncFailed, "conflict: apisix is newer, strict mode skipped pull")
		return "warned"
	}
	if err := m.importFromAPISIX(domain, apisixSSL, localCert.Source); err != nil {
		logger.Log.Error("从 APISIX 拉取证书失败", "domain", domain, "error", err)
		_ = m.certRepo.UpdateCertSyncState(domain, cert.CertStatusSyncFailed, err.Error())
		return "sync_failed"
	}
	return "updated"
}

func (m *Manager) handleRenew(c *cert.Certificate) {
	domain := c.Domain

	if c.Source == cert.CertSourceExternal {
		if SyncMode(m.cfg.SyncMode) == SyncModeCompat {
			logger.Log.Info("外部证书即将到期，尝试 ACME 自动续期", "domain", domain,
				"not_after", time.Unix(c.NotAfter, 0).Format("2006-01-02"))
			_ = m.certRepo.UpdateCertSyncState(domain, cert.CertStatusPending, "external cert approaching expiry, queued for renewal")
		} else {
			logger.Log.Warn("外部证书即将到期但严格模式下无法自动续期，请手动处理",
				"domain", domain,
				"not_after", time.Unix(c.NotAfter, 0).Format("2006-01-02"))
		}
		return
	}

	if !c.Renewing {
		logger.Log.Info("证书进入续期窗口，标记待续期", "domain", domain,
			"not_after", time.Unix(c.NotAfter, 0).Format("2006-01-02"))
	}
}

func (m *Manager) firstSync(allSSLs map[string]*cert.ApisixSSLObject) error {
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
			if err := m.importFromAPISIX(domain, ssl, cert.CertSourceManaged); err != nil {
				logger.Log.Error("首次同步：导入 managed 证书失败", "domain", domain, "error", err)
				continue
			}
			managedCount++
		} else if m.cfg.SNIPattern != "" && matchSNIPattern(ssl.SNIs, m.cfg.SNIPattern) {
			if err := m.importFromAPISIX(domain, ssl, cert.CertSourceExternal); err != nil {
				logger.Log.Error("首次同步：导入 external 证书失败", "domain", domain, "error", err)
				continue
			}
			externalCount++
		} else {
			logger.Log.Debug("首次同步：跳过非托管证书", "domain", domain, "snis", ssl.SNIs)
			skippedCount++
		}
	}

	logger.Log.Info("首次同步导入完成", "managed", managedCount, "external", externalCount, "skipped", skippedCount)
	return nil
}

func matchSNIPattern(snis []string, pattern string) bool {
	for _, sni := range snis {
		if matched, _ := filepath.Match(pattern, sni); matched {
			return true
		}
	}
	return false
}

func (m *Manager) importFromAPISIX(domain string, apisixSSL *cert.ApisixSSLObject, source cert.CertSource) error {
	block, _ := pem.Decode([]byte(apisixSSL.Cert))
	if block == nil {
		return fmt.Errorf("解析 APISIX 证书 PEM 失败")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("解析证书失败：%w", err)
	}

	fingerprint, _ := cert.CalculateFingerprint(apisixSSL.Cert)
	serialNumber, _ := cert.CalculateSerialNumber(apisixSSL.Cert)

	now := time.Now().Unix()
	apisixID := apisixSSL.ID
	if apisixID == "" {
		apisixID = cert.NormalizeAPISIXID(domain)
	}

	existingRevision := 0
	if existing, ok := m.certRepo.GetByAPISIXID(apisixID); ok {
		existingRevision = existing.Revision
	}

	localCert := &cert.Certificate{
		Domain:       domain,
		SNIs:         apisixSSL.SNIs,
		NotBefore:    certificate.NotBefore.Unix(),
		NotAfter:     certificate.NotAfter.Unix(),
		APISIXID:     apisixID,
		Fingerprint:  fingerprint,
		SerialNumber: serialNumber,
		CreatedAt:    now,
		UpdatedAt:    now,
		Deleted:      false,
		Status:       cert.CertStatusIssued,
		Source:       source,
		LastSyncedAt: now,
		Revision:     existingRevision,
	}

	if err := m.certRepo.Upsert(localCert); err != nil {
		return fmt.Errorf("保存证书到本地失败：%w", err)
	}

	if apisixSSL.Key != "" {
		if err := m.certCache.Put(domain, apisixSSL.Cert, apisixSSL.Key, certificate.NotBefore.Unix(), certificate.NotAfter.Unix()); err != nil {
			logger.Log.Error("保存证书到文件缓存失败", "domain", domain, "error", err)
		}
	}

	return nil
}

func (m *Manager) pushToAPISIX(localCert *cert.Certificate) error {
	domain := localCert.Domain
	snis := localCert.SNIs
	if len(snis) == 0 {
		snis = []string{domain}
	}

	cached, ok := m.certCache.Get(domain)
	if !ok {
		return fmt.Errorf("文件缓存不存在（domain=%s），已标记 pending 等待 renew 任务重新签发", domain)
	}

	labels := m.buildManagedLabels(localCert.Revision)
	if err := m.apisix.UpsertCertificate(domain, snis, cached.CertPEM, cached.KeyPEM, cached.NotAfter, labels); err != nil {
		return fmt.Errorf("上传证书到 APISIX 失败：%w", err)
	}

	logger.Log.Info("证书已推送到 APISIX", "domain", domain, "snis", snis, "revision", localCert.Revision)
	return nil
}