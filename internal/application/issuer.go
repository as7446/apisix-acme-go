package application

import (
	"fmt"
	"time"

	"github.com/as7446/apisix-acme-go/internal/domain/acme"
	"github.com/as7446/apisix-acme-go/internal/domain/cert"
	"github.com/as7446/apisix-acme-go/internal/infra/config"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
)

// Issuer 签发器：执行 ACME 证书签发
// 职责边界：
//   - 调用 lego 执行 ACME 签发
//   - 保存证书到 CertStorage（不是 DB）
//   - 更新证书元数据（revision++）
//   - 设置 sync_status = drifted（通知 Controller FSM 通过 Agent 同步）
//   - 不操作 APISIX（网关操作由 Agent 执行）
//   - 不负责 sync（由 Controller FSM 调度 Agent 执行）
//   - 不负责锁管理（由 Controller FSM 负责）
type Issuer struct {
	certRepo   cert.CertRepository
	certCache  cert.CertCache
	storage    cert.CertStorage
	acmeClient *acme.Manager
	cfg        *config.Config
}

// NewIssuer 创建签发器
func NewIssuer(
	certRepo cert.CertRepository,
	certCache cert.CertCache,
	storage cert.CertStorage,
	acmeClient *acme.Manager,
	cfg *config.Config,
) *Issuer {
	return &Issuer{
		certRepo:   certRepo,
		certCache:  certCache,
		storage:    storage,
		acmeClient: acmeClient,
		cfg:        cfg,
	}
}

// Issue 执行新证书签发
// 流程：
//  1. 调用 lego 获取证书
//  2. 保存到 cert storage
//  3. revision++
//  4. 更新 metadata（issue_status = idle, sync_status = drifted）
//
// 注意：锁管理和 issue_status 状态转换由 Controller FSM 负责
func (i *Issuer) Issue(domain string) error {
	logger.Log.Info("开始签发证书", "domain", domain)

	// 获取证书元数据
	c, ok := i.certRepo.Get(domain)
	if !ok {
		c = &cert.Certificate{
			Domain: domain,
			Source: cert.CertSourceManaged,
		}
	}

	// 调用 ACME 获取证书
	email := i.cfg.DefaultEmail
	certPEM, keyPEM, notBefore, notAfter, err := i.obtainCertificate(domain, email)
	if err != nil {
		return fmt.Errorf("获取证书失败：%w", err)
	}

	// 保存到 cert storage（不是 DB）
	if err := i.storage.Save(domain, certPEM, keyPEM); err != nil {
		return fmt.Errorf("保存证书到存储失败：%w", err)
	}

	// 计算指纹和序列号
	fingerprint, _ := cert.CalculateFingerprint(certPEM)
	serialNumber, _ := cert.CalculateSerialNumber(certPEM)

	// 更新元数据（issue_status = idle, sync_status = drifted）
	now := time.Now().Unix()
	updatedCert := &cert.Certificate{
		Domain:          domain,
		NotBefore:       notBefore,
		NotAfter:        notAfter,
		APISIXID:        cert.NormalizeAPISIXID(domain),
		Fingerprint:     fingerprint,
		SerialNumber:    serialNumber,
		Source:          cert.CertSourceManaged,
		LifecycleStatus: c.LifecycleStatus,
		LastIssuedAt:    now,
		IssueStatus:     cert.IssueIdle,
		SyncStatus:      cert.SyncDrifted,
		ChallengeZone:   c.ChallengeZone,
		SyncZones:       c.SyncZones,
	}

	if c.ID > 0 {
		updatedCert.ID = c.ID
		updatedCert.CreatedAt = c.CreatedAt
		updatedCert.Revision = c.Revision + 1
	} else {
		updatedCert.Revision = 1
	}

	if err := i.certRepo.Upsert(updatedCert); err != nil {
		return fmt.Errorf("保存证书元数据失败：%w", err)
	}

	logger.Log.Info("证书签发完成", "domain", domain,
		"not_before", time.Unix(notBefore, 0).Format("2006-01-02"),
		"not_after", time.Unix(notAfter, 0).Format("2006-01-02"),
		"revision", updatedCert.Revision)

	return nil
}

// Renew 执行证书续期
// 续期与签发的区别：
//   - 续期使用缓存证书（如果有效）
//   - 续期更新 LastRenewAt
//
// 注意：锁管理由 Controller FSM 负责
func (i *Issuer) Renew(domain string) error {
	logger.Log.Info("开始续期证书", "domain", domain)

	// 获取证书元数据
	c, ok := i.certRepo.Get(domain)
	if !ok {
		return fmt.Errorf("证书不存在：%s", domain)
	}

	now := time.Now().Unix()
	renewWindow := int64(i.cfg.RenewBeforeDays * 24 * 3600)
	renewThreshold := now + renewWindow

	// 检查缓存证书是否足够新
	cached, hasCache := i.getCertCache().Get(domain)
	if hasCache && cached.NotAfter > renewThreshold {
		logger.Log.Info("使用缓存证书续期", "domain", domain,
			"not_after", time.Unix(cached.NotAfter, 0).Format("2006-01-02"))
		return i.processCachedCert(domain, cached, c)
	}

	// 需要 ACME 签发
	return i.renewWithACME(domain, c)
}

// getCertCache 返回 CertCache
func (i *Issuer) getCertCache() cert.CertCache {
	return i.certCache
}

// processCachedCert 处理缓存证书
func (i *Issuer) processCachedCert(domain string, cached *cert.CachedCert, existing *cert.Certificate) error {
	// 保存到 storage
	if err := i.storage.Save(domain, cached.CertPEM, cached.KeyPEM); err != nil {
		return fmt.Errorf("保存证书到存储失败：%w", err)
	}

	// 计算指纹
	fingerprint, _ := cert.CalculateFingerprint(cached.CertPEM)
	serialNumber, _ := cert.CalculateSerialNumber(cached.CertPEM)

	now := time.Now().Unix()
	updatedCert := &cert.Certificate{
		Domain:          domain,
		NotBefore:       cached.NotBefore,
		NotAfter:        cached.NotAfter,
		APISIXID:        cert.NormalizeAPISIXID(domain),
		Fingerprint:     fingerprint,
		SerialNumber:    serialNumber,
		Source:          existing.Source,
		LifecycleStatus: existing.LifecycleStatus,
		LastRenewAt:     now,
		IssueStatus:     cert.IssueIdle,
		SyncStatus:      cert.SyncDrifted,
		ChallengeZone:   existing.ChallengeZone,
		SyncZones:       existing.SyncZones,
	}

	if existing.ID > 0 {
		updatedCert.ID = existing.ID
		updatedCert.CreatedAt = existing.CreatedAt
		updatedCert.Revision = existing.Revision + 1
	} else {
		updatedCert.Revision = 1
	}

	if err := i.certRepo.Upsert(updatedCert); err != nil {
		return fmt.Errorf("保存证书元数据失败：%w", err)
	}

	logger.Log.Info("缓存证书续期完成", "domain", domain,
		"not_after", time.Unix(cached.NotAfter, 0).Format("2006-01-02"),
		"revision", updatedCert.Revision)

	return nil
}

// renewWithACME 使用 ACME 续期
func (i *Issuer) renewWithACME(domain string, existing *cert.Certificate) error {
	email := i.cfg.DefaultEmail

	// 调用 ACME 获取证书
	certPEM, keyPEM, notBefore, notAfter, err := i.obtainCertificate(domain, email)
	if err != nil {
		return fmt.Errorf("ACME 续期失败：%w", err)
	}

	// 保存到 storage
	if err := i.storage.Save(domain, certPEM, keyPEM); err != nil {
		return fmt.Errorf("保存证书到存储失败：%w", err)
	}

	// 计算指纹
	fingerprint, _ := cert.CalculateFingerprint(certPEM)
	serialNumber, _ := cert.CalculateSerialNumber(certPEM)

	now := time.Now().Unix()
	updatedCert := &cert.Certificate{
		Domain:          domain,
		NotBefore:       notBefore,
		NotAfter:        notAfter,
		APISIXID:        cert.NormalizeAPISIXID(domain),
		Fingerprint:     fingerprint,
		SerialNumber:    serialNumber,
		Source:          existing.Source,
		LifecycleStatus: existing.LifecycleStatus,
		LastRenewAt:     now,
		IssueStatus:     cert.IssueIdle,
		SyncStatus:      cert.SyncDrifted,
		ChallengeZone:   existing.ChallengeZone,
		SyncZones:       existing.SyncZones,
	}

	if existing.ID > 0 {
		updatedCert.ID = existing.ID
		updatedCert.CreatedAt = existing.CreatedAt
		updatedCert.Revision = existing.Revision + 1
	} else {
		updatedCert.Revision = 1
	}

	if err := i.certRepo.Upsert(updatedCert); err != nil {
		return fmt.Errorf("保存证书元数据失败：%w", err)
	}

	logger.Log.Info("ACME 续期完成", "domain", domain,
		"not_after", time.Unix(notAfter, 0).Format("2006-01-02"),
		"revision", updatedCert.Revision)

	return nil
}

// obtainCertificate 调用纯 ACME 获取证书
func (i *Issuer) obtainCertificate(domain, email string) (certPEM, keyPEM string, notBefore, notAfter int64, err error) {
	//maxRetries := i.cfg.CertRetryMax
	//baseDelay := time.Duration(i.cfg.CertRetryDelay) * time.Second

	var lastErr error
	certPEM, keyPEM, notBefore, notAfter, lastErr = i.tryObtain(domain, email)
	if lastErr == nil {
		return certPEM, keyPEM, notBefore, notAfter, nil
	}
	return "", "", 0, 0, fmt.Errorf("证书申请最终失败：%w", lastErr)
}

// tryObtain 单次尝试获取证书
func (i *Issuer) tryObtain(domain, email string) (certPEM, keyPEM string, notBefore, notAfter int64, err error) {
	return i.acmeClient.ObtainCertificate(domain, email)
}
