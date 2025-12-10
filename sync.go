package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
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

// Sync 执行同步操作
func (m *SyncManager) Sync() error {
	lastSyncTime, firstSyncDone := m.store.GetLastSyncTime()
	now := time.Now().Unix()

	apisixSSLs, err := m.apisix.ListSSLs()
	if err != nil {
		return fmt.Errorf("获取 APISIX 证书列表失败：%w", err)
	}
	Log.Printf("从 APISIX 获取到 %d 个证书", len(apisixSSLs))

	if !firstSyncDone {
		Log.Printf("首次同步，导入所有 APISIX 证书")
		if err := m.importAllFromAPISIX(apisixSSLs); err != nil {
			return fmt.Errorf("首次导入失败：%w", err)
		}
		m.store.SetLastSyncTime(now, true)
		Log.Printf("首次同步完成，已导入 %d 个证书", len(apisixSSLs))
		return nil
	}

	localCerts, err := m.store.All()
	if err != nil {
		return fmt.Errorf("获取本地证书列表失败：%w", err)
	}
	Log.Printf("本地数据库有 %d 个证书", len(localCerts))

	localMap := make(map[string]*Certificate)
	for _, cert := range localCerts {
		localMap[cert.Domain] = cert
	}

	updatedCount := 0
	restoredCount := 0
	importedCount := 0
	deletedCount := 0

	for domain, localCert := range localMap {
		apisixSSL, exists := apisixSSLs[domain]
		if !exists {
			if !localCert.Deleted && localCert.UpdatedAt > lastSyncTime {
				Log.Printf("检测到 APISIX 证书被误删，自动恢复：domain=%s", domain)
				if err := m.restoreCertificate(domain, localCert); err != nil {
					Log.Printf("恢复证书失败：domain=%s, error=%v", domain, err)
					continue
				}
				restoredCount++
			}
			continue
		}

		apisixFingerprint, err := CalculateFingerprint(apisixSSL.Cert)
		if err != nil {
			Log.Printf("计算 APISIX 证书指纹失败：domain=%s, error=%v", domain, err)
			continue
		}

		if localCert.Fingerprint != "" && localCert.Fingerprint != apisixFingerprint {
			if localCert.UpdatedAt > lastSyncTime {
				Log.Printf("检测到证书不一致，更新到 APISIX：domain=%s", domain)
				if err := m.updateToAPISIX(domain, localCert); err != nil {
					Log.Printf("更新证书到 APISIX 失败：domain=%s, error=%v", domain, err)
					continue
				}
				updatedCount++
			}
		}
	}

	for domain, apisixSSL := range apisixSSLs {
		if _, exists := localMap[domain]; exists {
			continue
		}

		if SyncMode(m.cfg.SyncMode) == SyncModeStrict {
			Log.Printf("严格模式：删除 APISIX 证书：domain=%s", domain)
			if err := m.apisix.DeleteCertificate(domain); err != nil {
				Log.Printf("删除 APISIX 证书失败：domain=%s, error=%v", domain, err)
				continue
			}
			deletedCount++
		} else {
			Log.Printf("兼容模式：导入证书到本地：domain=%s", domain)
			if err := m.importCertificate(domain, apisixSSL); err != nil {
				Log.Printf("导入证书失败：domain=%s, error=%v", domain, err)
				continue
			}
			importedCount++
		}
	}

	m.store.SetLastSyncTime(now, true)
	Log.Printf("证书同步完成：更新=%d, 恢复=%d, 导入=%d, 删除=%d", updatedCount, restoredCount, importedCount, deletedCount)
	return nil
}

// importAllFromAPISIX 首次同步时导入所有 APISIX 证书
func (m *SyncManager) importAllFromAPISIX(apisixSSLs map[string]*ApisixSSLObject) error {
	for domain, apisixSSL := range apisixSSLs {
		if err := m.importCertificate(domain, apisixSSL); err != nil {
			Log.Printf("导入证书失败：domain=%s, error=%v", domain, err)
			continue
		}
	}
	return nil
}

// importCertificate 导入单个证书到本地
func (m *SyncManager) importCertificate(domain string, apisixSSL *ApisixSSLObject) error {
	block, _ := pem.Decode([]byte(apisixSSL.Cert))
	if block == nil {
		return fmt.Errorf("解析 APISIX 证书失败")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("解析证书失败：%w", err)
	}

	fingerprint, _ := CalculateFingerprint(apisixSSL.Cert)
	serialNumber, _ := CalculateSerialNumber(apisixSSL.Cert)

	now := time.Now().Unix()
	localCert := &Certificate{
		Domain:       domain,
		SNIs:         apisixSSL.SNIs,
		NotBefore:    cert.NotBefore.Unix(),
		NotAfter:     cert.NotAfter.Unix(),
		APISIXID:     apisixSSL.ID,
		Fingerprint:  fingerprint,
		SerialNumber: serialNumber,
		CreatedAt:    now,
		UpdatedAt:    now,
		Deleted:      false,
	}

	if err := m.store.Upsert(localCert); err != nil {
		return fmt.Errorf("保存证书到本地失败：%w", err)
	}

	if err := m.certCache.Put(domain, apisixSSL.Cert, apisixSSL.Key, cert.NotBefore.Unix(), cert.NotAfter.Unix()); err != nil {
		Log.Printf("保存证书到缓存失败：domain=%s, error=%v", domain, err)
	}

	return nil
}

// updateToAPISIX 更新证书到 APISIX
func (m *SyncManager) updateToAPISIX(domain string, localCert *Certificate) error {
	cached, ok := m.certCache.Get(domain)
	if !ok {
		return fmt.Errorf("本地缓存不存在")
	}

	if err := m.apisix.UpsertCertificate(domain, []string{domain}, cached.CertPEM, cached.KeyPEM, cached.NotAfter); err != nil {
		return fmt.Errorf("上传证书到 APISIX 失败：%w", err)
	}

	return nil
}

// restoreCertificate 恢复证书到 APISIX
func (m *SyncManager) restoreCertificate(domain string, localCert *Certificate) error {
	cached, ok := m.certCache.Get(domain)
	if !ok {
		return fmt.Errorf("本地缓存不存在")
	}

	if err := m.apisix.UpsertCertificate(domain, []string{domain}, cached.CertPEM, cached.KeyPEM, cached.NotAfter); err != nil {
		return fmt.Errorf("恢复证书到 APISIX 失败：%w", err)
	}

	return nil
}
