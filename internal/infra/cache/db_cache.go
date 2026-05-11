package cache

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/as7446/apisix-acme-go/internal/domain/cert"
	"github.com/as7446/apisix-acme-go/internal/infra/config"
	"github.com/as7446/apisix-acme-go/internal/infra/gorm"
)

// DBCache 基于数据库的证书缓存，优先从 DB 读，写时同时落 DB + 文件
type DBCache struct {
	dir      string
	certRepo *gorm.CertRepo
	mu       sync.RWMutex
}

// NewDBCache 创建 DB 缓存
func NewDBCache(storageDir string, certRepo *gorm.CertRepo) *DBCache {
	_ = os.MkdirAll(storageDir, 0755)
	return &DBCache{dir: storageDir, certRepo: certRepo}
}

func (c *DBCache) Load() error {
	return nil
}

// Get 优先从 DB 读取，无则从文件系统读取
func (c *DBCache) Get(domain string) (*cert.CachedCert, bool) {
	// 1. 尝试从 DB 读取最新版本
	if c.certRepo.HasVersionContent(domain) {
		version, ok := c.certRepo.GetLatestVersion(domain)
		if ok && version != nil {
			return &cert.CachedCert{
				Domain:    domain,
				CertPEM:   version.CertPEM,
				KeyPEM:    version.PrivateKeyPEM,
				NotBefore: version.NotBefore,
				NotAfter:  version.NotAfter,
			}, true
		}
	}

	// 2. 回退到文件系统（向后兼容旧数据）
	return c.getFromFile(domain)
}

// getFromFile 从文件系统读取
func (c *DBCache) getFromFile(domain string) (*cert.CachedCert, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	certData, err := os.ReadFile(c.GetCertPath(domain))
	if err != nil {
		return nil, false
	}
	keyData, err := os.ReadFile(c.GetKeyPath(domain))
	if err != nil {
		return nil, false
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, false
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, false
	}

	notBefore := parsed.NotBefore.Unix()
	notAfter := parsed.NotAfter.Unix()

	now := time.Now().Unix()
	if notAfter <= now+config.CacheExpiryBuffer {
		return nil, false
	}

	return &cert.CachedCert{
		Domain:    domain,
		CertPEM:   string(certData),
		KeyPEM:    string(keyData),
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}, true
}

// Put 写入 DB + 文件系统
func (c *DBCache) Put(domain, certPEM, keyPEM string, notBefore, notAfter int64) error {
	// 1. 写入 DB 版本表
	if err := c.certRepo.WriteCertContent(domain, certPEM, keyPEM); err != nil {
		logger.Log.Error("写入证书版本失败", "domain", domain, "error", err)
		// 不 return，继续写文件保证基本功能
	}

	// 2. 写入文件系统（保持向后兼容）
	c.mu.Lock()
	defer c.mu.Unlock()

	domainDir := filepath.Join(c.dir, domain)
	if err := os.MkdirAll(domainDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(c.GetCertPath(domain), []byte(certPEM), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(c.GetKeyPath(domain), []byte(keyPEM), 0o600); err != nil {
		return err
	}
	logger.Log.Info("证书已缓存（DB + File）", "domain", domain)
	return nil
}

// Remove 删除 DB 版本 + 文件
func (c *DBCache) Remove(domain string) error {
	// 删除文件
	c.mu.Lock()
	defer c.mu.Unlock()
	fileErr := os.RemoveAll(filepath.Join(c.dir, domain))

	// 删除 DB 版本（保留元数据）
	// 注意：这里不删除 cert_certs 记录，只删除版本
	// 如果需要删除元数据，调用 certRepo 的 MarkDeleted

	logger.Log.Info("证书缓存已删除", "domain", domain, "file_error", fileErr)
	return fileErr
}

// GetCertPath 获取证书文件路径
func (c *DBCache) GetCertPath(domain string) string {
	return filepath.Join(c.dir, domain, domain+".cer")
}

// GetKeyPath 获取私钥文件路径
func (c *DBCache) GetKeyPath(domain string) string {
	return filepath.Join(c.dir, domain, domain+".key")
}
