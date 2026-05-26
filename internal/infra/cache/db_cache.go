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

// Get 从文件系统读取证书（CertVersion 不再存储 PEM，统一走文件系统）
func (c *DBCache) Get(domain string) (*cert.CachedCert, bool) {
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

	// 2. 写入文件系统，供 Agent 同步任务读取证书内容。
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

	logger.Log.Info("证书缓存已删除", "domain", domain, "file_error", fileErr)
	return fileErr
}

// Delete 删除证书文件（实现 CertStorage 接口）
func (c *DBCache) Delete(domain string) error {
	return c.Remove(domain)
}

// Exists 检查证书文件是否存在（实现 CertStorage 接口）
func (c *DBCache) Exists(domain string) bool {
	_, ok := c.getFromFile(domain)
	return ok
}

// GetCertPEM 获取证书 PEM（实现 CertStorage 接口）
func (c *DBCache) GetCertPEM(domain string) (string, error) {
	data, err := os.ReadFile(c.GetCertPath(domain))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// GetKeyPEM 获取私钥 PEM（实现 CertStorage 接口）
func (c *DBCache) GetKeyPEM(domain string) (string, error) {
	data, err := os.ReadFile(c.GetKeyPath(domain))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Save 保存证书 PEM（实现 CertStorage 接口）
func (c *DBCache) Save(domain, certPEM, keyPEM string) error {
	return c.Put(domain, certPEM, keyPEM, 0, 0)
}

// GetCertPath 获取证书文件路径
func (c *DBCache) GetCertPath(domain string) string {
	return filepath.Join(c.dir, domain, domain+".cer")
}

// GetKeyPath 获取私钥文件路径
func (c *DBCache) GetKeyPath(domain string) string {
	return filepath.Join(c.dir, domain, domain+".key")
}
