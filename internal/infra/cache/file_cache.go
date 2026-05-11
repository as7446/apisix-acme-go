package cache

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/as7446/apisix-acme-go/internal/domain/cert"
	"github.com/as7446/apisix-acme-go/internal/infra/config"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
)

// FileCache 基于文件系统的证书缓存
type FileCache struct {
	dir string
	mu  sync.RWMutex
}

// New 创建文件缓存
func New(storageDir string) *FileCache {
	_ = os.MkdirAll(storageDir, 0755)
	return &FileCache{dir: storageDir}
}

func (c *FileCache) Load() error {
	return nil
}

func (c *FileCache) GetCertPath(domain string) string {
	return filepath.Join(c.dir, domain, domain+".cer")
}

func (c *FileCache) GetKeyPath(domain string) string {
	return filepath.Join(c.dir, domain, domain+".key")
}

func (c *FileCache) Get(domain string) (*cert.CachedCert, bool) {
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
		Domain: domain, CertPEM: string(certData), KeyPEM: string(keyData),
		NotBefore: notBefore, NotAfter: notAfter,
	}, true
}

func (c *FileCache) Put(domain, certPEM, keyPEM string, notBefore, notAfter int64) error {
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
	logger.Log.Info("证书已缓存", "domain", domain)
	return nil
}

func (c *FileCache) Remove(domain string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return os.RemoveAll(filepath.Join(c.dir, domain))
}
