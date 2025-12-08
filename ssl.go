package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Logger interface {
	Printf(format string, v ...any)
}

type CertMeta struct {
	Domain    string   `json:"domain"`
	SNIs      []string `json:"snis"`
	NotBefore int64    `json:"not_before"`
	NotAfter  int64    `json:"not_after"`
	APISIXID  string   `json:"apisix_id"`
	CreatedAt int64    `json:"created_at"`
	UpdatedAt int64    `json:"updated_at"`
}

type CachedCert struct {
	Domain    string
	CertPEM   string
	KeyPEM    string
	NotBefore int64
	NotAfter  int64
}

type FileCertStore struct {
	dir   string
	path  string
	mu    sync.RWMutex
	items map[string]*CertMeta
	log   Logger
}

func NewFileCertStore(cfg *Config, logger Logger) *FileCertStore {
	dir := cfg.StorageDir
	_ = os.MkdirAll(dir, 0755)
	return &FileCertStore{
		dir:   dir,
		path:  filepath.Join(dir, "certs.json"),
		items: make(map[string]*CertMeta),
		log:   logger,
	}
}

func (s *FileCertStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, &s.items)
}

func (s *FileCertStore) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tmp := s.path + ".tmp"
	data, err := json.MarshalIndent(s.items, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *FileCertStore) Upsert(meta *CertMeta) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().Unix()
	// 如果是新证书，设置创建时间；如果是更新，保留原有创建时间
	if existing, ok := s.items[meta.Domain]; ok {
		meta.CreatedAt = existing.CreatedAt
	} else {
		meta.CreatedAt = now
	}
	meta.UpdatedAt = now
	s.items[meta.Domain] = meta
	return s.Save()
}

func (s *FileCertStore) Get(domain string) (*CertMeta, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.items[domain]
	return m, ok
}

func (s *FileCertStore) All() []*CertMeta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make([]*CertMeta, 0, len(s.items))
	for _, v := range s.items {
		res = append(res, v)
	}
	return res
}

type CertCache struct {
	dir string
	mu  sync.RWMutex
	log Logger
}

func NewCertCache(cfg *Config, logger Logger) *CertCache {
	dir := cfg.StorageDir
	_ = os.MkdirAll(dir, 0755)
	return &CertCache{
		dir: dir,
		log: logger,
	}
}

func (c *CertCache) Load() error {
	return nil
}

func (c *CertCache) GetCertPath(domain string) string {
	return filepath.Join(c.dir, domain, domain+".cer")
}

func (c *CertCache) GetKeyPath(domain string) string {
	return filepath.Join(c.dir, domain, domain+".key")
}

func (c *CertCache) Get(domain string) (*CachedCert, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	certPath := c.GetCertPath(domain)
	keyPath := c.GetKeyPath(domain)

	// 检查文件是否存在
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, false
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, false
	}

	// 解析证书获取有效期
	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, false
	}

	notBefore := cert.NotBefore.Unix()
	notAfter := cert.NotAfter.Unix()

	// 检查证书是否过期（提前1天过期也算过期，避免使用即将过期的证书）
	now := time.Now().Unix()
	if notAfter <= now+86400 {
		return nil, false
	}

	return &CachedCert{
		Domain:    domain,
		CertPEM:   string(certData),
		KeyPEM:    string(keyData),
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}, true
}

// Put 保存证书到缓存目录
func (c *CertCache) Put(domain, certPEM, keyPEM string, notBefore, notAfter int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 创建域名目录
	domainDir := filepath.Join(c.dir, domain)
	if err := os.MkdirAll(domainDir, 0o755); err != nil {
		return err
	}

	certPath := c.GetCertPath(domain)
	keyPath := c.GetKeyPath(domain)

	// 写入证书文件
	if err := os.WriteFile(certPath, []byte(certPEM), 0o644); err != nil {
		return err
	}

	// 写入私钥文件（权限更严格）
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0o600); err != nil {
		return err
	}

	c.log.Printf("证书已缓存：域名=%s, 证书=%s, 私钥=%s", domain, certPath, keyPath)
	return nil
}

// Remove 删除缓存的证书目录
func (c *CertCache) Remove(domain string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	domainDir := filepath.Join(c.dir, domain)
	return os.RemoveAll(domainDir)
}
