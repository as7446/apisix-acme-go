package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/asdine/storm/v3"
	"github.com/asdine/storm/v3/codec/gob"
)

// Certificate 证书元数据（使用 Storm 存储）
type Certificate struct {
	ID           int      `storm:"id,increment"` // Storm 自增 ID
	Domain       string   `storm:"unique,index"` // 域名（主键，唯一索引）
	SNIs         []string `storm:"index"`        // SNI 列表（索引）
	NotBefore    int64    `storm:"index"`        // 证书生效时间
	NotAfter     int64    `storm:"index"`        // 证书过期时间
	APISIXID     string   `storm:"index"`        // APISIX SSL ID
	Fingerprint  string   `storm:"index"`        // 证书指纹 (SHA256)
	SerialNumber string   `storm:"index"`        // 证书序列号
	CreatedAt    int64    `storm:"index"`        // 创建时间
	UpdatedAt    int64    `storm:"index"`        // 更新时间
	LastRenewAt  int64    `storm:"index"`        // 最后续期时间
	RenewLock    int      `storm:"index"`        // 续期锁 (0=未锁定, 1=锁定中)
	Deleted      bool     `storm:"index"`        // 软删除标记
	DeletedAt    int64    `storm:"index"`        // 删除时间
}

// StormCertStore 使用 Storm 的证书存储
type StormCertStore struct {
	db   *storm.DB
	log  Logger
	path string
}

// NewStormCertStore 创建新的 Storm 证书存储
func NewStormCertStore(cfg *Config, logger Logger) (*StormCertStore, error) {
	dir := cfg.StorageDir
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("创建存储目录失败：%w", err)
	}

	dbPath := filepath.Join(dir, "certs.db")
	db, err := storm.Open(dbPath, storm.Codec(gob.Codec), storm.BoltOptions(0600, nil))
	if err != nil {
		return nil, fmt.Errorf("打开 Storm 数据库失败：%w", err)
	}

	store := &StormCertStore{
		db:   db,
		log:  logger,
		path: dbPath,
	}

	if logger != nil {
		logger.Printf("证书元数据存储初始化（Storm）：path=%s", dbPath)
	}

	return store, nil
}

// Close 关闭数据库连接
func (s *StormCertStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Get 获取证书元数据
func (s *StormCertStore) Get(domain string) (*Certificate, bool) {
	var cert Certificate
	err := s.db.One("Domain", domain, &cert)
	if err != nil {
		if err == storm.ErrNotFound {
			return nil, false
		}
		if s.log != nil {
			s.log.Printf("查询证书元数据失败：domain=%s, error=%v", domain, err)
		}
		return nil, false
	}
	// 如果已删除，返回 false
	if cert.Deleted {
		return nil, false
	}
	return &cert, true
}

// GetWithDeleted 获取证书元数据（包括已删除的）
func (s *StormCertStore) GetWithDeleted(domain string) (*Certificate, bool) {
	var cert Certificate
	err := s.db.One("Domain", domain, &cert)
	if err != nil {
		if err == storm.ErrNotFound {
			return nil, false
		}
		if s.log != nil {
			s.log.Printf("查询证书元数据失败：domain=%s, error=%v", domain, err)
		}
		return nil, false
	}
	return &cert, true
}

// Upsert 创建或更新证书元数据
func (s *StormCertStore) Upsert(cert *Certificate) error {
	now := time.Now().Unix()

	// 检查是否已存在
	existing, exists := s.GetWithDeleted(cert.Domain)
	if exists {
		// 保留创建时间和删除标记（如果未明确设置）
		if cert.CreatedAt == 0 {
			cert.CreatedAt = existing.CreatedAt
		}
		if !cert.Deleted && existing.Deleted {
			// 恢复已删除的证书
			cert.Deleted = false
			cert.DeletedAt = 0
		}
	} else {
		// 新证书
		if cert.CreatedAt == 0 {
			cert.CreatedAt = now
		}
	}

	cert.UpdatedAt = now

	err := s.db.Save(cert)
	if err != nil {
		return fmt.Errorf("保存证书元数据失败：%w", err)
	}

	if s.log != nil {
		s.log.Printf("证书元数据已保存：domain=%s, fingerprint=%s", cert.Domain, cert.Fingerprint)
	}

	return nil
}

// All 获取所有未删除的证书
func (s *StormCertStore) All() ([]*Certificate, error) {
	var certs []Certificate
	err := s.db.Find("Deleted", false, &certs)
	if err != nil {
		if err == storm.ErrNotFound {
			return []*Certificate{}, nil
		}
		return nil, fmt.Errorf("查询所有证书失败：%w", err)
	}

	result := make([]*Certificate, len(certs))
	for i := range certs {
		result[i] = &certs[i]
	}
	return result, nil
}

// FindNeedRenew 查找需要续期的证书
func (s *StormCertStore) FindNeedRenew(renewBeforeDays int) ([]*Certificate, error) {
	now := time.Now().Unix()
	threshold := now + int64(renewBeforeDays*24*int(time.Hour/time.Second))

	var certs []Certificate
	err := s.db.Find("Deleted", false, &certs)
	if err != nil && err != storm.ErrNotFound {
		return nil, fmt.Errorf("查询证书失败：%w", err)
	}

	result := make([]*Certificate, 0)
	for i := range certs {
		// 检查是否即将过期且未锁定
		if certs[i].NotAfter <= threshold && certs[i].RenewLock == 0 {
			result = append(result, &certs[i])
		}
	}
	return result, nil
}

// LockRenew 锁定续期（防止并发续期）
func (s *StormCertStore) LockRenew(domain string) (bool, error) {
	cert, exists := s.Get(domain)
	if !exists {
		return false, fmt.Errorf("证书不存在：%s", domain)
	}

	if cert.RenewLock == 1 {
		return false, nil // 已被锁定
	}

	cert.RenewLock = 1
	cert.UpdatedAt = time.Now().Unix()
	err := s.db.Save(cert)
	if err != nil {
		return false, fmt.Errorf("锁定续期失败：%w", err)
	}

	if s.log != nil {
		s.log.Printf("续期已锁定：domain=%s", domain)
	}

	return true, nil
}

// UnlockRenew 解锁续期
func (s *StormCertStore) UnlockRenew(domain string) error {
	cert, exists := s.GetWithDeleted(domain)
	if !exists {
		return fmt.Errorf("证书不存在：%s", domain)
	}

	cert.RenewLock = 0
	cert.UpdatedAt = time.Now().Unix()
	err := s.db.Save(cert)
	if err != nil {
		return fmt.Errorf("解锁续期失败：%w", err)
	}

	if s.log != nil {
		s.log.Printf("续期已解锁：domain=%s", domain)
	}

	return nil
}

// MarkDeleted 标记为已删除（软删除）
func (s *StormCertStore) MarkDeleted(domain string) error {
	cert, exists := s.GetWithDeleted(domain)
	if !exists {
		return fmt.Errorf("证书不存在：%s", domain)
	}

	cert.Deleted = true
	cert.DeletedAt = time.Now().Unix()
	cert.UpdatedAt = time.Now().Unix()
	err := s.db.Save(cert)
	if err != nil {
		return fmt.Errorf("标记删除失败：%w", err)
	}

	if s.log != nil {
		s.log.Printf("证书已标记删除：domain=%s", domain)
	}

	return nil
}

// RestoreDeleted 恢复已删除的证书
func (s *StormCertStore) RestoreDeleted(domain string) error {
	cert, exists := s.GetWithDeleted(domain)
	if !exists {
		return fmt.Errorf("证书不存在：%s", domain)
	}

	if !cert.Deleted {
		return nil // 未删除，无需恢复
	}

	cert.Deleted = false
	cert.DeletedAt = 0
	cert.UpdatedAt = time.Now().Unix()
	err := s.db.Save(cert)
	if err != nil {
		return fmt.Errorf("恢复证书失败：%w", err)
	}

	if s.log != nil {
		s.log.Printf("证书已恢复：domain=%s", domain)
	}

	return nil
}

// CalculateFingerprint 计算证书指纹（SHA256）
func CalculateFingerprint(certPEM string) (string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", fmt.Errorf("无效的 PEM 格式")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("解析证书失败：%w", err)
	}

	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:]), nil
}

// CalculateSerialNumber 计算证书序列号
func CalculateSerialNumber(certPEM string) (string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", fmt.Errorf("无效的 PEM 格式")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("解析证书失败：%w", err)
	}

	return cert.SerialNumber.String(), nil
}
