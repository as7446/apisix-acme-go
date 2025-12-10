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

// Certificate 证书元数据
type Certificate struct {
	ID           int      `storm:"id,increment"`
	Domain       string   `storm:"unique,index"`
	SNIs         []string `storm:"index"`
	NotBefore    int64    `storm:"index"`
	NotAfter     int64    `storm:"index"`
	APISIXID     string   `storm:"index"`
	Fingerprint  string   `storm:"index"`
	SerialNumber string   `storm:"index"`
	CreatedAt    int64    `storm:"index"`
	UpdatedAt    int64    `storm:"index"`
	LastRenewAt  int64    `storm:"index"`
	RenewLock    int      `storm:"index"`
	Deleted      bool     `storm:"index"`
	DeletedAt    int64    `storm:"index"`
}

// TaskRecord 任务记录
type TaskRecord struct {
	ID        int    `storm:"id,increment"`
	Domain    string `storm:"index"`
	Status    string `storm:"index"`
	Error     string
	CreatedAt int64 `storm:"index"`
	UpdatedAt int64 `storm:"index"`
}

// SyncState 同步状态
type SyncState struct {
	ID            int   `storm:"id,increment"`
	LastSyncTime  int64 `storm:"index"`
	FirstSyncDone bool  `storm:"index"`
}

// StormCertStore 证书存储
type StormCertStore struct {
	db   *storm.DB
	path string
}

// NewStormCertStore 创建证书存储
func NewStormCertStore(cfg *Config) (*StormCertStore, error) {
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
		path: dbPath,
	}

	Log.Printf("证书元数据存储初始化（Storm）：path=%s", dbPath)

	return store, nil
}

// GetLastSyncTime 获取最后同步时间
func (s *StormCertStore) GetLastSyncTime() (int64, bool) {
	var state SyncState
	err := s.db.One("ID", 1, &state)
	if err != nil {
		return 0, false
	}
	return state.LastSyncTime, state.FirstSyncDone
}

// SetLastSyncTime 设置最后同步时间
func (s *StormCertStore) SetLastSyncTime(syncTime int64, firstSyncDone bool) error {
	state := SyncState{
		ID:            1,
		LastSyncTime:  syncTime,
		FirstSyncDone: firstSyncDone,
	}
	return s.db.Save(&state)
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
		Log.Printf("查询证书元数据失败：domain=%s, error=%v", domain, err)
		return nil, false
	}
	if cert.Deleted {
		return nil, false
	}
	return &cert, true
}

// GetWithDeleted 获取证书元数据，包括已删除的
func (s *StormCertStore) GetWithDeleted(domain string) (*Certificate, bool) {
	var cert Certificate
	err := s.db.One("Domain", domain, &cert)
	if err != nil {
		if err == storm.ErrNotFound {
			return nil, false
		}
		Log.Printf("查询证书元数据失败：domain=%s, error=%v", domain, err)
		return nil, false
	}
	return &cert, true
}

// Upsert 创建或更新证书元数据
func (s *StormCertStore) Upsert(cert *Certificate) error {
	now := time.Now().Unix()

	existing, exists := s.GetWithDeleted(cert.Domain)
	if exists {
		cert.ID = existing.ID
		if cert.CreatedAt == 0 {
			cert.CreatedAt = existing.CreatedAt
		}
		if !cert.Deleted && existing.Deleted {
			cert.Deleted = false
			cert.DeletedAt = 0
		}
	} else {
		if cert.CreatedAt == 0 {
			cert.CreatedAt = now
		}
	}

	cert.UpdatedAt = now

	err := s.db.Save(cert)
	if err != nil {
		return fmt.Errorf("保存证书元数据失败：%w", err)
	}

	Log.Printf("证书元数据已保存：domain=%s, fingerprint=%s", cert.Domain, cert.Fingerprint)

	return nil
}

// All 获取所有未删除的证书
func (s *StormCertStore) All() ([]*Certificate, error) {
	var certs []Certificate
	err := s.db.All(&certs)
	if err != nil && err != storm.ErrNotFound {
		return nil, fmt.Errorf("查询所有证书失败：%w", err)
	}

	result := make([]*Certificate, 0, len(certs))
	for i := range certs {
		if !certs[i].Deleted {
			result = append(result, &certs[i])
		}
	}
	return result, nil
}

// SaveTask 保存任务记录
func (s *StormCertStore) SaveTask(domain string, status string, errMsg string) error {
	now := time.Now().Unix()
	var rec TaskRecord
	qErr := s.db.One("Domain", domain, &rec)
	if qErr != nil && qErr != storm.ErrNotFound {
		return fmt.Errorf("查询任务记录失败：%w", qErr)
	}
	if qErr == storm.ErrNotFound {
		rec.CreatedAt = now
		rec.Domain = domain
	}
	rec.Status = status
	rec.Error = errMsg
	rec.UpdatedAt = now
	if err := s.db.Save(&rec); err != nil {
		return fmt.Errorf("保存任务记录失败：%w", err)
	}
	return nil
}

// GetTaskRecord 获取任务记录
func (s *StormCertStore) GetTaskRecord(domain string) (*TaskRecord, bool) {
	var rec TaskRecord
	err := s.db.One("Domain", domain, &rec)
	if err != nil {
		return nil, false
	}
	return &rec, true
}

// CleanupTasks 清理过期任务记录
func (s *StormCertStore) CleanupTasks(retentionHours int) error {
	cutoff := time.Now().Add(-time.Duration(retentionHours) * time.Hour).Unix()
	var recs []TaskRecord
	if err := s.db.All(&recs); err != nil && err != storm.ErrNotFound {
		return fmt.Errorf("查询任务记录失败：%w", err)
	}
	for i := range recs {
		if recs[i].UpdatedAt < cutoff {
			_ = s.db.DeleteStruct(&recs[i])
		}
	}
	return nil
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
		if certs[i].NotAfter <= threshold && certs[i].RenewLock == 0 {
			result = append(result, &certs[i])
		}
	}
	return result, nil
}

// LockRenew 锁定续期，防止并发续期
func (s *StormCertStore) LockRenew(domain string) (bool, error) {
	cert, exists := s.Get(domain)
	if !exists {
		return false, fmt.Errorf("证书不存在：%s", domain)
	}

	if cert.RenewLock == 1 {
		return false, nil
	}

	cert.RenewLock = 1
	cert.UpdatedAt = time.Now().Unix()
	err := s.db.Save(cert)
	if err != nil {
		return false, fmt.Errorf("锁定续期失败：%w", err)
	}

	Log.Printf("续期已锁定：domain=%s", domain)

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

	Log.Printf("续期已解锁：domain=%s", domain)
	return nil
}

// MarkDeleted 标记为已删除
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

	Log.Printf("证书已标记删除：domain=%s", domain)

	return nil
}

// RestoreDeleted 恢复已删除的证书
func (s *StormCertStore) RestoreDeleted(domain string) error {
	cert, exists := s.GetWithDeleted(domain)
	if !exists {
		return fmt.Errorf("证书不存在：%s", domain)
	}

	if !cert.Deleted {
		return nil
	}

	cert.Deleted = false
	cert.DeletedAt = 0
	cert.UpdatedAt = time.Now().Unix()
	err := s.db.Save(cert)
	if err != nil {
		return fmt.Errorf("恢复证书失败：%w", err)
	}

	Log.Printf("证书已恢复：domain=%s", domain)

	return nil
}

// CalculateFingerprint 计算证书指纹
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
