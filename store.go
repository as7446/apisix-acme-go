package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/asdine/storm/v3/q"
	"os"
	"path/filepath"
	"time"

	"github.com/asdine/storm/v3"
	"github.com/asdine/storm/v3/codec/gob"
)

// CertStatus 证书同步状态枚举
type CertStatus string

const (
	// CertStatusPending 待推送到 APISIX（新建未上传，或上次上传失败）
	CertStatusPending CertStatus = "pending"
	// CertStatusIssued 已签发并成功推送到 APISIX
	CertStatusIssued CertStatus = "issued"
	// CertStatusRenewing 正在执行 ACME 续期（防止并发重复续期）
	CertStatusRenewing CertStatus = "renewing"
	// CertStatusSyncFailed 最近一次同步失败
	CertStatusSyncFailed CertStatus = "sync_failed"
	// CertStatusDeleting 标记为待删除（等待 sync 从 APISIX 侧删除后再清除 DB 记录）
	CertStatusDeleting CertStatus = "deleting"
)

// CertSource 证书来源
type CertSource string

const (
	// CertSourceManaged 由本服务签发和管理
	CertSourceManaged CertSource = "managed"
	// CertSourceExternal 从 APISIX 导入的外部证书（不由本服务签发，只做代管）
	CertSourceExternal CertSource = "external"
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
	RenewLockAt  int64    `storm:"index"`
	Deleted      bool     `storm:"index"`
	DeletedAt    int64    `storm:"index"`
	// 同步状态（旧记录零值为 "" 视为 pending/issued 兼容处理）
	Status       CertStatus `storm:"index"` // 当前同步状态
	Source       CertSource `storm:"index"` // 证书来源（managed / external）
	LastSyncedAt int64      `storm:"index"` // 最近一次成功 reconcile 的时间
	SyncError    string     // 最近一次同步失败原因
	// 资源版本（每次 Upsert 自增，同步到 APISIX label 用于冲突解决）
	Revision     int    `storm:"index"` // 本地资源版本号
	Renewing     bool   `storm:"index"` // 是否正在执行 ACME 续期
	LastIssuedAt int64  `storm:"index"` // 最近一次 ACME 签发成功时间
	AcmeOrderURL string // ACME Order URL（幂等续期用）
}

// effectiveStatus 兼容旧记录（Status 为空时按 Deleted 字段推断）
func (c *Certificate) effectiveStatus() CertStatus {
	if c.Status != "" {
		return c.Status
	}
	// 兼容旧记录
	if c.Deleted {
		return CertStatusDeleting
	}
	return CertStatusIssued
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

// AcmeAccount ACME 账户信息
type AcmeAccount struct {
	Email        string `storm:"id"`
	PrivateKey   []byte
	Registration []byte // JSON encoded registration resource
	CreatedAt    int64  `storm:"index"`
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

	Log.Info("证书元数据存储初始化（Storm）", "path", dbPath)

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

// Get 获取证书元数据，不包括以删除的
func (s *StormCertStore) Get(domain string) (*Certificate, bool) {
	var cert Certificate
	err := s.db.One("Domain", domain, &cert)
	if err != nil {
		if errors.Is(err, storm.ErrNotFound) {
			return nil, false
		}
		Log.Error("查询证书元数据失败", "domain", domain, "error", err)
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
		Log.Error("查询证书元数据失败", "domain", domain, "error", err)
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
		// 保留 Source 若新值未指定
		if cert.Source == "" {
			cert.Source = existing.Source
		}
		// Revision 自增（确保每次 Upsert 都产生新版本号）
		if cert.Revision <= existing.Revision {
			cert.Revision = existing.Revision + 1
		}
	} else {
		if cert.CreatedAt == 0 {
			cert.CreatedAt = now
		}
		if cert.Source == "" {
			cert.Source = CertSourceManaged
		}
		// 新记录从 revision=1 开始
		if cert.Revision == 0 {
			cert.Revision = 1
		}
	}

	cert.UpdatedAt = now

	err := s.db.Save(cert)
	if err != nil {
		return fmt.Errorf("保存证书元数据失败：%w", err)
	}

	Log.Info("证书元数据已保存", "domain", cert.Domain, "fingerprint", cert.Fingerprint, "revision", cert.Revision)

	return nil
}

// GetByAPISIXID 按 APISIX SSL ID 查询证书，包括已删除的
func (s *StormCertStore) GetByAPISIXID(apisixID string) (*Certificate, bool) {
	var certs []Certificate
	if err := s.db.Find("APISIXID", apisixID, &certs); err != nil {
		return nil, false
	}
	if len(certs) == 0 {
		return nil, false
	}
	return &certs[0], true
}

// SetRenewing 设置证书续期中标志（不触发 Revision 自增，避免与推送逻辑冲突）
func (s *StormCertStore) SetRenewing(domain string, renewing bool, orderURL string) error {
	cert, exists := s.GetWithDeleted(domain)
	if !exists {
		return fmt.Errorf("证书不存在：%s", domain)
	}

	cert.Renewing = renewing
	cert.AcmeOrderURL = orderURL
	if renewing {
		cert.Status = CertStatusRenewing
	}
	cert.UpdatedAt = time.Now().Unix()

	if err := s.db.Save(cert); err != nil {
		return fmt.Errorf("设置续期状态失败：%w", err)
	}
	return nil
}

// UpdateCertSyncState 按证书粒度更新同步状态（不覆盖其他字段）
func (s *StormCertStore) UpdateCertSyncState(domain string, status CertStatus, syncErr string) error {
	cert, exists := s.GetWithDeleted(domain)
	if !exists {
		return fmt.Errorf("证书不存在：%s", domain)
	}

	now := time.Now().Unix()
	cert.Status = status
	cert.SyncError = syncErr
	if status == CertStatusIssued {
		cert.LastSyncedAt = now
	}
	cert.UpdatedAt = now

	if err := s.db.Save(cert); err != nil {
		return fmt.Errorf("更新证书同步状态失败：%w", err)
	}
	return nil
}

// All 获取所有证书
func (s *StormCertStore) All() ([]*Certificate, error) {
	var certs []Certificate
	err := s.db.All(&certs)
	if err != nil && !errors.Is(storm.ErrNotFound, err) {
		return nil, fmt.Errorf("查询所有证书失败：%w", err)
	}

	result := make([]*Certificate, 0, len(certs))
	for i := range certs {
		result = append(result, &certs[i])
	}
	return result, nil
}

// SaveTask 保存任务记录
func (s *StormCertStore) SaveTask(domain string, status string, errMsg string) error {
	now := time.Now().Unix()
	var rec TaskRecord
	qErr := s.db.One("Domain", domain, &rec)
	if qErr != nil && !errors.Is(qErr, storm.ErrNotFound) {
		return fmt.Errorf("查询任务记录失败：%w", qErr)
	}
	if errors.Is(qErr, storm.ErrNotFound) {
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
	if err := s.db.All(&recs); err != nil && !errors.Is(storm.ErrNotFound, err) {
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
	lockTimeout := int64(3600) // 锁超时时间 1 小时

	var certs []Certificate
	err := s.db.Select(q.Eq("Deleted", false)).Find(&certs)
	if err != nil && !errors.Is(err, storm.ErrNotFound) {
		return nil, fmt.Errorf("查询证书失败：%w", err)
	}

	result := make([]*Certificate, 0)
	for i := range certs {
		// 如果证书需要续期（notAfter - now <= renewWindow）
		if certs[i].NotAfter <= threshold {
			// 检查锁是否有效
			isLocked := false
			if certs[i].RenewLockAt > 0 {
				if now-certs[i].RenewLockAt < lockTimeout {
					isLocked = true
				}
			}

			if !isLocked {
				result = append(result, &certs[i])
			}
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

	now := time.Now().Unix()
	lockTimeout := int64(3600)

	// 再次检查锁（防止并发竞争）
	if cert.RenewLockAt > 0 && now-cert.RenewLockAt < lockTimeout {
		return false, nil
	}

	cert.RenewLockAt = now
	cert.UpdatedAt = now
	err := s.db.Save(cert)
	if err != nil {
		return false, fmt.Errorf("锁定续期失败：%w", err)
	}

	Log.Debug("续期已锁定", "domain", domain)

	return true, nil
}

// UnlockRenew 解锁续期
func (s *StormCertStore) UnlockRenew(domain string) error {
	cert, exists := s.GetWithDeleted(domain)
	if !exists {
		return fmt.Errorf("证书不存在：%s", domain)
	}

	cert.RenewLockAt = 0
	cert.UpdatedAt = time.Now().Unix()
	err := s.db.Save(cert)
	if err != nil {
		return fmt.Errorf("解锁续期失败：%w", err)
	}

	Log.Debug("续期已解锁", "domain", domain)
	return nil
}

// MarkDeleted 标记为删除中（Deleting 状态），等待 sync 从 APISIX 侧删除
func (s *StormCertStore) MarkDeleted(domain string) error {
	cert, exists := s.GetWithDeleted(domain)
	if !exists {
		return fmt.Errorf("证书不存在：%s", domain)
	}

	cert.Deleted = true
	cert.DeletedAt = time.Now().Unix()
	cert.UpdatedAt = time.Now().Unix()
	cert.Status = CertStatusDeleting
	err := s.db.Save(cert)
	if err != nil {
		return fmt.Errorf("标记删除失败：%w", err)
	}

	Log.Info("证书已标记删除", "domain", domain)

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
	cert.Status = CertStatusPending // 恢复后标记为待同步
	err := s.db.Save(cert)
	if err != nil {
		return fmt.Errorf("恢复证书失败：%w", err)
	}

	Log.Info("证书已恢复", "domain", domain)
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

// GetAccount 获取 ACME 账户
func (s *StormCertStore) GetAccount(email string) (*AcmeAccount, error) {
	var account AcmeAccount
	err := s.db.One("Email", email, &account)
	if err != nil {
		return nil, err
	}
	return &account, nil
}

// SaveAccount 保存 ACME 账户
func (s *StormCertStore) SaveAccount(account *AcmeAccount) error {
	if account.CreatedAt == 0 {
		account.CreatedAt = time.Now().Unix()
	}
	return s.db.Save(account)
}
