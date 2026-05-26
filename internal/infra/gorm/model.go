package gorm

import (
	"time"

	"github.com/as7446/apisix-acme-go/internal/domain/cert"
)

// CertModel 证书元数据模型
type CertModel struct {
	ID              uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	Domain          string `gorm:"type:varchar(255);uniqueIndex;not null" json:"domain"`
	LifecycleStatus string `gorm:"type:varchar(32);default:'active';index" json:"lifecycle_status"`
	SyncStatus      string `gorm:"type:varchar(32);default:'unknown';index" json:"sync_status"`
	CurrentRevision uint   `gorm:"type:int unsigned;default:1" json:"current_revision"` // 当前生效版本
	NotBefore       uint64 `gorm:"type:bigint unsigned;default:0" json:"not_before"`
	NotAfter        uint64 `gorm:"type:bigint unsigned;default:0;index" json:"not_after"`
	APISIXID        string `gorm:"type:varchar(255);default:'';index" json:"apisix_id"`
	Fingerprint     string `gorm:"type:varchar(255);default:''" json:"fingerprint"`
	SerialNumber    string `gorm:"type:varchar(255);default:''" json:"serial_number"`
	CreatedAt       uint64 `gorm:"type:bigint unsigned;default:0" json:"created_at"`
	UpdatedAt       uint64 `gorm:"type:bigint unsigned;default:0;index" json:"updated_at"`
	LastRenewAt     uint64 `gorm:"type:bigint unsigned;default:0" json:"last_renew_at"`
	Deleted         bool   `gorm:"type:tinyint(1);default:0;index" json:"deleted"`
	DeletedAt       uint64 `gorm:"type:bigint unsigned;default:0" json:"deleted_at"`
	Source          string `gorm:"type:varchar(32);default:'';index" json:"source"`
	LastSyncedAt    uint64 `gorm:"type:bigint unsigned;default:0" json:"last_synced_at"`
	SyncError       string `gorm:"type:text" json:"sync_error"`
	IssueStatus     string `gorm:"type:varchar(32);default:'idle';index" json:"issue_status"` // idle/pending/issuing/failed
	LastIssuedAt    uint64 `gorm:"type:bigint unsigned;default:0" json:"last_issued_at"`
	ChallengeZone   string `gorm:"type:varchar(64);default:'';index" json:"challenge_zone"` // HTTP-01 challenge zone
	SyncZones       string `gorm:"type:text" json:"sync_zones"`                             // JSON array: ["hk","us"]
	RetryCount      int    `gorm:"type:int;default:0" json:"retry_count"`
	NextRetryAt     int64  `gorm:"type:bigint;default:0;index" json:"next_retry_at"`
}

func (CertModel) TableName() string {
	return "cert_certs"
}

// ToDomain 转换为领域模型
func (m *CertModel) ToDomain() *cert.Certificate {
	issueStatus := cert.IssueStatus(m.IssueStatus)
	if issueStatus == "" {
		issueStatus = cert.IssueIdle
	}
	lifecycleStatus := cert.LifecycleStatus(m.LifecycleStatus)
	if lifecycleStatus == "" {
		lifecycleStatus = cert.LifecycleActive
	}
	syncStatus := cert.SyncStatus(m.SyncStatus)
	if syncStatus == "" {
		syncStatus = cert.SyncUnknown
	}
	var syncZones []string
	if m.SyncZones != "" && m.SyncZones != "[]" {
		parseJSONArray(m.SyncZones, &syncZones)
	}
	return &cert.Certificate{
		ID:              int(m.ID),
		Domain:          m.Domain,
		NotBefore:       int64(m.NotBefore),
		NotAfter:        int64(m.NotAfter),
		APISIXID:        m.APISIXID,
		Fingerprint:     m.Fingerprint,
		SerialNumber:    m.SerialNumber,
		CreatedAt:       int64(m.CreatedAt),
		UpdatedAt:       int64(m.UpdatedAt),
		LastRenewAt:     int64(m.LastRenewAt),
		Deleted:         m.Deleted,
		Source:          cert.CertSource(m.Source),
		LastSyncedAt:    int64(m.LastSyncedAt),
		Revision:        int64(m.CurrentRevision),
		LastIssuedAt:    int64(m.LastIssuedAt),
		LifecycleStatus: lifecycleStatus,
		IssueStatus:     issueStatus,
		SyncStatus:      syncStatus,
		ChallengeZone:   m.ChallengeZone,
		SyncZones:       syncZones,
		RetryCount:      m.RetryCount,
		NextRetryAt:     m.NextRetryAt,
	}
}

// FromDomain 从领域模型转换
func (m *CertModel) FromDomain(c *cert.Certificate) {
	m.ID = uint(c.ID)
	m.Domain = c.Domain
	m.NotBefore = uint64(c.NotBefore)
	m.NotAfter = uint64(c.NotAfter)
	m.APISIXID = c.APISIXID
	m.Fingerprint = c.Fingerprint
	m.SerialNumber = c.SerialNumber
	m.CreatedAt = uint64(c.CreatedAt)
	m.UpdatedAt = uint64(c.UpdatedAt)
	m.LastRenewAt = uint64(c.LastRenewAt)
	m.Deleted = c.Deleted
	m.Source = string(c.Source)
	m.LastSyncedAt = uint64(c.LastSyncedAt)
	m.CurrentRevision = uint(c.Revision)
	m.LastIssuedAt = uint64(c.LastIssuedAt)
	if c.LifecycleStatus == "" {
		c.LifecycleStatus = cert.LifecycleActive
	}
	if c.IssueStatus == "" {
		c.IssueStatus = cert.IssueIdle
	}
	if c.SyncStatus == "" {
		c.SyncStatus = cert.SyncUnknown
	}
	m.LifecycleStatus = string(c.LifecycleStatus)
	m.SyncStatus = string(c.SyncStatus)
	m.IssueStatus = string(c.IssueStatus)
	m.ChallengeZone = c.ChallengeZone
	m.SyncZones = toJSONArray(c.SyncZones)
	m.RetryCount = c.RetryCount
	m.NextRetryAt = c.NextRetryAt
}

// AcmeAccountModel ACME 账户模型
type AcmeAccountModel struct {
	Email        string `gorm:"type:varchar(255);primaryKey" json:"email"`
	PrivateKey   []byte `gorm:"type:mediumblob;not null" json:"private_key"`
	Registration []byte `gorm:"type:mediumblob" json:"registration"`
	CreatedAt    uint64 `gorm:"type:bigint unsigned;default:0" json:"created_at"`
}

func (AcmeAccountModel) TableName() string {
	return "cert_acme_accounts"
}

func (m *AcmeAccountModel) ToDomain() *cert.AcmeAccount {
	return &cert.AcmeAccount{
		Email:        m.Email,
		PrivateKey:   m.PrivateKey,
		Registration: m.Registration,
		CreatedAt:    int64(m.CreatedAt),
	}
}

func (m *AcmeAccountModel) FromDomain(a *cert.AcmeAccount) {
	m.Email = a.Email
	m.PrivateKey = a.PrivateKey
	m.Registration = a.Registration
	m.CreatedAt = uint64(a.CreatedAt)
}

// 辅助函数：解析简单 JSON 数组
func parseJSONArray(s string, target *[]string) {
	if s == "" || s == "[]" {
		*target = []string{}
		return
	}
	// 简单解析，移除 [] 并按 , 分割
	s = trimQuotes(s)
	if s == "" {
		*target = []string{}
		return
	}
	parts := splitJSONArray(s)
	*target = parts
}

func trimQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '[' && s[len(s)-1] == ']') {
			s = s[1 : len(s)-1]
		}
	}
	return s
}

func splitJSONArray(s string) []string {
	var result []string
	var current string
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			inQuote = !inQuote
		} else if c == ',' && !inQuote {
			result = append(result, trimQuotes(current))
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, trimQuotes(current))
	}
	return result
}

func toJSONArray(arr []string) string {
	if len(arr) == 0 {
		return "[]"
	}
	result := "["
	for i, s := range arr {
		if i > 0 {
			result += ","
		}
		result += "\"" + s + "\""
	}
	result += "]"
	return result
}

// TimeNow 当前时间戳
func TimeNow() uint64 {
	return uint64(time.Now().Unix())
}

// VersionModel 证书版本模型
type VersionModel struct {
	ID            uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	CertID        uint   `gorm:"type:bigint unsigned;not null;index" json:"cert_id"`
	Revision      uint   `gorm:"type:int unsigned;not null" json:"revision"`
	CertPEM       []byte `gorm:"type:mediumblob;not null" json:"cert_pem"`
	PrivateKeyPEM []byte `gorm:"type:mediumblob;not null" json:"private_key_pem"`
	NotBefore     uint64 `gorm:"type:bigint unsigned;default:0" json:"not_before"`
	NotAfter      uint64 `gorm:"type:bigint unsigned;default:0" json:"not_after"`
	Fingerprint   string `gorm:"type:varchar(255);default:''" json:"fingerprint"`
	SerialNumber  string `gorm:"type:varchar(255);default:''" json:"serial_number"`
	CreatedAt     uint64 `gorm:"type:bigint unsigned;default:0" json:"created_at"`
}

func (VersionModel) TableName() string {
	return "cert_versions"
}

// ToVersion 转换为领域模型
func (m *VersionModel) ToVersion() *cert.CertVersion {
	return &cert.CertVersion{
		ID:           int(m.ID),
		CertID:       int(m.CertID),
		Revision:     int64(m.Revision),
		NotBefore:    int64(m.NotBefore),
		NotAfter:     int64(m.NotAfter),
		Fingerprint:  m.Fingerprint,
		SerialNumber: m.SerialNumber,
		CreatedAt:    int64(m.CreatedAt),
	}
}

// FromVersion 从领域模型转换
func (m *VersionModel) FromVersion(v *cert.CertVersion) {
	m.ID = uint(v.ID)
	m.CertID = uint(v.CertID)
	m.Revision = uint(v.Revision)
	m.NotBefore = uint64(v.NotBefore)
	m.NotAfter = uint64(v.NotAfter)
	m.Fingerprint = v.Fingerprint
	m.SerialNumber = v.SerialNumber
	m.CreatedAt = uint64(v.CreatedAt)
}
