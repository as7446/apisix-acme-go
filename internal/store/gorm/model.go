package gorm

import (
	"time"

	"github.com/as7446/apisix-acme-go/internal/domain/cert"
	"github.com/as7446/apisix-acme-go/internal/domain/task"
)

// CertModel 证书元数据模型
type CertModel struct {
	ID           uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	Domain       string `gorm:"type:varchar(255);uniqueIndex;not null" json:"domain"`
	SNIs         string `gorm:"type:text" json:"snis"` // JSON array: ["example.com"]
	NotBefore    uint64 `gorm:"type:bigint unsigned;default:0" json:"not_before"`
	NotAfter     uint64 `gorm:"type:bigint unsigned;default:0;index" json:"not_after"`
	APISIXID     string `gorm:"type:varchar(255);default:'';index" json:"apisix_id"`
	Fingerprint  string `gorm:"type:varchar(255);default:''" json:"fingerprint"`
	SerialNumber string `gorm:"type:varchar(255);default:''" json:"serial_number"`
	CreatedAt    uint64 `gorm:"type:bigint unsigned;default:0" json:"created_at"`
	UpdatedAt    uint64 `gorm:"type:bigint unsigned;default:0;index" json:"updated_at"`
	LastRenewAt  uint64 `gorm:"type:bigint unsigned;default:0" json:"last_renew_at"`
	RenewLockAt  uint64 `gorm:"type:bigint unsigned;default:0" json:"renew_lock_at"`
	Deleted      bool   `gorm:"type:tinyint(1);default:0;index" json:"deleted"`
	DeletedAt    uint64 `gorm:"type:bigint unsigned;default:0" json:"deleted_at"`
	Status       string `gorm:"type:varchar(32);default:'';index" json:"status"`
	Source       string `gorm:"type:varchar(32);default:'';index" json:"source"`
	LastSyncedAt uint64 `gorm:"type:bigint unsigned;default:0" json:"last_synced_at"`
	SyncError    string `gorm:"type:text" json:"sync_error"`
	Revision     uint   `gorm:"type:int unsigned;default:0" json:"revision"`
	Renewing     bool   `gorm:"type:tinyint(1);default:0;index" json:"renewing"`
	LastIssuedAt uint64 `gorm:"type:bigint unsigned;default:0" json:"last_issued_at"`
	AcmeOrderURL string `gorm:"type:text" json:"acme_order_url"`
}

func (CertModel) TableName() string {
	return "cert_certs"
}

// ToDomain 转换为领域模型
func (m *CertModel) ToDomain() *cert.Certificate {
	var snis []string
	if m.SNIs != "" {
		// 简单解析 JSON 数组
		parseJSONArray(m.SNIs, &snis)
	}

	return &cert.Certificate{
		ID:           int(m.ID),
		Domain:       m.Domain,
		SNIs:         snis,
		NotBefore:    int64(m.NotBefore),
		NotAfter:     int64(m.NotAfter),
		APISIXID:     m.APISIXID,
		Fingerprint:  m.Fingerprint,
		SerialNumber: m.SerialNumber,
		CreatedAt:    int64(m.CreatedAt),
		UpdatedAt:    int64(m.UpdatedAt),
		LastRenewAt:  int64(m.LastRenewAt),
		RenewLockAt:  int64(m.RenewLockAt),
		Deleted:      m.Deleted,
		DeletedAt:    int64(m.DeletedAt),
		Status:       cert.CertStatus(m.Status),
		Source:       cert.CertSource(m.Source),
		LastSyncedAt: int64(m.LastSyncedAt),
		SyncError:    m.SyncError,
		Revision:     int(m.Revision),
		Renewing:     m.Renewing,
		LastIssuedAt: int64(m.LastIssuedAt),
		AcmeOrderURL: m.AcmeOrderURL,
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
	m.RenewLockAt = uint64(c.RenewLockAt)
	m.Deleted = c.Deleted
	m.DeletedAt = uint64(c.DeletedAt)
	m.Status = string(c.Status)
	m.Source = string(c.Source)
	m.LastSyncedAt = uint64(c.LastSyncedAt)
	m.SyncError = c.SyncError
	m.Revision = uint(c.Revision)
	m.Renewing = c.Renewing
	m.LastIssuedAt = uint64(c.LastIssuedAt)
	m.AcmeOrderURL = c.AcmeOrderURL
	// SNIs 转换
	if len(c.SNIs) > 0 {
		m.SNIs = toJSONArray(c.SNIs)
	}
}

// TaskModel 任务记录模型
type TaskModel struct {
	ID        uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	Domain    string `gorm:"type:varchar(255);index" json:"domain"`
	Status    string `gorm:"type:varchar(32);default:'';index" json:"status"`
	Error     string `gorm:"type:text" json:"error"`
	CreatedAt uint64 `gorm:"type:bigint unsigned;default:0" json:"created_at"`
	UpdatedAt uint64 `gorm:"type:bigint unsigned;default:0;index" json:"updated_at"`
}

func (TaskModel) TableName() string {
	return "cert_tasks"
}

func (m *TaskModel) ToDomain() *task.TaskRecord {
	return &task.TaskRecord{
		ID:        int(m.ID),
		Domain:    m.Domain,
		Status:    m.Status,
		Error:     m.Error,
		CreatedAt: int64(m.CreatedAt),
		UpdatedAt: int64(m.UpdatedAt),
	}
}

func (m *TaskModel) FromDomain(t *task.TaskRecord) {
	m.ID = uint(t.ID)
	m.Domain = t.Domain
	m.Status = t.Status
	m.Error = t.Error
	m.CreatedAt = uint64(t.CreatedAt)
	m.UpdatedAt = uint64(t.UpdatedAt)
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

// SyncStateModel 同步状态模型
type SyncStateModel struct {
	ID            uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	LastSyncTime  uint64 `gorm:"type:bigint unsigned;default:0" json:"last_sync_time"`
	FirstSyncDone bool   `gorm:"type:tinyint(1);default:0" json:"first_sync_done"`
}

func (SyncStateModel) TableName() string {
	return "cert_sync_states"
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
