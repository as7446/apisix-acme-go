package repository

import (
	"github.com/as7446/apisix-acme-go/internal/domain/cert"
	"github.com/as7446/apisix-acme-go/internal/domain/task"
)

// CertRepository 证书存储接口
type CertRepository interface {
	// Get 获取证书元数据（不含已删除）
	Get(domain string) (*cert.Certificate, bool)
	// GetWithDeleted 获取证书元数据（含已删除）
	GetWithDeleted(domain string) (*cert.Certificate, bool)
	// GetByAPISIXID 按 APISIX SSL ID 查询证书
	GetByAPISIXID(apisixID string) (*cert.Certificate, bool)
	// Upsert 创建或更新证书元数据
	Upsert(c *cert.Certificate) error
	// All 获取所有证书
	All() ([]*cert.Certificate, error)
	// FindNeedRenew 查找需要续期的证书
	FindNeedRenew(renewBeforeDays int) ([]*cert.Certificate, error)
	// MarkDeleted 标记为删除中
	MarkDeleted(domain string) error
	// RestoreDeleted 恢复已删除的证书
	RestoreDeleted(domain string) error
	// SetRenewing 设置证书续期中标志
	SetRenewing(domain string, renewing bool, orderURL string) error
	// UpdateCertSyncState 更新同步状态
	UpdateCertSyncState(domain string, status cert.CertStatus, syncErr string) error
	// LockRenew 锁定续期
	LockRenew(domain string) (bool, error)
	// UnlockRenew 解锁续期
	UnlockRenew(domain string) error
	// Close 关闭存储连接
	Close() error
}

// TaskRepository 任务存储接口
type TaskRepository interface {
	// SaveTask 保存任务记录
	SaveTask(domain string, status string, errMsg string) error
	// GetTaskRecord 获取任务记录
	GetTaskRecord(domain string) (*task.TaskRecord, bool)
	// CleanupTasks 清理过期任务记录
	CleanupTasks(retentionHours int) error
}
