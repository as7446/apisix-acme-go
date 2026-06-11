package cert

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
)

/*
	LifecycleStatus：这个证书资源还管不管。
	IssueStatus：证书有没有在签发，以及签发到哪一步。
	SyncStatus：证书有没有同步到目标网关，以及是否一致。
*/
// LifecycleStatus - 证书生命周期状态
type LifecycleStatus string

const (
	LifecycleActive   LifecycleStatus = "active"
	LifecycleExpired  LifecycleStatus = "expired"
	LifecycleRevoked  LifecycleStatus = "revoked"
	LifecycleDeleting LifecycleStatus = "deleting"
	LifecycleDeleted  LifecycleStatus = "deleted"
)

// IssueStatus - 签发任务状态
type IssueStatus string

const (
	IssueIdle    IssueStatus = "idle"
	IssuePending IssueStatus = "pending"
	IssueIssuing IssueStatus = "issuing"
	IssueFailed  IssueStatus = "failed"

	// Controller+Agent FSM 扩展状态
	IssueChallengeInjecting IssueStatus = "challenge_injecting" // 等待 Agent 注入验证路由
	IssueChallengeReady     IssueStatus = "challenge_ready"     // Agent 已注入验证路由
	IssueAcmeVerifying      IssueStatus = "acme_verifying"      // ACME 验证+获取证书中
	IssueIssued             IssueStatus = "issued"              // 证书已获取，待同步
	IssueSyncDispatched     IssueStatus = "sync_dispatched"     // 同步任务已派发给 Agent
)

// SyncStatus - APISIX 同步状态
type SyncStatus string

const (
	SyncUnknown SyncStatus = "unknown"
	SyncDrifted SyncStatus = "drifted"
	SyncSyncing SyncStatus = "syncing"
	SyncSynced  SyncStatus = "synced"
	SyncFailed  SyncStatus = "failed"
)

// CertSource 证书来源
type CertSource string

const (
	CertSourceManaged  CertSource = "managed"
	CertSourceExternal CertSource = "external"
)

// Certificate 证书元数据
type Certificate struct {
	ID              int
	Domain          string
	APISIXID        string
	Revision        int64      // 真正递增的版本号
	Source          CertSource // managed / external
	LifecycleStatus LifecycleStatus
	IssueStatus     IssueStatus
	SyncStatus      SyncStatus
	Fingerprint     string // 从 storage cert 计算
	SerialNumber    string
	NotBefore       int64
	NotAfter        int64
	LastIssuedAt    int64
	LastRenewAt     int64
	LastSyncedAt    int64
	CreatedAt       int64
	UpdatedAt       int64
	ErrorMessage    string
	// 删除标记
	Deleted bool
	// 重试控制
	RetryCount  int   // 当前重试次数（达到 max 后进入冷却期并重置为 0）
	NextRetryAt int64 // 下次可重试时间 (unix timestamp, 0=可立即重试)
	// 多 Zone 支持
	ChallengeZone string   // HTTP-01 验证由哪个 zone 的 Agent 处理
	SyncZones     []string // 需要同步的 zone 列表（空=所有在线 Agent）
}

// CertVersion 证书版本（不再存储 PEM/KEY，PEM 存于 CertStorage）
type CertVersion struct {
	ID           int
	CertID       int
	Revision     int64
	Fingerprint  string
	SerialNumber string
	NotBefore    int64
	NotAfter     int64
	CreatedAt    int64
}

// CertStorage 证书 PEM/KEY 存储接口（不再存 DB，存独立存储）
type CertStorage interface {
	GetCertPEM(domain string) (string, error)
	GetKeyPEM(domain string) (string, error)
	Save(domain, certPEM, keyPEM string) error
	Delete(domain string) error
	Exists(domain string) bool
}

// CertMetadata 证书解析后的元数据
type CertMetadata struct {
	Fingerprint  string
	SerialNumber string
	NotBefore    int64
	NotAfter     int64
}

// ParseCertMetadata 一次性解析证书 PEM 并返回指纹、序列号和有效期
func ParseCertMetadata(certPEM string) (*CertMetadata, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("无效的 PEM 格式")
	}

	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析证书失败：%w", err)
	}

	hash := sha256.Sum256(c.Raw)
	return &CertMetadata{
		Fingerprint:  hex.EncodeToString(hash[:]),
		SerialNumber: c.SerialNumber.String(),
		NotBefore:    c.NotBefore.Unix(),
		NotAfter:     c.NotAfter.Unix(),
	}, nil
}

// CalculateFingerprint 计算证书指纹
func CalculateFingerprint(certPEM string) (string, error) {
	m, err := ParseCertMetadata(certPEM)
	if err != nil {
		return "", err
	}
	return m.Fingerprint, nil
}

// CalculateSerialNumber 计算证书序列号
func CalculateSerialNumber(certPEM string) (string, error) {
	m, err := ParseCertMetadata(certPEM)
	if err != nil {
		return "", err
	}
	return m.SerialNumber, nil
}

// NormalizeAPISIXID 将通配符域名转为 APISIX 侧安全 ID（如 *.example.com → wildcard.example.com）
func NormalizeAPISIXID(domain string) string {
	return strings.ReplaceAll(domain, "*.", "wildcard.")
}

// CachedCert 缓存的证书文件内容
type CachedCert struct {
	Domain    string
	CertPEM   string
	KeyPEM    string
	NotBefore int64
	NotAfter  int64
}

// ApisixSSLObject APISIX SSL 对象（用于 sync 模块）
type ApisixSSLObject struct {
	ID         string            `json:"id,omitempty"`
	SNIs       []string          `json:"snis"`
	Cert       string            `json:"cert"`
	Key        string            `json:"key"`
	Labels     map[string]string `json:"labels,omitempty"`
	UpdateTime int64             `json:"update_time,omitempty"`
}
