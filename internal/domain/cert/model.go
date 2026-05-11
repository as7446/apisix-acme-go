package cert

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
)

// CertStatus 证书同步状态枚举
type CertStatus string

const (
	CertStatusPending    CertStatus = "pending"
	CertStatusIssued     CertStatus = "issued"
	CertStatusRenewing   CertStatus = "renewing"
	CertStatusSyncFailed CertStatus = "sync_failed"
	CertStatusDeleting   CertStatus = "deleting"
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
	SNIs            []string
	NotBefore       int64
	NotAfter        int64
	APISIXID        string
	Fingerprint     string
	SerialNumber    string
	CreatedAt       int64
	UpdatedAt       int64
	LastRenewAt     int64
	RenewLockAt     int64
	Deleted         bool
	DeletedAt       int64
	Status          CertStatus
	Source          CertSource
	LastSyncedAt    int64
	SyncError       string
	CurrentRevision int // 当前生效版本
	Renewing        bool
	LastIssuedAt    int64
	AcmeOrderURL    string
}

// CertVersion 证书版本（存储 PEM/KEY）
type CertVersion struct {
	ID            int
	CertID        int
	Revision      int
	CertPEM       string
	PrivateKeyPEM string
	NotBefore     int64
	NotAfter      int64
	Fingerprint   string
	SerialNumber  string
	AcmeOrderURL  string
	CreatedAt     int64
}

// EffectiveStatus 兼容旧记录（Status 为空时按 Deleted 字段推断）
func (c *Certificate) EffectiveStatus() CertStatus {
	if c.Status != "" {
		return c.Status
	}
	if c.Deleted {
		return CertStatusDeleting
	}
	return CertStatusIssued
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
