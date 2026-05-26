package cert

// CertRepository 证书存储抽象接口
type CertRepository interface {
	// Get 获取证书元数据（不含已删除）
	Get(domain string) (*Certificate, bool)
	// GetWithDeleted 获取证书元数据（含已删除）
	GetWithDeleted(domain string) (*Certificate, bool)
	// GetByAPISIXID 按 APISIX SSL ID 查询证书
	GetByAPISIXID(apisixID string) (*Certificate, bool)
	// Upsert 创建或更新证书元数据
	Upsert(cert *Certificate) error
	// All 获取所有证书
	All() ([]*Certificate, error)
	// FindNeedRenew 查找需要续期的证书
	FindNeedRenew(renewBeforeDays int) ([]*Certificate, error)
	// MarkDeleting 标记证书进入删除中
	MarkDeleting(domain string) error
	// MarkDeleted 标记证书删除完成
	MarkDeleted(domain string) error
	// RestoreDeleted 恢复已删除的证书
	RestoreDeleted(domain string) error
	// ClaimIssue 原子领取一个待签发证书，成功后 issue_status=issuing
	ClaimIssue(domain string) (bool, error)
	// UpdateIssueStatus 更新签发状态
	UpdateIssueStatus(domain string, status IssueStatus) error
	// UpdateCertSyncState 更新同步状态
	UpdateCertSyncState(domain string, status SyncStatus, syncErr string) error
	// UpdateRouting 更新证书的 Agent 路由策略
	UpdateRouting(domain string, challengeZone string, syncZones []string) error
	// FindByIssueStatus 查找指定签发状态的证书
	FindByIssueStatus(statuses []IssueStatus) ([]*Certificate, error)
	// FindBySyncStatus 查找指定同步状态的证书（且 issue_status=idle）
	FindBySyncStatus(statuses []SyncStatus) ([]*Certificate, error)
	// UpdateRetryState 更新重试状态
	UpdateRetryState(domain string, retryCount int, nextRetryAt int64, issueStatus IssueStatus, errMsg string) error
	// FindRetryReady 查找已到重试时间的 failed 证书
	FindRetryReady(now int64) ([]*Certificate, error)
	// FindRetryPending 查找所有处于重试等待中的 failed 证书（含未到期）
	FindRetryPending() ([]*Certificate, error)
	// Close 关闭存储连接
	Close() error
}

// CertCache 证书文件缓存接口
type CertCache interface {
	// Get 获取缓存的证书
	Get(domain string) (*CachedCert, bool)
	// Put 保存证书到缓存
	Put(domain, certPEM, keyPEM string, notBefore, notAfter int64) error
	// Remove 删除缓存
	Remove(domain string) error
	// GetCertPath 获取证书文件路径
	GetCertPath(domain string) string
	// GetKeyPath 获取私钥文件路径
	GetKeyPath(domain string) string
	// Load 加载缓存
	Load() error
}

// AcmeAccount ACME 账户信息
type AcmeAccount struct {
	Email        string
	PrivateKey   []byte
	Registration []byte // JSON encoded registration resource
	CreatedAt    int64
}

// AccountRepository ACME 账户存储接口
type AccountRepository interface {
	// GetAccount 获取账户
	GetAccount(email string) (*AcmeAccount, error)
	// SaveAccount 保存账户
	SaveAccount(account *AcmeAccount) error
}
