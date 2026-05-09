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
	// MarkDeleted 标记为删除中
	MarkDeleted(domain string) error
	// RestoreDeleted 恢复已删除的证书
	RestoreDeleted(domain string) error
	// SetRenewing 设置证书续期中标志
	SetRenewing(domain string, renewing bool, orderURL string) error
	// UpdateCertSyncState 更新同步状态
	UpdateCertSyncState(domain string, status CertStatus, syncErr string) error
	// LockRenew 锁定续期
	LockRenew(domain string) (bool, error)
	// UnlockRenew 解锁续期
	UnlockRenew(domain string) error
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

// SyncStateRepository 同步状态存储接口
type SyncStateRepository interface {
	// GetLastSyncTime 获取最后同步时间
	GetLastSyncTime() (syncTime int64, firstSyncDone bool)
	// SetLastSyncTime 设置最后同步时间
	SetLastSyncTime(syncTime int64, firstSyncDone bool) error
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