package storm

import (
	"errors"
	"fmt"
	"time"

	stormdb "github.com/asdine/storm/v3"
	"github.com/asdine/storm/v3/q"

	"github.com/as7446/apisix-acme-go/internal/domain/cert"
	"github.com/as7446/apisix-acme-go/internal/infra/config"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
)

// certRecord Storm 存储层模型
type certRecord struct {
	ID           int             `storm:"id,increment"`
	Domain       string          `storm:"unique,index"`
	SNIs         []string        `storm:"index"`
	NotBefore    int64           `storm:"index"`
	NotAfter     int64           `storm:"index"`
	APISIXID     string          `storm:"index"`
	Fingerprint  string          `storm:"index"`
	SerialNumber string          `storm:"index"`
	CreatedAt    int64           `storm:"index"`
	UpdatedAt    int64           `storm:"index"`
	LastRenewAt  int64           `storm:"index"`
	RenewLockAt  int64           `storm:"index"`
	Deleted      bool            `storm:"index"`
	DeletedAt    int64           `storm:"index"`
	Status       cert.CertStatus `storm:"index"`
	Source       cert.CertSource `storm:"index"`
	LastSyncedAt int64           `storm:"index"`
	SyncError    string
	Revision     int   `storm:"index"`
	Renewing     bool  `storm:"index"`
	LastIssuedAt int64 `storm:"index"`
	AcmeOrderURL string
}

func toDomain(r *certRecord) *cert.Certificate {
	return &cert.Certificate{
		ID: r.ID, Domain: r.Domain, SNIs: r.SNIs,
		NotBefore: r.NotBefore, NotAfter: r.NotAfter,
		APISIXID: r.APISIXID, Fingerprint: r.Fingerprint,
		SerialNumber: r.SerialNumber, CreatedAt: r.CreatedAt,
		UpdatedAt: r.UpdatedAt, LastRenewAt: r.LastRenewAt,
		RenewLockAt: r.RenewLockAt, Deleted: r.Deleted,
		DeletedAt: r.DeletedAt, Status: r.Status, Source: r.Source,
		LastSyncedAt: r.LastSyncedAt, SyncError: r.SyncError,
		Revision: r.Revision, Renewing: r.Renewing,
		LastIssuedAt: r.LastIssuedAt, AcmeOrderURL: r.AcmeOrderURL,
	}
}

func toRecord(c *cert.Certificate) *certRecord {
	return &certRecord{
		ID: c.ID, Domain: c.Domain, SNIs: c.SNIs,
		NotBefore: c.NotBefore, NotAfter: c.NotAfter,
		APISIXID: c.APISIXID, Fingerprint: c.Fingerprint,
		SerialNumber: c.SerialNumber, CreatedAt: c.CreatedAt,
		UpdatedAt: c.UpdatedAt, LastRenewAt: c.LastRenewAt,
		RenewLockAt: c.RenewLockAt, Deleted: c.Deleted,
		DeletedAt: c.DeletedAt, Status: c.Status, Source: c.Source,
		LastSyncedAt: c.LastSyncedAt, SyncError: c.SyncError,
		Revision: c.Revision, Renewing: c.Renewing,
		LastIssuedAt: c.LastIssuedAt, AcmeOrderURL: c.AcmeOrderURL,
	}
}

// CertRepo Storm 实现的 CertRepository
type CertRepo struct {
	store *Store
}

// NewCertRepo 创建 CertRepo
func NewCertRepo(s *Store) *CertRepo {
	return &CertRepo{store: s}
}

func (r *CertRepo) Get(domain string) (*cert.Certificate, bool) {
	var rec certRecord
	err := r.store.DB.One("Domain", domain, &rec)
	if err != nil {
		if errors.Is(err, stormdb.ErrNotFound) {
			return nil, false
		}
		logger.Log.Error("查询证书元数据失败", "domain", domain, "error", err)
		return nil, false
	}
	if rec.Deleted {
		return nil, false
	}
	return toDomain(&rec), true
}

func (r *CertRepo) GetWithDeleted(domain string) (*cert.Certificate, bool) {
	var rec certRecord
	err := r.store.DB.One("Domain", domain, &rec)
	if err != nil {
		if errors.Is(err, stormdb.ErrNotFound) {
			return nil, false
		}
		logger.Log.Error("查询证书元数据失败", "domain", domain, "error", err)
		return nil, false
	}
	return toDomain(&rec), true
}

func (r *CertRepo) GetByAPISIXID(apisixID string) (*cert.Certificate, bool) {
	var recs []certRecord
	if err := r.store.DB.Find("APISIXID", apisixID, &recs); err != nil {
		return nil, false
	}
	if len(recs) == 0 {
		return nil, false
	}
	return toDomain(&recs[0]), true
}

func (r *CertRepo) Upsert(c *cert.Certificate) error {
	now := time.Now().Unix()

	existing, exists := r.GetWithDeleted(c.Domain)
	if exists {
		c.ID = existing.ID
		if c.CreatedAt == 0 {
			c.CreatedAt = existing.CreatedAt
		}
		if !c.Deleted && existing.Deleted {
			c.Deleted = false
			c.DeletedAt = 0
		}
		if c.Source == "" {
			c.Source = existing.Source
		}
		if c.Revision <= existing.Revision {
			c.Revision = existing.Revision + 1
		}
	} else {
		if c.CreatedAt == 0 {
			c.CreatedAt = now
		}
		if c.Source == "" {
			c.Source = cert.CertSourceManaged
		}
		if c.Revision == 0 {
			c.Revision = 1
		}
	}
	c.UpdatedAt = now

	rec := toRecord(c)
	if err := r.store.DB.Save(rec); err != nil {
		return fmt.Errorf("保存证书元数据失败：%w", err)
	}
	c.ID = rec.ID
	logger.Log.Info("证书元数据已保存", "domain", c.Domain, "fingerprint", c.Fingerprint, "revision", c.Revision)
	return nil
}

func (r *CertRepo) All() ([]*cert.Certificate, error) {
	var recs []certRecord
	err := r.store.DB.All(&recs)
	if err != nil && !errors.Is(err, stormdb.ErrNotFound) {
		return nil, fmt.Errorf("查询所有证书失败：%w", err)
	}
	result := make([]*cert.Certificate, 0, len(recs))
	for i := range recs {
		result = append(result, toDomain(&recs[i]))
	}
	return result, nil
}

func (r *CertRepo) FindNeedRenew(renewBeforeDays int) ([]*cert.Certificate, error) {
	now := time.Now().Unix()
	threshold := now + int64(renewBeforeDays*24*int(time.Hour/time.Second))

	var recs []certRecord
	err := r.store.DB.Select(q.Eq("Deleted", false)).Find(&recs)
	if err != nil && !errors.Is(err, stormdb.ErrNotFound) {
		return nil, fmt.Errorf("查询证书失败：%w", err)
	}

	result := make([]*cert.Certificate, 0)
	for i := range recs {
		if recs[i].NotAfter <= threshold {
			isLocked := recs[i].RenewLockAt > 0 && now-recs[i].RenewLockAt < config.RenewLockTimeout
			if !isLocked {
				result = append(result, toDomain(&recs[i]))
			}
		}
	}
	return result, nil
}

func (r *CertRepo) MarkDeleted(domain string) error {
	c, exists := r.GetWithDeleted(domain)
	if !exists {
		return fmt.Errorf("证书不存在：%s", domain)
	}
	c.Deleted = true
	c.DeletedAt = time.Now().Unix()
	c.UpdatedAt = time.Now().Unix()
	c.Status = cert.CertStatusDeleting
	rec := toRecord(c)
	if err := r.store.DB.Save(rec); err != nil {
		return fmt.Errorf("标记删除失败：%w", err)
	}
	logger.Log.Info("证书已标记删除", "domain", domain)
	return nil
}

func (r *CertRepo) RestoreDeleted(domain string) error {
	c, exists := r.GetWithDeleted(domain)
	if !exists {
		return fmt.Errorf("证书不存在：%s", domain)
	}
	if !c.Deleted {
		return nil
	}
	c.Deleted = false
	c.DeletedAt = 0
	c.UpdatedAt = time.Now().Unix()
	c.Status = cert.CertStatusPending
	rec := toRecord(c)
	if err := r.store.DB.Save(rec); err != nil {
		return fmt.Errorf("恢复证书失败：%w", err)
	}
	logger.Log.Info("证书已恢复", "domain", domain)
	return nil
}

func (r *CertRepo) SetRenewing(domain string, renewing bool, orderURL string) error {
	c, exists := r.GetWithDeleted(domain)
	if !exists {
		return fmt.Errorf("证书不存在：%s", domain)
	}
	c.Renewing = renewing
	c.AcmeOrderURL = orderURL
	if renewing {
		c.Status = cert.CertStatusRenewing
	}
	c.UpdatedAt = time.Now().Unix()
	rec := toRecord(c)
	if err := r.store.DB.Save(rec); err != nil {
		return fmt.Errorf("设置续期状态失败：%w", err)
	}
	return nil
}

func (r *CertRepo) UpdateCertSyncState(domain string, status cert.CertStatus, syncErr string) error {
	c, exists := r.GetWithDeleted(domain)
	if !exists {
		return fmt.Errorf("证书不存在：%s", domain)
	}
	now := time.Now().Unix()
	c.Status = status
	c.SyncError = syncErr
	if status == cert.CertStatusIssued {
		c.LastSyncedAt = now
	}
	c.UpdatedAt = now
	rec := toRecord(c)
	if err := r.store.DB.Save(rec); err != nil {
		return fmt.Errorf("更新证书同步状态失败：%w", err)
	}
	return nil
}

func (r *CertRepo) LockRenew(domain string) (bool, error) {
	r.store.RenewMu.Lock()
	defer r.store.RenewMu.Unlock()

	c, exists := r.Get(domain)
	if !exists {
		return false, fmt.Errorf("证书不存在：%s", domain)
	}
	now := time.Now().Unix()
	if c.RenewLockAt > 0 && now-c.RenewLockAt < config.RenewLockTimeout {
		return false, nil
	}
	c.RenewLockAt = now
	c.UpdatedAt = now
	rec := toRecord(c)
	if err := r.store.DB.Save(rec); err != nil {
		return false, fmt.Errorf("锁定续期失败：%w", err)
	}
	logger.Log.Debug("续期已锁定", "domain", domain)
	return true, nil
}

func (r *CertRepo) UnlockRenew(domain string) error {
	r.store.RenewMu.Lock()
	defer r.store.RenewMu.Unlock()

	c, exists := r.GetWithDeleted(domain)
	if !exists {
		return fmt.Errorf("证书不存在：%s", domain)
	}
	c.RenewLockAt = 0
	c.UpdatedAt = time.Now().Unix()
	rec := toRecord(c)
	if err := r.store.DB.Save(rec); err != nil {
		return fmt.Errorf("解锁续期失败：%w", err)
	}
	logger.Log.Debug("续期已解锁", "domain", domain)
	return nil
}

func (r *CertRepo) Close() error {
	return r.store.Close()
}
