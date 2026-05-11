package gorm

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/as7446/apisix-acme-go/internal/domain/cert"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
)

// CertRepo GORM 实现的 CertRepository
type CertRepo struct {
	db *gorm.DB
}

// NewCertRepo 创建 CertRepo
func NewCertRepo(db *gorm.DB) *CertRepo {
	return &CertRepo{db: db}
}

// WriteCertContent 写入证书内容到版本表
func (r *CertRepo) WriteCertContent(domain string, certPEM, keyPEM string) error {
	// 查询证书
	var model CertModel
	err := r.db.Where("domain = ? AND deleted = ?", domain, false).First(&model).Error
	if err != nil {
		return fmt.Errorf("查询证书失败：%w", err)
	}

	// 解析证书获取元数据
	metadata, err := cert.ParseCertMetadata(certPEM)
	if err != nil {
		return fmt.Errorf("解析证书失败：%w", err)
	}

	now := TimeNow()
	newRevision := model.CurrentRevision + 1

	// 开启事务
	tx := r.db.Begin()

	// 创建版本记录
	version := &cert.CertVersion{
		CertID:        int(model.ID),
		Revision:      int(newRevision),
		CertPEM:       certPEM,
		PrivateKeyPEM: keyPEM,
		NotBefore:     metadata.NotBefore,
		NotAfter:      metadata.NotAfter,
		Fingerprint:   metadata.Fingerprint,
		SerialNumber:  metadata.SerialNumber,
		CreatedAt:     int64(now),
	}

	var versionModel VersionModel
	versionModel.FromVersion(version)
	if err := tx.Create(&versionModel).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("创建版本记录失败：%w", err)
	}
	version.ID = int(versionModel.ID)

	// 更新证书元数据
	updates := map[string]interface{}{
		"current_revision": newRevision,
		"not_before":       metadata.NotBefore,
		"not_after":        metadata.NotAfter,
		"fingerprint":      metadata.Fingerprint,
		"serial_number":    metadata.SerialNumber,
		"updated_at":       now,
	}
	if err := tx.Model(&CertModel{}).Where("id = ?", model.ID).Updates(updates).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("更新证书元数据失败：%w", err)
	}

	tx.Commit()
	logger.Log.Info("证书内容已写入版本表", "domain", domain, "revision", newRevision)
	return nil
}

// GetVersion 获取证书指定版本内容
func (r *CertRepo) GetVersion(domain string, revision int) (*cert.CertVersion, bool) {
	var certModel CertModel
	err := r.db.Where("domain = ? AND deleted = ?", domain, false).First(&certModel).Error
	if err != nil {
		return nil, false
	}

	var versionModel VersionModel
	err = r.db.Where("cert_id = ? AND revision = ?", certModel.ID, revision).First(&versionModel).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, false
		}
		return nil, false
	}
	return versionModel.ToVersion(), true
}

// GetLatestVersion 获取证书最新版本
func (r *CertRepo) GetLatestVersion(domain string) (*cert.CertVersion, bool) {
	var certModel CertModel
	err := r.db.Where("domain = ? AND deleted = ?", domain, false).First(&certModel).Error
	if err != nil {
		return nil, false
	}

	var versionModel VersionModel
	err = r.db.Where("cert_id = ?", certModel.ID).Order("revision DESC").First(&versionModel).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, false
		}
		return nil, false
	}
	return versionModel.ToVersion(), true
}

// HasVersionContent 检查证书是否有版本内容
func (r *CertRepo) HasVersionContent(domain string) bool {
	var certModel CertModel
	err := r.db.Where("domain = ? AND deleted = ?", domain, false).First(&certModel).Error
	if err != nil {
		return false
	}

	var count int64
	r.db.Model(&VersionModel{}).Where("cert_id = ?", certModel.ID).Count(&count)
	return count > 0
}

func (r *CertRepo) Get(domain string) (*cert.Certificate, bool) {
	var model CertModel
	err := r.db.Where("domain = ? AND deleted = ?", domain, false).First(&model).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, false
		}
		logger.Log.Error("查询证书失败", "domain", domain, "error", err)
		return nil, false
	}
	return model.ToDomain(), true
}

func (r *CertRepo) GetWithDeleted(domain string) (*cert.Certificate, bool) {
	var model CertModel
	err := r.db.Where("domain = ?", domain).First(&model).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, false
		}
		logger.Log.Error("查询证书（含已删除）失败", "domain", domain, "error", err)
		return nil, false
	}
	return model.ToDomain(), true
}

func (r *CertRepo) GetByAPISIXID(apisixID string) (*cert.Certificate, bool) {
	var model CertModel
	err := r.db.Where("apisix_id = ?", apisixID).First(&model).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, false
		}
		return nil, false
	}
	return model.ToDomain(), true
}

func (r *CertRepo) Upsert(c *cert.Certificate) error {
	now := TimeNow()

	// 查询是否存在
	var existing CertModel
	err := r.db.Where("domain = ?", c.Domain).First(&existing).Error

	if err == nil {
		// 存在，更新
		c.ID = int(existing.ID)
		if c.CreatedAt == 0 {
			c.CreatedAt = int64(existing.CreatedAt)
		}
		if !c.Deleted && existing.Deleted {
			c.DeletedAt = 0
		}
		if c.Source == "" {
			c.Source = cert.CertSource(existing.Source)
		}
		if c.CurrentRevision <= int(existing.CurrentRevision) {
			c.CurrentRevision = int(existing.CurrentRevision) + 1
		}
	} else if err == gorm.ErrRecordNotFound {
		// 不存在，创建
		if c.CreatedAt == 0 {
			c.CreatedAt = int64(now)
		}
		if c.Source == "" {
			c.Source = cert.CertSourceManaged
		}
		if c.CurrentRevision == 0 {
			c.CurrentRevision = 1
		}
	} else {
		return fmt.Errorf("查询证书失败：%w", err)
	}

	c.UpdatedAt = int64(now)

	var model CertModel
	model.FromDomain(c)

	if err := r.db.Save(&model).Error; err != nil {
		return fmt.Errorf("保存证书失败：%w", err)
	}

	c.ID = int(model.ID)
	logger.Log.Info("证书已保存", "domain", c.Domain, "revision", c.CurrentRevision)
	return nil
}

func (r *CertRepo) All() ([]*cert.Certificate, error) {
	var models []CertModel
	err := r.db.Find(&models).Error
	if err != nil {
		return nil, fmt.Errorf("查询所有证书失败：%w", err)
	}

	result := make([]*cert.Certificate, 0, len(models))
	for i := range models {
		result = append(result, models[i].ToDomain())
	}
	return result, nil
}

func (r *CertRepo) FindNeedRenew(renewBeforeDays int) ([]*cert.Certificate, error) {
	now := TimeNow()
	threshold := now + uint64(renewBeforeDays*24*3600)

	var models []CertModel
	err := r.db.Where("deleted = ? AND not_after <= ?", false, threshold).Find(&models).Error
	if err != nil {
		return nil, fmt.Errorf("查询需要续期的证书失败：%w", err)
	}

	result := make([]*cert.Certificate, 0)
	renewLockTimeout := uint64(3600) // 1小时
	for i := range models {
		cert := models[i].ToDomain()
		// 检查锁是否有效
		if cert.RenewLockAt > 0 && int64(now)-cert.RenewLockAt < int64(renewLockTimeout) {
			continue
		}
		result = append(result, cert)
	}
	return result, nil
}

func (r *CertRepo) MarkDeleted(domain string) error {
	now := TimeNow()
	err := r.db.Model(&CertModel{}).Where("domain = ?", domain).Updates(map[string]interface{}{
		"deleted":    true,
		"deleted_at": now,
		"updated_at": now,
		"status":     cert.CertStatusDeleting,
	}).Error
	if err != nil {
		return fmt.Errorf("标记删除失败：%w", err)
	}
	logger.Log.Info("证书已标记删除", "domain", domain)
	return nil
}

func (r *CertRepo) RestoreDeleted(domain string) error {
	err := r.db.Model(&CertModel{}).Where("domain = ? AND deleted = ?", domain, true).Updates(map[string]interface{}{
		"deleted":    false,
		"deleted_at": 0,
		"updated_at": TimeNow(),
		"status":     cert.CertStatusPending,
	}).Error
	if err != nil {
		return fmt.Errorf("恢复证书失败：%w", err)
	}
	logger.Log.Info("证书已恢复", "domain", domain)
	return nil
}

func (r *CertRepo) SetRenewing(domain string, renewing bool, orderURL string) error {
	updates := map[string]interface{}{
		"renewing":   renewing,
		"updated_at": TimeNow(),
	}
	if orderURL != "" {
		updates["acme_order_url"] = orderURL
	}
	if renewing {
		updates["status"] = cert.CertStatusRenewing
	}

	err := r.db.Model(&CertModel{}).Where("domain = ?", domain).Updates(updates).Error
	if err != nil {
		return fmt.Errorf("设置续期状态失败：%w", err)
	}
	return nil
}

func (r *CertRepo) UpdateCertSyncState(domain string, status cert.CertStatus, syncErr string) error {
	now := TimeNow()
	updates := map[string]interface{}{
		"status":     status,
		"sync_error": syncErr,
		"updated_at": now,
	}
	if status == cert.CertStatusIssued {
		updates["last_synced_at"] = now
	}

	err := r.db.Model(&CertModel{}).Where("domain = ?", domain).Updates(updates).Error
	if err != nil {
		return fmt.Errorf("更新证书同步状态失败：%w", err)
	}
	return nil
}

func (r *CertRepo) LockRenew(domain string) (bool, error) {
	now := TimeNow()

	// 先查询当前状态
	var model CertModel
	err := r.db.Where("domain = ? AND deleted = ?", domain, false).First(&model).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, fmt.Errorf("证书不存在：%s", domain)
		}
		return false, fmt.Errorf("查询证书失败：%w", err)
	}

	// 检查锁是否有效
	if model.RenewLockAt > 0 && now-model.RenewLockAt < 3600 {
		return false, nil
	}

	// 设置锁
	err = r.db.Model(&CertModel{}).Where("domain = ?", domain).Updates(map[string]interface{}{
		"renew_lock_at": now,
		"updated_at":    now,
	}).Error
	if err != nil {
		return false, fmt.Errorf("锁定续期失败：%w", err)
	}
	logger.Log.Debug("续期已锁定", "domain", domain)
	return true, nil
}

func (r *CertRepo) UnlockRenew(domain string) error {
	err := r.db.Model(&CertModel{}).Where("domain = ?", domain).Updates(map[string]interface{}{
		"renew_lock_at": 0,
		"updated_at":    TimeNow(),
	}).Error
	if err != nil {
		return fmt.Errorf("解锁续期失败：%w", err)
	}
	logger.Log.Debug("续期已解锁", "domain", domain)
	return nil
}

func (r *CertRepo) Close() error {
	return nil
}
