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
		CertID:       int(model.ID),
		Revision:     int64(newRevision),
		NotBefore:    metadata.NotBefore,
		NotAfter:     metadata.NotAfter,
		Fingerprint:  metadata.Fingerprint,
		SerialNumber: metadata.SerialNumber,
		CreatedAt:    int64(now),
	}

	var versionModel VersionModel
	versionModel.FromVersion(version)
	versionModel.CertPEM = []byte(certPEM)
	versionModel.PrivateKeyPEM = []byte(keyPEM)
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

// ImportCertContent 导入指定 revision 的证书内容，不额外递增版本号。
func (r *CertRepo) ImportCertContent(domain string, revision int64, certPEM, keyPEM string) error {
	if revision <= 0 {
		revision = 1
	}

	var model CertModel
	err := r.db.Where("domain = ? AND deleted = ?", domain, false).First(&model).Error
	if err != nil {
		return fmt.Errorf("查询证书失败：%w", err)
	}

	metadata, err := cert.ParseCertMetadata(certPEM)
	if err != nil {
		return fmt.Errorf("解析证书失败：%w", err)
	}

	tx := r.db.Begin()
	if tx.Error != nil {
		return fmt.Errorf("开启事务失败：%w", tx.Error)
	}

	var versionModel VersionModel
	err = tx.Where("cert_id = ? AND revision = ?", model.ID, revision).First(&versionModel).Error
	switch err {
	case nil:
		versionModel.CertPEM = []byte(certPEM)
		versionModel.PrivateKeyPEM = []byte(keyPEM)
		versionModel.NotBefore = uint64(metadata.NotBefore)
		versionModel.NotAfter = uint64(metadata.NotAfter)
		versionModel.Fingerprint = metadata.Fingerprint
		versionModel.SerialNumber = metadata.SerialNumber
		if err := tx.Save(&versionModel).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("更新版本记录失败：%w", err)
		}
	case gorm.ErrRecordNotFound:
		version := &cert.CertVersion{
			CertID:       int(model.ID),
			Revision:     revision,
			NotBefore:    metadata.NotBefore,
			NotAfter:     metadata.NotAfter,
			Fingerprint:  metadata.Fingerprint,
			SerialNumber: metadata.SerialNumber,
			CreatedAt:    int64(TimeNow()),
		}
		versionModel = VersionModel{}
		versionModel.FromVersion(version)
		versionModel.CertPEM = []byte(certPEM)
		versionModel.PrivateKeyPEM = []byte(keyPEM)
		if err := tx.Create(&versionModel).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("创建版本记录失败：%w", err)
		}
	default:
		tx.Rollback()
		return fmt.Errorf("查询版本记录失败：%w", err)
	}

	updates := map[string]interface{}{
		"current_revision": revision,
		"not_before":       metadata.NotBefore,
		"not_after":        metadata.NotAfter,
		"fingerprint":      metadata.Fingerprint,
		"serial_number":    metadata.SerialNumber,
	}
	if err := tx.Model(&CertModel{}).Where("id = ?", model.ID).Updates(updates).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("更新证书元数据失败：%w", err)
	}

	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("提交事务失败：%w", err)
	}

	logger.Log.Info("证书内容已导入版本表", "domain", domain, "revision", revision)
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

func (r *CertRepo) GetLatestVersionContent(domain string) (*VersionModel, bool) {
	var certModel CertModel
	err := r.db.Where("domain = ? AND deleted = ?", domain, false).First(&certModel).Error
	if err != nil {
		return nil, false
	}

	var versionModel VersionModel
	err = r.db.Where("cert_id = ?", certModel.ID).Order("revision DESC").First(&versionModel).Error
	if err != nil {
		return nil, false
	}
	return &versionModel, true
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
		if c.Source == "" {
			c.Source = cert.CertSource(existing.Source)
		}
		if c.LifecycleStatus == "" {
			c.LifecycleStatus = cert.LifecycleStatus(existing.LifecycleStatus)
		}
		if c.SyncStatus == "" {
			c.SyncStatus = cert.SyncStatus(existing.SyncStatus)
		}
		if c.ChallengeZone == "" {
			c.ChallengeZone = existing.ChallengeZone
		}
		if c.SyncZones == nil && existing.SyncZones != "" && existing.SyncZones != "[]" {
			var syncZones []string
			parseJSONArray(existing.SyncZones, &syncZones)
			c.SyncZones = syncZones
		}
		if c.Revision == 0 {
			c.Revision = int64(existing.CurrentRevision) + 1
		}
	} else if err == gorm.ErrRecordNotFound {
		// 不存在，创建
		if c.CreatedAt == 0 {
			c.CreatedAt = int64(now)
		}
		if c.Source == "" {
			c.Source = cert.CertSourceManaged
		}
		if c.Revision == 0 {
			c.Revision = 1
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
	logger.Log.Info("证书已保存", "domain", c.Domain, "revision", c.Revision)
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
	for i := range models {
		result = append(result, models[i].ToDomain())
	}
	return result, nil
}

func (r *CertRepo) MarkDeleting(domain string) error {
	now := TimeNow()
	err := r.db.Model(&CertModel{}).Where("domain = ? AND deleted = ?", domain, false).Updates(map[string]interface{}{
		"updated_at":       now,
		"lifecycle_status": string(cert.LifecycleDeleting),
		"sync_status":      string(cert.SyncSyncing),
		"sync_error":       "",
	}).Error
	if err != nil {
		return fmt.Errorf("标记删除中失败：%w", err)
	}
	logger.Log.Info("证书已标记删除中", "domain", domain)
	return nil
}

func (r *CertRepo) MarkDeleted(domain string) error {
	now := TimeNow()
	err := r.db.Model(&CertModel{}).Where("domain = ?", domain).Updates(map[string]interface{}{
		"deleted":          true,
		"deleted_at":       now,
		"updated_at":       now,
		"lifecycle_status": string(cert.LifecycleDeleted),
		"sync_status":      string(cert.SyncSynced),
		"sync_error":       "",
		"last_synced_at":   now,
	}).Error
	if err != nil {
		return fmt.Errorf("标记删除完成失败：%w", err)
	}
	logger.Log.Info("证书已标记删除完成", "domain", domain)
	return nil
}

func (r *CertRepo) RestoreDeleted(domain string) error {
	err := r.db.Model(&CertModel{}).Where("domain = ? AND deleted = ?", domain, true).Updates(map[string]interface{}{
		"deleted":          false,
		"deleted_at":       0,
		"updated_at":       TimeNow(),
		"lifecycle_status": string(cert.LifecycleActive),
		"sync_status":      string(cert.SyncDrifted),
	}).Error
	if err != nil {
		return fmt.Errorf("恢复证书失败：%w", err)
	}
	logger.Log.Info("证书已恢复", "domain", domain)
	return nil
}

// ClaimIssue 原子领取待签发证书。
func (r *CertRepo) ClaimIssue(domain string) (bool, error) {
	now := TimeNow()
	result := r.db.Model(&CertModel{}).
		Where("domain = ? AND deleted = ? AND issue_status IN ?",
			domain, false, []string{string(cert.IssuePending), string(cert.IssueFailed)}).
		Updates(map[string]interface{}{
			"issue_status": string(cert.IssueIssuing),
			"updated_at":   now,
		})

	if result.Error != nil {
		return false, fmt.Errorf("领取签发任务失败：%w", result.Error)
	}
	return result.RowsAffected > 0, nil
}

// UpdateIssueStatus 更新签发状态
func (r *CertRepo) UpdateIssueStatus(domain string, status cert.IssueStatus) error {
	now := TimeNow()
	updates := map[string]interface{}{
		"issue_status": string(status),
		"updated_at":   now,
	}
	err := r.db.Model(&CertModel{}).Where("domain = ?", domain).Updates(updates).Error
	if err != nil {
		return fmt.Errorf("更新签发状态失败：%w", err)
	}
	return nil
}

func (r *CertRepo) UpdateCertSyncState(domain string, status cert.SyncStatus, syncErr string) error {
	now := TimeNow()
	updates := map[string]interface{}{
		"sync_status": string(status),
		"sync_error":  syncErr,
		"updated_at":  now,
	}
	if status == cert.SyncSynced {
		updates["last_synced_at"] = now
	}

	err := r.db.Model(&CertModel{}).Where("domain = ?", domain).Updates(updates).Error
	if err != nil {
		return fmt.Errorf("更新证书同步状态失败：%w", err)
	}
	return nil
}

// UpdateRouting 更新证书的 Agent 路由策略
func (r *CertRepo) UpdateRouting(domain string, challengeZone string, syncZones []string) error {
	updates := map[string]interface{}{
		"challenge_zone": challengeZone,
		"sync_zones":     toJSONArray(syncZones),
		"updated_at":     TimeNow(),
	}
	err := r.db.Model(&CertModel{}).Where("domain = ? AND deleted = ?", domain, false).Updates(updates).Error
	if err != nil {
		return fmt.Errorf("更新证书路由策略失败：%w", err)
	}
	return nil
}

// FindByIssueStatus 查找指定签发状态的证书
func (r *CertRepo) FindByIssueStatus(statuses []cert.IssueStatus) ([]*cert.Certificate, error) {
	var models []CertModel
	err := r.db.Where("issue_status IN ? AND deleted = ?", statuses, false).Find(&models).Error
	if err != nil {
		return nil, fmt.Errorf("查询签发状态失败：%w", err)
	}
	result := make([]*cert.Certificate, 0, len(models))
	for _, m := range models {
		result = append(result, m.ToDomain())
	}
	return result, nil
}

// FindBySyncStatus 查找指定同步状态的证书（且 issue_status=idle）
func (r *CertRepo) FindBySyncStatus(statuses []cert.SyncStatus) ([]*cert.Certificate, error) {
	var models []CertModel
	err := r.db.Where("sync_status IN ? AND issue_status = ? AND deleted = ?", statuses, string(cert.IssueIdle), false).Find(&models).Error
	if err != nil {
		return nil, fmt.Errorf("查询同步状态失败：%w", err)
	}
	result := make([]*cert.Certificate, 0, len(models))
	for _, m := range models {
		result = append(result, m.ToDomain())
	}
	return result, nil
}

func (r *CertRepo) Close() error {
	return nil
}

// UpdateRetryState 更新重试状态
func (r *CertRepo) UpdateRetryState(domain string, retryCount int, nextRetryAt int64, issueStatus cert.IssueStatus, errMsg string) error {
	now := TimeNow()
	updates := map[string]interface{}{
		"retry_count":   retryCount,
		"next_retry_at": nextRetryAt,
		"issue_status":  string(issueStatus),
		"sync_error":    errMsg,
		"updated_at":    now,
	}
	err := r.db.Model(&CertModel{}).Where("domain = ?", domain).Updates(updates).Error
	if err != nil {
		return fmt.Errorf("更新重试状态失败：%w", err)
	}
	return nil
}

func (r *CertRepo) MarkRetryPendingIfDue(domain string, now int64) (bool, error) {
	result := r.db.Model(&CertModel{}).
		Where("domain = ? AND deleted = ? AND issue_status = ? AND next_retry_at > 0 AND next_retry_at <= ?",
			domain, false, string(cert.IssueFailed), now).
		Updates(map[string]interface{}{
			"issue_status": string(cert.IssuePending),
			"updated_at":   uint64(now),
		})
	if result.Error != nil {
		return false, fmt.Errorf("标记重试 pending 失败：%w", result.Error)
	}
	return result.RowsAffected > 0, nil
}

func (r *CertRepo) ClearRetryState(domain string) error {
	err := r.db.Model(&CertModel{}).Where("domain = ?", domain).Updates(map[string]interface{}{
		"retry_count":   0,
		"next_retry_at": 0,
		"sync_error":    "",
		"updated_at":    TimeNow(),
	}).Error
	if err != nil {
		return fmt.Errorf("清空重试状态失败：%w", err)
	}
	return nil
}

// FindRetryReady 查找已到重试时间的 failed 证书
func (r *CertRepo) FindRetryReady(now int64) ([]*cert.Certificate, error) {
	var models []CertModel
	err := r.db.Where("issue_status = ? AND next_retry_at > 0 AND next_retry_at <= ? AND deleted = ?",
		string(cert.IssueFailed), now, false).Find(&models).Error
	if err != nil {
		return nil, fmt.Errorf("查询待重试证书失败：%w", err)
	}
	result := make([]*cert.Certificate, 0, len(models))
	for _, m := range models {
		result = append(result, m.ToDomain())
	}
	return result, nil
}

// FindRetryPending 查找所有处于重试等待中的 failed 证书（含未到期）
func (r *CertRepo) FindRetryPending() ([]*cert.Certificate, error) {
	var models []CertModel
	err := r.db.Where("issue_status = ? AND next_retry_at > 0 AND deleted = ?",
		string(cert.IssueFailed), false).Find(&models).Error
	if err != nil {
		return nil, fmt.Errorf("查询重试等待中证书失败：%w", err)
	}
	result := make([]*cert.Certificate, 0, len(models))
	for _, m := range models {
		result = append(result, m.ToDomain())
	}
	return result, nil
}
