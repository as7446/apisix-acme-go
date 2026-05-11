package gorm

import (
	"gorm.io/gorm"

	"github.com/as7446/apisix-acme-go/internal/domain/cert"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
)

// VersionRepo GORM 实现的版本仓库
type VersionRepo struct {
	db *gorm.DB
}

// NewVersionRepo 创建 VersionRepo
func NewVersionRepo(db *gorm.DB) *VersionRepo {
	return &VersionRepo{db: db}
}

// GetByCertAndRevision 获取指定版本的证书内容
func (r *VersionRepo) GetByCertAndRevision(certID, revision int) (*cert.CertVersion, bool) {
	var model VersionModel
	err := r.db.Where("cert_id = ? AND revision = ?", certID, revision).First(&model).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, false
		}
		logger.Log.Error("查询证书版本失败", "cert_id", certID, "revision", revision, "error", err)
		return nil, false
	}
	return model.ToVersion(), true
}

// GetLatest 获取证书最新版本
func (r *VersionRepo) GetLatest(certID int) (*cert.CertVersion, bool) {
	var model VersionModel
	err := r.db.Where("cert_id = ?", certID).Order("revision DESC").First(&model).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, false
		}
		return nil, false
	}
	return model.ToVersion(), true
}

// Create 创建新版本
func (r *VersionRepo) Create(v *cert.CertVersion) error {
	var model VersionModel
	model.FromVersion(v)
	if err := r.db.Create(&model).Error; err != nil {
		return err
	}
	v.ID = int(model.ID)
	return nil
}

// ListByCertID 列出证书所有版本
func (r *VersionRepo) ListByCertID(certID int) ([]*cert.CertVersion, error) {
	var models []VersionModel
	err := r.db.Where("cert_id = ?", certID).Order("revision DESC").Find(&models).Error
	if err != nil {
		return nil, err
	}
	result := make([]*cert.CertVersion, 0, len(models))
	for i := range models {
		result = append(result, models[i].ToVersion())
	}
	return result, nil
}

// DeleteByCertID 删除证书所有版本
func (r *VersionRepo) DeleteByCertID(certID int) error {
	return r.db.Where("cert_id = ?", certID).Delete(&VersionModel{}).Error
}
