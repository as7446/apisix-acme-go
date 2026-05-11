package gorm

import (
	"gorm.io/gorm"

	"github.com/as7446/apisix-acme-go/internal/domain/cert"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
)

// AccountRepo GORM 实现的 AccountRepository
type AccountRepo struct {
	db *gorm.DB
}

// NewAccountRepo 创建 AccountRepo
func NewAccountRepo(db *gorm.DB) *AccountRepo {
	return &AccountRepo{db: db}
}

func (r *AccountRepo) GetAccount(email string) (*cert.AcmeAccount, error) {
	var model AcmeAccountModel
	err := r.db.Where("email = ?", email).First(&model).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		logger.Log.Error("查询 ACME 账户失败", "email", email, "error", err)
		return nil, err
	}
	return model.ToDomain(), nil
}

func (r *AccountRepo) SaveAccount(account *cert.AcmeAccount) error {
	if account.CreatedAt == 0 {
		account.CreatedAt = int64(TimeNow())
	}

	var model AcmeAccountModel
	err := r.db.Where("email = ?", account.Email).First(&model).Error

	if err == gorm.ErrRecordNotFound {
		// 不存在，创建
		model.FromDomain(account)
		err = r.db.Create(&model).Error
	} else if err == nil {
		// 存在，更新
		model.FromDomain(account)
		err = r.db.Save(&model).Error
	}

	if err != nil {
		logger.Log.Error("保存 ACME 账户失败", "email", account.Email, "error", err)
		return err
	}
	return nil
}
