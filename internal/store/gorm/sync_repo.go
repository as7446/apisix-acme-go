package gorm

import (
	"gorm.io/gorm"
)

// SyncRepo GORM 实现的 SyncStateRepository
type SyncRepo struct {
	db *gorm.DB
}

// NewSyncRepo 创建 SyncRepo
func NewSyncRepo(db *gorm.DB) *SyncRepo {
	return &SyncRepo{db: db}
}

func (r *SyncRepo) GetLastSyncTime() (int64, bool) {
	var model SyncStateModel
	err := r.db.Where("id = ?", 1).First(&model).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return 0, false
		}
		return 0, false
	}
	return int64(model.LastSyncTime), model.FirstSyncDone
}

func (r *SyncRepo) SetLastSyncTime(syncTime int64, firstSyncDone bool) error {
	var model SyncStateModel
	err := r.db.Where("id = ?", 1).First(&model).Error

	if err == gorm.ErrRecordNotFound {
		// 不存在，创建
		model = SyncStateModel{
			ID:            1,
			LastSyncTime:  uint64(syncTime),
			FirstSyncDone: firstSyncDone,
		}
		err = r.db.Create(&model).Error
	} else if err == nil {
		// 存在，更新
		updates := map[string]interface{}{
			"last_sync_time":  syncTime,
			"first_sync_done": firstSyncDone,
		}
		err = r.db.Model(&SyncStateModel{}).Where("id = ?", 1).Updates(updates).Error
	}

	return err
}

// EnsureSyncState 确保同步状态记录存在
func EnsureSyncState(db *gorm.DB) error {
	var model SyncStateModel
	err := db.Where("id = ?", 1).First(&model).Error
	if err == gorm.ErrRecordNotFound {
		model = SyncStateModel{
			ID:            1,
			LastSyncTime:  0,
			FirstSyncDone: false,
		}
		return db.Create(&model).Error
	}
	return err
}
