package gorm

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/as7446/apisix-acme-go/internal/domain/task"
	"github.com/as7446/apisix-acme-go/internal/infra/logger"
)

// TaskRepo GORM 实现的 TaskRepository
type TaskRepo struct {
	db *gorm.DB
}

// NewTaskRepo 创建 TaskRepo
func NewTaskRepo(db *gorm.DB) *TaskRepo {
	return &TaskRepo{db: db}
}

func (r *TaskRepo) SaveTask(domain string, status string, errMsg string) error {
	now := TimeNow()

	var model TaskModel
	err := r.db.Where("domain = ?", domain).First(&model).Error

	if err == nil {
		// 存在，更新
		updates := map[string]interface{}{
			"status":     status,
			"error":      errMsg,
			"updated_at": now,
		}
		err = r.db.Model(&TaskModel{}).Where("domain = ?", domain).Updates(updates).Error
	} else if err == gorm.ErrRecordNotFound {
		// 不存在，创建
		model = TaskModel{
			Domain:    domain,
			Status:    status,
			Error:     errMsg,
			CreatedAt: now,
			UpdatedAt: now,
		}
		err = r.db.Create(&model).Error
	} else {
		return fmt.Errorf("查询任务记录失败：%w", err)
	}

	if err != nil {
		return fmt.Errorf("保存任务记录失败：%w", err)
	}
	return nil
}

func (r *TaskRepo) GetTaskRecord(domain string) (*task.TaskRecord, bool) {
	var model TaskModel
	err := r.db.Where("domain = ?", domain).First(&model).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, false
		}
		logger.Log.Error("查询任务记录失败", "domain", domain, "error", err)
		return nil, false
	}
	return model.ToDomain(), true
}

func (r *TaskRepo) CleanupTasks(retentionHours int) error {
	cutoff := TimeNow() - uint64(retentionHours*3600)

	var models []TaskModel
	err := r.db.Where("updated_at < ?", cutoff).Find(&models).Error
	if err != nil {
		return fmt.Errorf("查询过期任务失败：%w", err)
	}

	if len(models) > 0 {
		err = r.db.Delete(&models).Error
		if err != nil {
			return fmt.Errorf("删除过期任务失败：%w", err)
		}
		logger.Log.Info("清理过期任务", "count", len(models))
	}
	return nil
}
