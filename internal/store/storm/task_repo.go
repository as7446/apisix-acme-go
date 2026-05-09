package storm

import (
	"errors"
	"fmt"
	"time"

	stormdb "github.com/asdine/storm/v3"

	"github.com/as7446/apisix-acme-go/internal/domain/task"
)

// taskRecord Storm 存储层模型
type taskRecord struct {
	ID        int    `storm:"id,increment"`
	Domain    string `storm:"index"`
	Status    string `storm:"index"`
	Error     string
	CreatedAt int64 `storm:"index"`
	UpdatedAt int64 `storm:"index"`
}

// TaskRepo Storm 实现的 TaskRepository
type TaskRepo struct {
	store *Store
}

// NewTaskRepo 创建 TaskRepo
func NewTaskRepo(s *Store) *TaskRepo {
	return &TaskRepo{store: s}
}

func (r *TaskRepo) SaveTask(domain string, status string, errMsg string) error {
	now := time.Now().Unix()
	var rec taskRecord
	qErr := r.store.DB.One("Domain", domain, &rec)
	if qErr != nil && !errors.Is(qErr, stormdb.ErrNotFound) {
		return fmt.Errorf("查询任务记录失败：%w", qErr)
	}
	if errors.Is(qErr, stormdb.ErrNotFound) {
		rec.CreatedAt = now
		rec.Domain = domain
	}
	rec.Status = status
	rec.Error = errMsg
	rec.UpdatedAt = now
	if err := r.store.DB.Save(&rec); err != nil {
		return fmt.Errorf("保存任务记录失败：%w", err)
	}
	return nil
}

func (r *TaskRepo) GetTaskRecord(domain string) (*task.TaskRecord, bool) {
	var rec taskRecord
	err := r.store.DB.One("Domain", domain, &rec)
	if err != nil {
		return nil, false
	}
	return &task.TaskRecord{
		ID: rec.ID, Domain: rec.Domain, Status: rec.Status,
		Error: rec.Error, CreatedAt: rec.CreatedAt, UpdatedAt: rec.UpdatedAt,
	}, true
}

func (r *TaskRepo) CleanupTasks(retentionHours int) error {
	cutoff := time.Now().Add(-time.Duration(retentionHours) * time.Hour).Unix()
	var recs []taskRecord
	if err := r.store.DB.All(&recs); err != nil && !errors.Is(err, stormdb.ErrNotFound) {
		return fmt.Errorf("查询任务记录失败：%w", err)
	}
	for i := range recs {
		if recs[i].UpdatedAt < cutoff {
			_ = r.store.DB.DeleteStruct(&recs[i])
		}
	}
	return nil
}
