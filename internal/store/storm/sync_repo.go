package storm

// syncStateRecord Storm 存储层模型
type syncStateRecord struct {
	ID            int   `storm:"id,increment"`
	LastSyncTime  int64 `storm:"index"`
	FirstSyncDone bool  `storm:"index"`
}

// SyncRepo 同步状态存储
type SyncRepo struct {
	store *Store
}

// NewSyncRepo 创建 SyncRepo
func NewSyncRepo(s *Store) *SyncRepo {
	return &SyncRepo{store: s}
}

func (r *SyncRepo) GetLastSyncTime() (int64, bool) {
	var state syncStateRecord
	err := r.store.DB.One("ID", 1, &state)
	if err != nil {
		return 0, false
	}
	return state.LastSyncTime, state.FirstSyncDone
}

func (r *SyncRepo) SetLastSyncTime(syncTime int64, firstSyncDone bool) error {
	state := syncStateRecord{
		ID:            1,
		LastSyncTime:  syncTime,
		FirstSyncDone: firstSyncDone,
	}
	return r.store.DB.Save(&state)
}
