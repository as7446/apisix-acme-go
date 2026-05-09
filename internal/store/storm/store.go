package storm

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/asdine/storm/v3"
	"github.com/asdine/storm/v3/codec/gob"
)

// Store Storm 数据库封装
type Store struct {
	DB      *storm.DB
	Path    string
	RenewMu sync.Mutex // 保护 LockRenew/UnlockRenew 的原子性
}

// New 打开 Storm 数据库
func New(storageDir string) (*Store, error) {
	if err := os.MkdirAll(storageDir, 0755); err != nil {
		return nil, fmt.Errorf("创建存储目录失败：%w", err)
	}

	dbPath := filepath.Join(storageDir, "certs.db")
	db, err := storm.Open(dbPath, storm.Codec(gob.Codec), storm.BoltOptions(0600, nil))
	if err != nil {
		return nil, fmt.Errorf("打开 Storm 数据库失败：%w", err)
	}

	return &Store{DB: db, Path: dbPath}, nil
}

// Close 关闭数据库连接
func (s *Store) Close() error {
	if s.DB != nil {
		return s.DB.Close()
	}
	return nil
}
