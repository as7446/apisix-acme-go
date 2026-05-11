package gorm

import (
	"fmt"
	"time"

	"gorm.io/driver/mysql"
	gormlib "gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/as7446/apisix-acme-go/internal/infra/config"
	appLogger "github.com/as7446/apisix-acme-go/internal/infra/logger"
)

// Store GORM 数据库封装
type Store struct {
	DB          *gormlib.DB
	TablePrefix string
}

// New 创建 GORM 数据库连接
func New(cfg *config.Config) (*Store, error) {
	if cfg.DB.Dsn == "" {
		return nil, fmt.Errorf("数据库 DSN 未配置，请检查 db.dsn 配置项")
	}

	gormConfig := &gormlib.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	}

	db, err := gormlib.Open(mysql.Open(cfg.DB.Dsn), gormConfig)
	if err != nil {
		return nil, fmt.Errorf("连接数据库失败：%w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("获取底层 sql.DB 失败：%w", err)
	}

	// 配置连接池
	sqlDB.SetMaxOpenConns(cfg.DB.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.DB.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(time.Duration(cfg.DB.ConnMaxLifetime) * time.Second)

	store := &Store{
		DB:          db,
		TablePrefix: cfg.DB.TablePrefix,
	}

	// 自动迁移表结构
	if err := store.autoMigrate(); err != nil {
		return nil, fmt.Errorf("自动迁移表结构失败：%w", err)
	}

	appLogger.Log.Info("数据库连接初始化成功",
		"max_open_conns", cfg.DB.MaxOpenConns,
		"max_idle_conns", cfg.DB.MaxIdleConns,
		"conn_max_lifetime", cfg.DB.ConnMaxLifetime,
		"table_prefix", cfg.DB.TablePrefix)

	return store, nil
}

// autoMigrate 自动迁移表结构
func (s *Store) autoMigrate() error {
	return s.DB.AutoMigrate(
		&CertModel{},
		&TaskModel{},
		&AcmeAccountModel{},
		&SyncStateModel{},
		&VersionModel{},
		&AgentModel{},
	)
}

// Close 关闭数据库连接
func (s *Store) Close() error {
	sqlDB, err := s.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// TableName 返回带前缀的表名
func (s *Store) TableName(name string) string {
	return s.TablePrefix + name
}
