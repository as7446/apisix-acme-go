package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/asdine/storm/v3"
	"github.com/asdine/storm/v3/codec/gob"
	"gorm.io/driver/mysql"
	gormlib "gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/as7446/apisix-acme-go/internal/infra/config"
	appLogger "github.com/as7446/apisix-acme-go/internal/infra/logger"
)

const (
	// StormCertRecord Storm 数据库证书记录结构
	StormCertRecordBucket = "certs"
)

func main() {
	appLogger.Init("info")

	// 命令行参数
	stormDBPath := flag.String("storm-db", "", "Storm 数据库文件路径（默认为配置中的 storage_dir/certs.db）")
	configPath := flag.String("config", "", "配置文件路径")
	tablePrefix := flag.String("table-prefix", "cert_", "MySQL 表名前缀")
	dryRun := flag.Bool("dry-run", false, "仅预览，不执行写入")
	flag.Parse()

	if *stormDBPath == "" {
		// 尝试从配置读取
		if *configPath != "" {
			cfg, err := config.Load(*configPath)
			if err == nil {
				*stormDBPath = filepath.Join(cfg.StorageDir, "certs.db")
			}
		}
		if *stormDBPath == "" {
			*stormDBPath = "out/certs.db"
		}
	}

	fmt.Printf("Storm 数据库路径: %s\n", *stormDBPath)
	fmt.Printf("MySQL 表名前缀: %s\n", *tablePrefix)
	fmt.Printf("Dry Run: %v\n\n", *dryRun)

	// 1. 读取 Storm 数据
	fmt.Println("=== 步骤 1: 读取 Storm 数据 ===")
	stormData, err := readStormData(*stormDBPath)
	if err != nil {
		log.Fatalf("读取 Storm 数据失败: %v", err)
	}
	fmt.Printf("读取到 %d 条证书记录\n", len(stormData.Certs))
	fmt.Printf("读取到 %d 条任务记录\n", len(stormData.Tasks))
	fmt.Printf("读取到 %d 个 ACME 账户\n", len(stormData.Accounts))

	if len(stormData.Certs) == 0 && len(stormData.Tasks) == 0 && len(stormData.Accounts) == 0 {
		fmt.Println("\n⚠️  Storm 数据库为空，无需迁移")
		return
	}

	// 2. 预览数据
	fmt.Println("\n=== 步骤 2: 数据预览 ===")
	previewData(stormData)

	if *dryRun {
		fmt.Println("\n⚠️ Dry Run 模式，跳过实际迁移")
		return
	}

	// 3. 获取 MySQL 连接
	fmt.Println("\n=== 步骤 3: 连接 MySQL ===")
	mysqlDsn := os.Getenv("MYSQL_DSN")
	if mysqlDsn == "" {
		fmt.Print("请输入 MySQL DSN (user:password@tcp(host:port)/dbname?charset=utf8mb4): ")
		fmt.Scanln(&mysqlDsn)
		if mysqlDsn == "" {
			log.Fatal("MySQL DSN 不能为空")
		}
	}

	db, err := gormlib.Open(mysql.Open(mysqlDsn), &gormlib.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		log.Fatalf("连接 MySQL 失败: %v", err)
	}
	fmt.Println("MySQL 连接成功")

	// 4. 创建表结构
	fmt.Println("\n=== 步骤 4: 创建表结构 ===")
	if err := createTables(db, *tablePrefix); err != nil {
		log.Fatalf("创建表结构失败: %v", err)
	}
	fmt.Println("表结构创建成功")

	// 5. 迁移数据
	fmt.Println("\n=== 步骤 5: 迁移数据 ===")
	migratedCerts, err := migrateCerts(db, stormData.Certs, *tablePrefix)
	if err != nil {
		log.Fatalf("迁移证书失败: %v", err)
	}
	fmt.Printf("迁移证书: %d/%d\n", migratedCerts, len(stormData.Certs))

	migratedTasks, err := migrateTasks(db, stormData.Tasks, *tablePrefix)
	if err != nil {
		log.Fatalf("迁移任务失败: %v", err)
	}
	fmt.Printf("迁移任务: %d/%d\n", migratedTasks, len(stormData.Tasks))

	migratedAccounts, err := migrateAccounts(db, stormData.Accounts, *tablePrefix)
	if err != nil {
		log.Fatalf("迁移账户失败: %v", err)
	}
	fmt.Printf("迁移账户: %d/%d\n", migratedAccounts, len(stormData.Accounts))

	// 6. 迁移同步状态
	fmt.Println("\n=== 步骤 6: 迁移同步状态 ===")
	if err := migrateSyncState(db, stormData.SyncState, *tablePrefix); err != nil {
		log.Fatalf("迁移同步状态失败: %v", err)
	}

	fmt.Println("\n=== 迁移完成 ===")
	fmt.Println("⚠️  建议:")
	fmt.Println("  1. 备份 Storm 数据库文件:", *stormDBPath)
	fmt.Println("  2. 确认数据正确后删除 Storm 数据库文件")
	fmt.Println("  3. 配置 db.dsn 启动服务")
}

// StormData Storm 数据库中的所有数据
type StormData struct {
	Certs     []StormCert
	Tasks     []StormTask
	Accounts  []StormAccount
	SyncState *StormSyncState
}

// StormCert Storm 证书记录（根据实际结构定义）
type StormCert struct {
	ID           int
	Domain       string
	SNIs         []string
	NotBefore    int64
	NotAfter     int64
	APISIXID     string
	Fingerprint  string
	SerialNumber string
	CreatedAt    int64
	UpdatedAt    int64
	LastRenewAt  int64
	RenewLockAt  int64
	Deleted      bool
	DeletedAt    int64
	Status       string
	Source       string
	LastSyncedAt int64
	SyncError    string
	Revision     int
	Renewing     bool
	LastIssuedAt int64
	AcmeOrderURL string
}

// StormTask Storm 任务记录
type StormTask struct {
	ID        int
	Domain    string
	Status    string
	Error     string
	CreatedAt int64
	UpdatedAt int64
}

// StormAccount Storm ACME 账户
type StormAccount struct {
	Email        string
	PrivateKey   []byte
	Registration []byte
	CreatedAt    int64
}

// StormSyncState Storm 同步状态
type StormSyncState struct {
	ID            int
	LastSyncTime  int64
	FirstSyncDone bool
}

// readStormData 读取 Storm 数据库
func readStormData(dbPath string) (*StormData, error) {
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return &StormData{}, nil
	}

	db, err := storm.Open(dbPath, storm.Codec(gob.Codec))
	if err != nil {
		return nil, fmt.Errorf("打开 Storm 数据库失败: %w", err)
	}
	defer db.Close()

	data := &StormData{
		Certs:    make([]StormCert, 0),
		Tasks:    make([]StormTask, 0),
		Accounts: make([]StormAccount, 0),
	}

	// 读取证书
	var certs []StormCert
	if err := db.All(&certs); err == nil {
		data.Certs = certs
	}

	// 读取任务
	var tasks []StormTask
	if err := db.All(&tasks); err == nil {
		data.Tasks = tasks
	}

	// 读取账户
	var accounts []StormAccount
	if err := db.All(&accounts); err == nil {
		data.Accounts = accounts
	}

	// 读取同步状态
	var syncState StormSyncState
	if err := db.One("ID", 1, &syncState); err == nil {
		data.SyncState = &syncState
	}

	return data, nil
}

// previewData 预览数据
func previewData(data *StormData) {
	fmt.Println("\n--- 证书预览 (前5条) ---")
	for i, cert := range data.Certs {
		if i >= 5 {
			fmt.Printf("... 共 %d 条\n", len(data.Certs))
			break
		}
		fmt.Printf("  %s | %s | 过期: %s\n",
			cert.Domain,
			cert.Status,
			time.Unix(cert.NotAfter, 0).Format("2006-01-02"))
	}

	fmt.Println("\n--- 任务预览 (前5条) ---")
	for i, task := range data.Tasks {
		if i >= 5 {
			fmt.Printf("... 共 %d 条\n", len(data.Tasks))
			break
		}
		fmt.Printf("  %s | %s\n", task.Domain, task.Status)
	}
}

// createTables 创建 MySQL 表结构
func createTables(db *gormlib.DB, prefix string) error {
	// 证书表
	certTable := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %scerts (
		id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
		domain VARCHAR(255) NOT NULL UNIQUE,
		snis TEXT,
		not_before BIGINT UNSIGNED DEFAULT 0,
		not_after BIGINT UNSIGNED DEFAULT 0,
		apisix_id VARCHAR(255) NOT NULL DEFAULT '',
		fingerprint VARCHAR(255) NOT NULL DEFAULT '',
		serial_number VARCHAR(255) NOT NULL DEFAULT '',
		created_at BIGINT UNSIGNED DEFAULT 0,
		updated_at BIGINT UNSIGNED DEFAULT 0,
		last_renew_at BIGINT UNSIGNED DEFAULT 0,
		renew_lock_at BIGINT UNSIGNED DEFAULT 0,
		deleted TINYINT(1) NOT NULL DEFAULT 0,
		deleted_at BIGINT UNSIGNED DEFAULT 0,
		status VARCHAR(32) NOT NULL DEFAULT '',
		source VARCHAR(32) NOT NULL DEFAULT '',
		last_synced_at BIGINT UNSIGNED DEFAULT 0,
		sync_error TEXT,
		revision INT UNSIGNED NOT NULL DEFAULT 0,
		renewing TINYINT(1) NOT NULL DEFAULT 0,
		last_issued_at BIGINT UNSIGNED DEFAULT 0,
		acme_order_url TEXT,
		INDEX idx_cert_deleted (deleted),
		INDEX idx_cert_status (status),
		INDEX idx_cert_source (source),
		INDEX idx_cert_not_after (not_after),
		INDEX idx_cert_renewing (renewing),
		INDEX idx_cert_apisix_id (apisix_id),
		INDEX idx_cert_updated_at (updated_at),
		INDEX idx_cert_last_renew_at (last_renew_at)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`, prefix)

	if err := db.Exec(certTable).Error; err != nil {
		return err
	}

	// 任务表
	taskTable := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %stasks (
		id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
		domain VARCHAR(255) NOT NULL,
		status VARCHAR(32) NOT NULL DEFAULT '',
		error TEXT,
		created_at BIGINT UNSIGNED DEFAULT 0,
		updated_at BIGINT UNSIGNED DEFAULT 0,
		INDEX idx_cert_task_domain (domain),
		INDEX idx_cert_task_status (status),
		INDEX idx_cert_task_updated_at (updated_at)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`, prefix)

	if err := db.Exec(taskTable).Error; err != nil {
		return err
	}

	// 账户表
	accountTable := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %sacme_accounts (
		email VARCHAR(255) PRIMARY KEY,
		private_key MEDIUMBLOB NOT NULL,
		registration MEDIUMBLOB,
		created_at BIGINT UNSIGNED DEFAULT 0
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`, prefix)

	if err := db.Exec(accountTable).Error; err != nil {
		return err
	}

	// 同步状态表
	syncTable := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %ssync_states (
		id BIGINT UNSIGNED PRIMARY KEY,
		last_sync_time BIGINT UNSIGNED DEFAULT 0,
		first_sync_done TINYINT(1) NOT NULL DEFAULT 0
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`, prefix)

	if err := db.Exec(syncTable).Error; err != nil {
		return err
	}

	return nil
}

// migrateCerts 迁移证书数据
func migrateCerts(db *gormlib.DB, certs []StormCert, prefix string) (int, error) {
	tableName := prefix + "certs"
	migrated := 0

	for _, cert := range certs {
		snisJSON := "[]"
		if len(cert.SNIs) > 0 {
			data, _ := json.Marshal(cert.SNIs)
			snisJSON = string(data)
		}

		result := db.Exec(fmt.Sprintf(`INSERT INTO %s
			(domain, snis, not_before, not_after, apisix_id, fingerprint, serial_number,
			 created_at, updated_at, last_renew_at, renew_lock_at, deleted, deleted_at,
			 status, source, last_synced_at, sync_error, revision, renewing, last_issued_at, acme_order_url)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON DUPLICATE KEY UPDATE
				snis=VALUES(snis), not_before=VALUES(not_before), not_after=VALUES(not_after),
				apisix_id=VALUES(apisix_id), fingerprint=VALUES(fingerprint), serial_number=VALUES(serial_number),
				updated_at=VALUES(updated_at), last_renew_at=VALUES(last_renew_at), renew_lock_at=VALUES(renew_lock_at),
				deleted=VALUES(deleted), deleted_at=VALUES(deleted_at), status=VALUES(status),
				source=VALUES(source), last_synced_at=VALUES(last_synced_at), sync_error=VALUES(sync_error),
				revision=VALUES(revision), renewing=VALUES(renewing), last_issued_at=VALUES(last_issued_at),
				acme_order_url=VALUES(acme_order_url)`,
			tableName),
			cert.Domain, snisJSON, cert.NotBefore, cert.NotAfter, cert.APISIXID,
			cert.Fingerprint, cert.SerialNumber, cert.CreatedAt, cert.UpdatedAt,
			cert.LastRenewAt, cert.RenewLockAt, cert.Deleted, cert.DeletedAt,
			cert.Status, cert.Source, cert.LastSyncedAt, cert.SyncError,
			cert.Revision, cert.Renewing, cert.LastIssuedAt, cert.AcmeOrderURL)

		if result.Error == nil && result.RowsAffected > 0 {
			migrated++
		}
	}

	return migrated, nil
}

// migrateTasks 迁移任务数据
func migrateTasks(db *gormlib.DB, tasks []StormTask, prefix string) (int, error) {
	tableName := prefix + "tasks"
	migrated := 0

	for _, task := range tasks {
		result := db.Exec(fmt.Sprintf(`INSERT INTO %s
			(domain, status, error, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?)
			ON DUPLICATE KEY UPDATE
				status=VALUES(status), error=VALUES(error), updated_at=VALUES(updated_at)`,
			tableName),
			task.Domain, task.Status, task.Error, task.CreatedAt, task.UpdatedAt)

		if result.Error == nil && result.RowsAffected > 0 {
			migrated++
		}
	}

	return migrated, nil
}

// migrateAccounts 迁移账户数据
func migrateAccounts(db *gormlib.DB, accounts []StormAccount, prefix string) (int, error) {
	tableName := prefix + "acme_accounts"
	migrated := 0

	for _, account := range accounts {
		result := db.Exec(fmt.Sprintf(`INSERT INTO %s
			(email, private_key, registration, created_at)
			VALUES (?, ?, ?, ?)
			ON DUPLICATE KEY UPDATE
				private_key=VALUES(private_key), registration=VALUES(registration)`,
			tableName),
			account.Email, account.PrivateKey, account.Registration, account.CreatedAt)

		if result.Error == nil && result.RowsAffected > 0 {
			migrated++
		}
	}

	return migrated, nil
}

// migrateSyncState 迁移同步状态
func migrateSyncState(db *gormlib.DB, state *StormSyncState, prefix string) error {
	if state == nil {
		return nil
	}

	tableName := prefix + "sync_states"
	return db.Exec(fmt.Sprintf(`INSERT INTO %s (id, last_sync_time, first_sync_done)
		VALUES (1, ?, ?)
		ON DUPLICATE KEY UPDATE last_sync_time=VALUES(last_sync_time), first_sync_done=VALUES(first_sync_done)`,
		tableName),
		state.LastSyncTime, state.FirstSyncDone).Error
}
