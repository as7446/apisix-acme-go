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

// Storm 数据结构 - 使用 Storm 期望的 struct 名称
// Storm 根据 struct 名称查找对应的 bucket

// Certificate 对应 BoltDB bucket "Certificate"
type Certificate struct {
	ID           int    `storm:"id"`
	Domain       string `storm:"unique"`
	SNIs         []string
	NotBefore    int64
	NotAfter     int64
	APISIXID     string
	Fingerprint  string
	SerialNumber string
	CreatedAt    int64 `storm:"index"`
	UpdatedAt    int64
	LastRenewAt  int64
	RenewLockAt  int64
	Deleted      bool
	DeletedAt    int64
	Status       string `storm:"index"`
	Source       string `storm:"index"`
	LastSyncedAt int64
	SyncError    string
	Revision     int
	Renewing     bool
	LastIssuedAt int64
	AcmeOrderURL string
}

// TaskRecord 对应 BoltDB bucket "TaskRecord"
type TaskRecord struct {
	ID        int    `storm:"id"`
	Domain    string `storm:"index"`
	Status    string `storm:"index"`
	Error     string
	CreatedAt int64 `storm:"index"`
	UpdatedAt int64
}

// AcmeAccountRecord 对应 BoltDB bucket "AcmeAccountRecord"
type AcmeAccountRecord struct {
	Email        string `storm:"id"`
	PrivateKey   []byte
	Registration []byte
	CreatedAt    int64
}

// SyncStateRecord 对应 BoltDB bucket "SyncStateRecord"
type SyncStateRecord struct {
	ID            int   `storm:"id"`
	LastSyncTime  int64 `storm:"index"`
	FirstSyncDone bool
}

// StormData Storm 数据库中的所有数据
type StormData struct {
	Certs     []Certificate
	Tasks     []TaskRecord
	Accounts  []AcmeAccountRecord
	SyncState *SyncStateRecord
}

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
			if err == nil && cfg.StorageDir != "" {
				*stormDBPath = filepath.Join(cfg.StorageDir, "certs.db")
			}
		}
		// 默认路径
		if *stormDBPath == "" {
			*stormDBPath = "out/certs.db"
		}
	}

	fmt.Println("Storm 数据库路径:", *stormDBPath)
	fmt.Println("MySQL 表名前缀:", *tablePrefix)
	fmt.Println("Dry Run:", *dryRun)

	// 1. 读取 Storm 数据
	fmt.Println("\n=== 步骤 1: 读取 Storm 数据 ===")
	stormData, err := readStormData(*stormDBPath)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("读取到 %d 条证书记录\n", len(stormData.Certs))
	fmt.Printf("读取到 %d 条任务记录\n", len(stormData.Tasks))
	fmt.Printf("读取到 %d 个 ACME 账户\n", len(stormData.Accounts))

	if len(stormData.Certs) == 0 && len(stormData.Tasks) == 0 && len(stormData.Accounts) == 0 {
		fmt.Println("⚠️  Storm 数据库为空，无需迁移")
		return
	}

	// 2. 预览数据
	fmt.Println("\n=== 步骤 2: 预览数据 ===")
	previewData(stormData)

	if *dryRun {
		fmt.Println("\n=== Dry Run 完成，未写入任何数据 ===")
		return
	}

	// 3. 连接 MySQL
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
	fmt.Printf("已迁移 %d 条证书\n", migratedCerts)

	migratedTasks, err := migrateTasks(db, stormData.Tasks, *tablePrefix)
	if err != nil {
		log.Fatalf("迁移任务失败: %v", err)
	}
	fmt.Printf("已迁移 %d 条任务\n", migratedTasks)

	migratedAccounts, err := migrateAccounts(db, stormData.Accounts, *tablePrefix)
	if err != nil {
		log.Fatalf("迁移账户失败: %v", err)
	}
	fmt.Printf("已迁移 %d 个账户\n", migratedAccounts)

	if stormData.SyncState != nil {
		if err := migrateSyncState(db, stormData.SyncState, *tablePrefix); err != nil {
			log.Printf("迁移同步状态失败: %v", err)
		} else {
			fmt.Println("同步状态已迁移")
		}
	}

	fmt.Println("\n=== 迁移完成 ===")
	fmt.Println("⚠️  建议:")
	fmt.Println("  1. 备份 Storm 数据库文件:", *stormDBPath)
	fmt.Println("  2. 确认数据正确后删除 Storm 数据库文件")
	fmt.Println("  3. 配置 db.dsn 启动服务")
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
		Certs:    make([]Certificate, 0),
		Tasks:    make([]TaskRecord, 0),
		Accounts: make([]AcmeAccountRecord, 0),
	}

	// 读取证书 - Storm 根据 struct 名称找 bucket
	var certs []Certificate
	if err := db.All(&certs); err == nil {
		data.Certs = certs
	}

	// 读取任务
	var tasks []TaskRecord
	if err := db.All(&tasks); err == nil {
		data.Tasks = tasks
	}

	// 读取账户
	var accounts []AcmeAccountRecord
	if err := db.All(&accounts); err == nil {
		data.Accounts = accounts
	}

	// 读取同步状态
	var syncState SyncStateRecord
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
		fmt.Printf("  %s | %s | 错误: %s\n",
			task.Domain,
			task.Status,
			task.Error)
	}

	fmt.Println("\n--- 账户预览 ---")
	for i, account := range data.Accounts {
		if i >= 5 {
			fmt.Printf("... 共 %d 个\n", len(data.Accounts))
			break
		}
		fmt.Printf("  %s | 创建: %s\n",
			account.Email,
			time.Unix(account.CreatedAt, 0).Format("2006-01-02"))
	}

	if data.SyncState != nil {
		fmt.Println("\n--- 同步状态 ---")
		fmt.Printf("  LastSyncTime: %d | FirstSyncDone: %v\n",
			data.SyncState.LastSyncTime,
			data.SyncState.FirstSyncDone)
	}
}

// createTables 创建 MySQL 表结构
func createTables(db *gormlib.DB, prefix string) error {
	certTable := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %scerts (
		id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
		domain VARCHAR(255) NOT NULL UNIQUE,
		snis TEXT,
		not_before BIGINT NOT NULL DEFAULT 0,
		not_after BIGINT NOT NULL DEFAULT 0,
		apisix_id VARCHAR(255) DEFAULT '',
		fingerprint VARCHAR(255) DEFAULT '',
		serial_number VARCHAR(255) DEFAULT '',
		created_at BIGINT NOT NULL DEFAULT 0,
		updated_at BIGINT NOT NULL DEFAULT 0,
		last_renew_at BIGINT NOT NULL DEFAULT 0,
		renew_lock_at BIGINT NOT NULL DEFAULT 0,
		deleted TINYINT(1) NOT NULL DEFAULT 0,
		deleted_at BIGINT NOT NULL DEFAULT 0,
		status VARCHAR(50) NOT NULL DEFAULT 'pending',
		source VARCHAR(50) NOT NULL DEFAULT 'managed',
		last_synced_at BIGINT NOT NULL DEFAULT 0,
		sync_error TEXT,
		revision INT NOT NULL DEFAULT 1,
		renewing TINYINT(1) NOT NULL DEFAULT 0,
		last_issued_at BIGINT NOT NULL DEFAULT 0,
		acme_order_url TEXT,
		INDEX idx_deleted (deleted),
		INDEX idx_status (status),
		INDEX idx_source (source),
		INDEX idx_not_after (not_after)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`, prefix)

	taskTable := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %stasks (
		id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
		domain VARCHAR(255) NOT NULL,
		status VARCHAR(50) NOT NULL DEFAULT 'created',
		error TEXT,
		created_at BIGINT NOT NULL DEFAULT 0,
		updated_at BIGINT NOT NULL DEFAULT 0,
		INDEX idx_domain (domain),
		INDEX idx_status (status),
		INDEX idx_created_at (created_at)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`, prefix)

	accountTable := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %sacme_accounts (
		email VARCHAR(255) NOT NULL PRIMARY KEY,
		private_key LONGBLOB,
		registration LONGBLOB,
		created_at BIGINT NOT NULL DEFAULT 0
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`, prefix)

	syncTable := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %ssync_states (
		id INT NOT NULL PRIMARY KEY,
		last_sync_time BIGINT NOT NULL DEFAULT 0,
		first_sync_done TINYINT(1) NOT NULL DEFAULT 0,
		INDEX idx_last_sync_time (last_sync_time)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`, prefix)

	for _, sql := range []string{certTable, taskTable, accountTable, syncTable} {
		if err := db.Exec(sql).Error; err != nil {
			return err
		}
	}

	return nil
}

// migrateCerts 迁移证书数据
func migrateCerts(db *gormlib.DB, certs []Certificate, prefix string) (int, error) {
	if len(certs) == 0 {
		return 0, nil
	}

	tableName := prefix + "certs"
	count := 0

	for _, cert := range certs {
		snisJSON, _ := json.Marshal(cert.SNIs)

		// 使用 INSERT ... ON DUPLICATE KEY UPDATE 确保幂等性
		sql := fmt.Sprintf(`INSERT INTO %s (domain, snis, not_before, not_after, apisix_id, fingerprint, serial_number, created_at, updated_at, last_renew_at, renew_lock_at, deleted, deleted_at, status, source, last_synced_at, sync_error, revision, renewing, last_issued_at, acme_order_url)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			snis = VALUES(snis),
			not_before = VALUES(not_before),
			not_after = VALUES(not_after),
			apisix_id = VALUES(apisix_id),
			fingerprint = VALUES(fingerprint),
			serial_number = VALUES(serial_number),
			created_at = VALUES(created_at),
			updated_at = VALUES(updated_at),
			last_renew_at = VALUES(last_renew_at),
			renew_lock_at = VALUES(renew_lock_at),
			deleted = VALUES(deleted),
			deleted_at = VALUES(deleted_at),
			status = VALUES(status),
			source = VALUES(source),
			last_synced_at = VALUES(last_synced_at),
			sync_error = VALUES(sync_error),
			revision = VALUES(revision),
			renewing = VALUES(renewing),
			last_issued_at = VALUES(last_issued_at),
			acme_order_url = VALUES(acme_order_url)`,
			tableName)

		err := db.Exec(sql,
			cert.Domain, string(snisJSON), cert.NotBefore, cert.NotAfter,
			cert.APISIXID, cert.Fingerprint, cert.SerialNumber,
			cert.CreatedAt, time.Now().Unix(), cert.LastRenewAt, cert.RenewLockAt,
			cert.Deleted, cert.DeletedAt, cert.Status, cert.Source,
			cert.LastSyncedAt, cert.SyncError, cert.Revision, cert.Renewing,
			cert.LastIssuedAt, cert.AcmeOrderURL,
		).Error
		if err != nil {
			return count, fmt.Errorf("迁移证书 %s 失败: %w", cert.Domain, err)
		}
		count++
	}

	return count, nil
}

// migrateTasks 迁移任务数据
func migrateTasks(db *gormlib.DB, tasks []TaskRecord, prefix string) (int, error) {
	if len(tasks) == 0 {
		return 0, nil
	}

	tableName := prefix + "tasks"
	count := 0

	for _, task := range tasks {
		sql := fmt.Sprintf(`INSERT INTO %s (domain, status, error, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			status = VALUES(status),
			error = VALUES(error),
			created_at = VALUES(created_at),
			updated_at = VALUES(updated_at)`,
			tableName)

		err := db.Exec(sql, task.Domain, task.Status, task.Error, task.CreatedAt, task.UpdatedAt).Error
		if err != nil {
			return count, fmt.Errorf("迁移任务 %s 失败: %w", task.Domain, err)
		}
		count++
	}

	return count, nil
}

// migrateAccounts 迁移账户数据
func migrateAccounts(db *gormlib.DB, accounts []AcmeAccountRecord, prefix string) (int, error) {
	if len(accounts) == 0 {
		return 0, nil
	}

	tableName := prefix + "acme_accounts"
	count := 0

	for _, account := range accounts {
		sql := fmt.Sprintf(`INSERT INTO %s (email, private_key, registration, created_at)
		VALUES (?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			private_key = VALUES(private_key),
			registration = VALUES(registration),
			created_at = VALUES(created_at)`,
			tableName)

		err := db.Exec(sql, account.Email, account.PrivateKey, account.Registration, account.CreatedAt).Error
		if err != nil {
			return count, fmt.Errorf("迁移账户 %s 失败: %w", account.Email, err)
		}
		count++
	}

	return count, nil
}

// migrateSyncState 迁移同步状态
func migrateSyncState(db *gormlib.DB, state *SyncStateRecord, prefix string) error {
	tableName := prefix + "sync_states"

	sql := fmt.Sprintf(`INSERT INTO %s (id, last_sync_time, first_sync_done)
	VALUES (?, ?, ?)
	ON DUPLICATE KEY UPDATE
		last_sync_time = VALUES(last_sync_time),
		first_sync_done = VALUES(first_sync_done)`,
		tableName)

	return db.Exec(sql, state.ID, state.LastSyncTime, state.FirstSyncDone).Error
}
