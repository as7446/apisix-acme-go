package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

const (
	// RenewLockTimeout 续期锁超时时间（秒）
	RenewLockTimeout = 3600 // 1 小时
	// RSAKeyBits RSA 密钥位数
	RSAKeyBits = 2048
	// CacheExpiryBuffer 缓存过期缓冲（秒，提前 1 天视为过期）
	CacheExpiryBuffer = 86400
)

// Config 应用配置
type Config struct {
	// 运行模式：controller / agent（默认 controller）
	Mode string `yaml:"mode"`

	Listen           string `yaml:"listen"`
	BearerToken      string `yaml:"bearer_token"`
	ApisixAdminURL   string `yaml:"apisix_admin_url"`
	ApisixAdminToken string `yaml:"apisix_admin_token"`
	DefaultEmail     string `yaml:"default_email"`
	StorageDir       string `yaml:"storage_dir"`
	RenewCron        string `yaml:"renew_cron"`
	RenewBeforeDays  int    `yaml:"renew_before_days"`
	SyncCron         string `yaml:"sync_cron"`
	SyncMode         string `yaml:"sync_mode"`
	ManagedByLabel   string `yaml:"managed_by_label"` // Label value written to APISIX SSL resources to identify managed certs
	SNIPattern       string `yaml:"sni_pattern"`      // Glob pattern for importing unmanaged certs during first sync
	TaskCleanupCron  string `yaml:"task_cleanup_cron"`
	TaskRetentionHrs int    `yaml:"task_retention_hours"`

	// 数据库配置
	DB DBConfig `yaml:"db"`

	// Client/Server Config
	HTTPTimeout        int `yaml:"http_timeout"`         // HTTP Client Timeout (seconds)
	ServerReadTimeout  int `yaml:"server_read_timeout"`  // Server Read Timeout (seconds)
	ServerWriteTimeout int `yaml:"server_write_timeout"` // Server Write Timeout (seconds)

	// ACME 配置
	AcmeDirectoryURL string            `yaml:"acme_directory_url"`
	AcmeDNSProvider  string            `yaml:"acme_dns_provider"`
	AcmeDNSEnv       map[string]string `yaml:"acme_dns_env"`
	// ChallengeRoute HTTP-01 验证路由配置
	ChallengeRoute ChallengeRouteConfig `yaml:"challenge_route"`

	// 证书申请重试配置
	CertRetryMax   int `yaml:"cert_retry_max"`   // 证书申请最大重试次数（默认 3）
	CertRetryDelay int `yaml:"cert_retry_delay"` // 首次重试延迟秒数（默认 2，后续指数增长）

	// 日志级别（debug / info / warn / error）
	LogLevel string `yaml:"log_level"`

	// Agent 模式配置（预留）
	ControllerURL string `yaml:"controller_url"`
	AgentRegion   string `yaml:"agent_region"`
	AgentPullCron string `yaml:"agent_pull_cron"`
}

// DBConfig 数据库配置
type DBConfig struct {
	Dsn             string `yaml:"dsn"`               // 数据源名称，如 user:password@tcp(host:port)/dbname?charset=utf8mb4
	MaxOpenConns    int    `yaml:"max_open_conns"`    // 最大打开连接数（默认 100）
	MaxIdleConns    int    `yaml:"max_idle_conns"`    // 最大空闲连接数（默认 10）
	ConnMaxLifetime int    `yaml:"conn_max_lifetime"` // 连接最大存活时间（秒，默认 3600）
	TablePrefix     string `yaml:"table_prefix"`      // 表名前缀（默认 cert_）
}

// ChallengeRouteConfig HTTP-01 验证路由配置
type ChallengeRouteConfig struct {
	Enable         bool     `yaml:"enable"`
	RouteName      string   `yaml:"route_name"`
	Hosts          []string `yaml:"hosts"`
	UpstreamNodes  []string `yaml:"upstream_nodes"`
	UpstreamScheme string   `yaml:"upstream_scheme"`
	Priority       int      `yaml:"priority"`
}

// IsController 当前是否为 Controller 模式
func (c *Config) IsController() bool {
	return c.Mode == "" || c.Mode == "controller"
}

// IsAgent 当前是否为 Agent 模式
func (c *Config) IsAgent() bool {
	return c.Mode == "agent"
}

// Load 加载配置文件
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	return &cfg, nil
}

func (cfg *Config) applyDefaults() {
	if cfg.Listen == "" {
		cfg.Listen = ":8080"
	}
	if cfg.StorageDir == "" {
		cfg.StorageDir = "out"
	}
	if cfg.RenewBeforeDays <= 0 {
		cfg.RenewBeforeDays = 30
	}
	if cfg.TaskRetentionHrs <= 0 {
		cfg.TaskRetentionHrs = 24 * 7
	}
	if cfg.RenewCron == "" {
		cfg.RenewCron = "0 0 2 * * *"
	}
	if cfg.TaskCleanupCron == "" {
		cfg.TaskCleanupCron = "0 0 1 * * *"
	}
	if cfg.SyncCron == "" {
		cfg.SyncCron = "0 0 * * * *"
	}
	if cfg.SyncMode == "" {
		cfg.SyncMode = "compat"
	}
	if cfg.ManagedByLabel == "" {
		cfg.ManagedByLabel = "apisix-acme-go"
	}
	if cfg.AcmeDirectoryURL == "" {
		cfg.AcmeDirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"
	}
	if cfg.ChallengeRoute.RouteName == "" {
		cfg.ChallengeRoute.RouteName = "apisix_acme_http01"
	}
	if cfg.ChallengeRoute.UpstreamScheme == "" {
		cfg.ChallengeRoute.UpstreamScheme = "http"
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 15
	}
	if cfg.ServerReadTimeout <= 0 {
		cfg.ServerReadTimeout = 15
	}
	if cfg.ServerWriteTimeout <= 0 {
		cfg.ServerWriteTimeout = 30
	}
	if cfg.CertRetryMax <= 0 {
		cfg.CertRetryMax = 3
	}
	if cfg.CertRetryDelay <= 0 {
		cfg.CertRetryDelay = 2
	}
	if cfg.AgentPullCron == "" {
		cfg.AgentPullCron = "0 */30 * * * *"
	}
	// DB 默认值
	if cfg.DB.MaxOpenConns <= 0 {
		cfg.DB.MaxOpenConns = 100
	}
	if cfg.DB.MaxIdleConns <= 0 {
		cfg.DB.MaxIdleConns = 10
	}
	if cfg.DB.ConnMaxLifetime <= 0 {
		cfg.DB.ConnMaxLifetime = 3600
	}
	if cfg.DB.TablePrefix == "" {
		cfg.DB.TablePrefix = "cert_"
	}
}
